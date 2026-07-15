#!/usr/bin/env python3
"""
文件职责：实验性地把静态网络知识切块并写入 FAISS，再通过 LangChain RetrievalQA 生成诊断。
初始化失败或问答链不可用时，会退回固定阈值的本地报告。
"""

import os
import json
import re
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

try:
    from openai import OpenAI
    from langchain.text_splitter import RecursiveCharacterTextSplitter
    from langchain_community.vectorstores import FAISS
    from langchain_community.embeddings import OpenAIEmbeddings
    from langchain.chains import RetrievalQA
    from langchain.prompts import PromptTemplate
    from langchain.schema import Document
    RAG_AVAILABLE = True
# 任一 RAG 依赖缺失时保留本地 fallback，不阻止脚本启动。
except ImportError as e:
    print(f"⚠️ RAG依赖不可用: {e}")
    print("将使用简化模式")
    RAG_AVAILABLE = False

from network_knowledge_base import get_network_knowledge

# 表示从日志解析出的单项网络指标。
@dataclass
class NetworkMetric:
    """从一行格式化日志中提取出的单项网络观测。"""
    timestamp: str
    interface: str
    rtt: Optional[float] = None
    tcp_loss_rate: Optional[float] = None
    traffic_mbps: Optional[float] = None
    rssi: Optional[int] = None
    quality: Optional[int] = None
    using: Optional[bool] = None
    flows: Optional[int] = None
    pps: Optional[int] = None
    level: Optional[str] = None

# 将 log_capture.py 的规范化输出转换为结构化指标。
class LogCaptureParser:
    """负责把日志展示格式转换成 ``NetworkMetric``。"""
    
    # 预编译各类指标日志正则。
    def __init__(self):
        """预编译各类指标正则，供后续逐行匹配复用。"""
        # log_capture.py输出的正则表达式模式
        self.patterns = {
            # RTT监控: 🎯 [HH:MM:SS] RTT监控: eth0 = 15ms (质量:1, 使用:YES, 目标:223.5.5.5)
            'rtt_monitor': re.compile(r'🎯 \[(\d{2}:\d{2}:\d{2})\] RTT监控: (\w+) = (-?\d+(?:\.\d+)?)ms \(质量:(\d+), 使用:(\w+), 目标:([\d.]+)\)'),
            
            # TCP丢包: 📈 [HH:MM:SS] TCP详细: eth0 = 0.5% (发送:137, 重传:0, 等级:good)
            'tcp_loss': re.compile(r'📈 \[(\d{2}:\d{2}:\d{2})\] TCP详细: (\w+) = ([\d.]+)% \(发送:(\d+), 重传:(\d+), 等级:(\w+)\)'),
            
            # 流量监控: 🌊 [HH:MM:SS] 流量监控: eth0 = 2.5MB/s (连接:15, 包/秒:1200)
            'traffic': re.compile(r'🌊 \[(\d{2}:\d{2}:\d{2})\] 流量监控: (\w+) = ([\d.]+)MB/s \(连接:(\d+), 包/秒:(\d+)\)'),
            
            # RSSI监控: 📶 [HH:MM:SS] RSSI监控: wlan0 = -65dBm (质量:2, 使用:NO)
            'rssi': re.compile(r'📶 \[(\d{2}:\d{2}:\d{2})\] RSSI监控: (\w+) = (-?\d+)dBm \(质量:(\d+), 使用:(\w+)\)'),
            
            # 接口汇总: 📋 [HH:MM:SS] 接口汇总: eth0 = RTT:15ms, 质量:1, RSSI:-1000dBm, TCP丢包:0.5%, 流量:2.5MB/s
            'interface_summary': re.compile(r'📋 \[(\d{2}:\d{2}:\d{2})\] 接口汇总: (\w+) = RTT:(-?\d+(?:\.\d+)?)ms, 质量:(\d+), RSSI:(-?\d+)dBm, TCP丢包:(-?[\d.]+)%, 流量:([\d.]+)MB/s'),
            
            # 网络质量: ⭐ [HH:MM:SS] 网络质量: eth0 = good (分数:85.5)
            'network_quality': re.compile(r'⭐ \[(\d{2}:\d{2}:\d{2})\] 网络质量: (\w+) = (\w+) \(分数:([\d.]+)\)'),
        }
    
    # 逐行提取指标并过滤无法识别的文本。
    def parse_log_capture_output(self, log_data: str) -> List[NetworkMetric]:
        """解析可识别的指标行，忽略普通日志和未知格式。"""
        metrics = []
        lines = log_data.strip().split('\n')
        
        for line in lines:
            if not line.strip():
                continue
                
            # 解析RTT监控
            rtt_match = self.patterns['rtt_monitor'].search(line)
            if rtt_match:
                time_str, interface, rtt, quality, using, target = rtt_match.groups()
                metrics.append(NetworkMetric(
                    timestamp=time_str,
                    interface=interface,
                    rtt=float(rtt),
                    quality=int(quality),
                    using=using == 'YES'
                ))
                continue
            
            # 解析TCP丢包
            tcp_match = self.patterns['tcp_loss'].search(line)
            if tcp_match:
                time_str, interface, rate, sent, retrans, level = tcp_match.groups()
                metrics.append(NetworkMetric(
                    timestamp=time_str,
                    interface=interface,
                    tcp_loss_rate=float(rate),
                    level=level
                ))
                continue
            
            # 解析流量监控
            traffic_match = self.patterns['traffic'].search(line)
            if traffic_match:
                time_str, interface, mbps, flows, pps = traffic_match.groups()
                metrics.append(NetworkMetric(
                    timestamp=time_str,
                    interface=interface,
                    traffic_mbps=float(mbps),
                    flows=int(flows),
                    pps=int(pps)
                ))
                continue
            
            # 解析RSSI监控
            rssi_match = self.patterns['rssi'].search(line)
            if rssi_match:
                time_str, interface, rssi, quality, using = rssi_match.groups()
                metrics.append(NetworkMetric(
                    timestamp=time_str,
                    interface=interface,
                    rssi=int(rssi),
                    quality=int(quality),
                    using=using == 'YES'
                ))
                continue
            
            # 解析接口汇总
            summary_match = self.patterns['interface_summary'].search(line)
            if summary_match:
                time_str, interface, rtt, quality, rssi, tcp_loss, traffic = summary_match.groups()
                metrics.append(NetworkMetric(
                    timestamp=time_str,
                    interface=interface,
                    rtt=float(rtt) if rtt != '-1' else None,
                    quality=int(quality),
                    rssi=int(rssi) if rssi != '-1000' else None,
                    tcp_loss_rate=float(tcp_loss) if tcp_loss != '-1' else None,
                    traffic_mbps=float(traffic)
                ))
                continue
            
            # 解析网络质量
            quality_match = self.patterns['network_quality'].search(line)
            if quality_match:
                time_str, interface, quality_level, score = quality_match.groups()
                metrics.append(NetworkMetric(
                    timestamp=time_str,
                    interface=interface,
                    quality=float(score)
                ))
                continue
        
        return metrics

# 每次启动构建云 embedding FAISS，并通过 RetrievalQA 生成诊断。
class TrueRAGNetworkAnalyzer:
    """编排知识建库、Retriever 问答链、时间点分析和本地降级逻辑。"""
    
    # 初始化模型、临时向量库和问答链，失败时保留本地降级路径。
    def __init__(self, api_key: str):
        """初始化模型客户端；依赖可用时现场构建知识索引和问答链。"""
        self.api_key = api_key
        self.client = None
        self.vector_store = None
        self.qa_chain = None
        self.parser = LogCaptureParser()
        self.use_rag = False
        
        # 初始化阿里百炼客户端
        try:
            os.environ["DASHSCOPE_API_KEY"] = api_key
            self.client = OpenAI(
                api_key=os.getenv("DASHSCOPE_API_KEY"),
                base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
            )
            print("✅ 阿里百炼API初始化成功")
        # 模型客户端无法创建时结束在线初始化，避免后续空引用。
        except Exception as e:
            print(f"⚠️ 阿里百炼API初始化失败: {e}")
            return
        
        # 初始化RAG系统
        if RAG_AVAILABLE:
            try:
                self._build_vector_store()
                self._create_qa_chain()
                self.use_rag = True
                print("✅ RAG系统初始化成功")
            # 建库或问答链失败时关闭 RAG 标记，后续走本地报告。
            except Exception as e:
                print(f"⚠️ RAG系统初始化失败: {e}")
                print("将使用简化模式")
                self.use_rag = False
        else:
            print("⚠️ RAG依赖不可用，使用简化模式")
    
    # 把静态知识库切块后用 DashScope embedding 构建内存 FAISS。
    def _build_vector_store(self):
        """把嵌套知识字典展平、切块并写入内存 FAISS 索引。"""
        print("🔨 构建网络知识库向量存储...")
        
        # 获取网络知识库
        knowledge_base = get_network_knowledge()
        
        # 每个顶层知识类别先转为一篇 Document，再由 splitter 控制检索粒度。
        documents = []
        for category, content in knowledge_base.items():
            # 创建文档内容
            doc_content = f"网络分析知识 - {category}\n\n"
            
            if isinstance(content, dict):
                for key, value in content.items():
                    if isinstance(value, dict):
                        doc_content += f"{key}:\n"
                        for sub_key, sub_value in value.items():
                            doc_content += f"  {sub_key}: {sub_value}\n"
                    else:
                        doc_content += f"{key}: {value}\n"
            else:
                doc_content += str(content)
            
            documents.append(Document(page_content=doc_content, metadata={"category": category}))
        
        # 文本分割
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200,
            length_function=len,
        )
        
        splits = text_splitter.split_documents(documents)
        print(f"📚 知识库分割为 {len(splits)} 个文档块")
        
        # 创建嵌入 - 使用简化的嵌入方式
        try:
            embeddings = OpenAIEmbeddings(
                openai_api_key=self.api_key,
                openai_api_base="https://dashscope.aliyuncs.com/compatible-mode/v1",
                model="text-embedding-v1"
            )
        # embedding 初始化失败后记录降级意图，交由后续建库结果决定可用性。
        except Exception as e:
            print(f"⚠️ 嵌入模型初始化失败: {e}")
            print("使用简化的文本匹配模式")
            embeddings = None
        
        # 构建向量存储
        self.vector_store = FAISS.from_documents(splits, embeddings)
        print("✅ 向量存储构建完成")
    
    # 组合检索器、提示模板和模型，形成返回来源文档的问答链。
    def _create_qa_chain(self):
        """将 FAISS Retriever、提示模板和模型客户端组装成 RetrievalQA。"""
        print("🔗 创建RAG问答链...")
        
        # 创建提示模板
        prompt_template = """作为网络问题诊断专家，请基于以下网络知识库信息分析网络状况：

网络知识库信息：
{context}

用户问题：{question}

请提供详细的分析报告，包括：
1. 网络状况评估
2. 问题识别
3. 原因分析
4. 解决建议

回答："""

        PROMPT = PromptTemplate(
            template=prompt_template,
            input_variables=["context", "question"]
        )
        
        # 创建检索器
        retriever = self.vector_store.as_retriever(search_kwargs={"k": 3})
        
        # 创建问答链
        self.qa_chain = RetrievalQA.from_chain_type(
            llm=self.client,
            chain_type="stuff",
            retriever=retriever,
            chain_type_kwargs={"prompt": PROMPT},
            return_source_documents=True
        )
        
        print("✅ RAG问答链创建完成")
    
    # 精确选择时间点指标并执行检索问答，异常时退回本地分析。
    def analyze_time_point(self, log_data: str, time_point: str) -> str:
        """精确选取目标时间指标并调用 QA 链；异常时生成本地报告。"""
        print(f"🔍 RAG分析时间点: {time_point}")
        
        # 解析日志数据
        metrics = self.parser.parse_log_capture_output(log_data)
        
        # 获取该时间点的指标
        time_metrics = [m for m in metrics if m.timestamp == time_point]
        
        if not time_metrics:
            return f"❌ 未找到时间点 {time_point} 的网络数据"
        
        print(f"📊 找到时间点 {time_point} 的 {len(time_metrics)} 个指标")
        
        # 构建分析问题
        question = self._build_analysis_question(time_point, time_metrics)
        
        # 使用RAG进行分析
        if self.use_rag and self.qa_chain:
            try:
                print("🤖 使用RAG系统分析...")
                result = self.qa_chain({"query": question})
                
                analysis = result["result"]
                sources = result["source_documents"]
                
                # 添加来源信息
                analysis += "\n\n📚 分析依据：\n"
                for i, doc in enumerate(sources, 1):
                    category = doc.metadata.get("category", "未知")
                    analysis += f"{i}. {category}\n"
                
                return analysis
                
            # 问答链运行失败不终止进程，改用固定阈值报告。
            except Exception as e:
                print(f"⚠️ RAG分析失败: {e}")
                return self._fallback_analysis(time_point, time_metrics)
        else:
            return self._fallback_analysis(time_point, time_metrics)
    
    # 按接口整理指标，构建 RetrievalQA 的 query。
    def _build_analysis_question(self, time_point: str, metrics: List[NetworkMetric]) -> str:
        """按接口整理事实指标，生成 Retriever 问答链的 query。"""
        question = f"请分析在 {time_point} 时间点的网络情况。\n\n"
        question += "网络指标数据：\n"
        
        # 按接口分组指标
        interface_metrics = {}
        for metric in metrics:
            if metric.interface not in interface_metrics:
                interface_metrics[metric.interface] = []
            interface_metrics[metric.interface].append(metric)
        
        for interface, iface_metrics in interface_metrics.items():
            question += f"\n接口 {interface}:\n"
            
            for metric in iface_metrics:
                question += f"- 时间: {metric.timestamp}\n"
                if metric.rtt is not None:
                    question += f"  RTT延迟: {metric.rtt}ms\n"
                if metric.tcp_loss_rate is not None:
                    question += f"  TCP丢包率: {metric.tcp_loss_rate}%\n"
                if metric.traffic_mbps is not None:
                    question += f"  网络流量: {metric.traffic_mbps}MB/s\n"
                if metric.rssi is not None:
                    question += f"  WiFi信号: {metric.rssi}dBm\n"
                if metric.quality is not None:
                    question += f"  质量评分: {metric.quality}\n"
                if metric.flows is not None:
                    question += f"  活跃连接: {metric.flows}\n"
                if metric.pps is not None:
                    question += f"  包速率: {metric.pps} pps\n"
                if metric.level is not None:
                    question += f"  丢包等级: {metric.level}\n"
                question += "\n"
        
        return question
    
    # RAG 不可用时生成不依赖外部服务的本地报告。
    def _fallback_analysis(self, time_point: str, metrics: List[NetworkMetric]) -> str:
        """在向量链不可用时按固定阈值生成确定性诊断摘要。"""
        print("📊 使用备用分析模式...")
        
        # 简单的本地分析
        analysis = f"🔍 {time_point} 时间点网络情况分析（备用模式）\n"
        analysis += "=" * 60 + "\n"
        
        # 按接口分组
        interface_metrics = {}
        for metric in metrics:
            if metric.interface not in interface_metrics:
                interface_metrics[metric.interface] = []
            interface_metrics[metric.interface].append(metric)
        
        for interface, iface_metrics in interface_metrics.items():
            analysis += f"\n📡 接口 {interface} 分析:\n"
            
            # 统计指标
            rtt_values = [m.rtt for m in iface_metrics if m.rtt is not None]
            tcp_loss_values = [m.tcp_loss_rate for m in iface_metrics if m.tcp_loss_rate is not None]
            traffic_values = [m.traffic_mbps for m in iface_metrics if m.traffic_mbps is not None]
            rssi_values = [m.rssi for m in iface_metrics if m.rssi is not None]
            
            if rtt_values:
                avg_rtt = sum(rtt_values) / len(rtt_values)
                status = "🟢 优秀" if avg_rtt <= 10 else "🟡 良好" if avg_rtt <= 30 else "🟠 一般" if avg_rtt <= 50 else "🔴 较差"
                analysis += f"  • RTT延迟: {avg_rtt:.1f}ms {status}\n"
            
            if tcp_loss_values:
                avg_loss = sum(tcp_loss_values) / len(tcp_loss_values)
                status = "🟢 优秀" if avg_loss <= 0.5 else "🟡 良好" if avg_loss <= 1 else "🟠 一般" if avg_loss <= 3 else "🔴 较差"
                analysis += f"  • TCP丢包率: {avg_loss:.2f}% {status}\n"
            
            if traffic_values:
                avg_traffic = sum(traffic_values) / len(traffic_values)
                status = "🟢 正常" if avg_traffic > 0 else "🔴 异常"
                analysis += f"  • 网络流量: {avg_traffic:.1f}MB/s {status}\n"
            
            if rssi_values:
                avg_rssi = sum(rssi_values) / len(rssi_values)
                status = "🟢 优秀" if avg_rssi >= -50 else "🟡 良好" if avg_rssi >= -60 else "🟠 一般" if avg_rssi >= -70 else "🔴 较差"
                analysis += f"  • WiFi信号: {avg_rssi:.0f}dBm {status}\n"
        
        analysis += f"\n💡 建议: 启用RAG系统可获得更详细的分析报告"
        
        return analysis
    
    # 返回日志中全部唯一时间点及指标计数。
    def get_available_times(self, log_data: str) -> str:
        """获取可用的时间点"""
        metrics = self.parser.parse_log_capture_output(log_data)
        
        # 获取所有唯一的时间点
        times = sorted(set(metric.timestamp for metric in metrics))
        
        summary = []
        summary.append("📅 可用时间点:")
        summary.append("=" * 30)
        
        for time_str in times:
            count = len([m for m in metrics if m.timestamp == time_str])
            summary.append(f"• {time_str}: {count} 个指标")
        
        return "\n".join(summary)

# 使用内置样例演示临时向量库 RAG 的完整流程。
def main():
    """通过内置样例演示建库和多个时间点的分析结果。"""
    # 初始化真正的RAG系统
    api_key = "YOUR_DASHSCOPE_API_KEY_HERE"  # 请替换为您的阿里百炼API密钥
    rag_analyzer = TrueRAGNetworkAnalyzer(api_key)
    
    # 示例log_capture.py输出
    sample_log_data = """
🎯 [00:13:24] RTT监控: eth0 = 15ms (质量:1, 使用:YES, 目标:223.5.5.5)
📈 [00:13:34] TCP详细: eth0 = 0.5% (发送:137, 重传:0, 等级:good)
🌊 [00:13:24] 流量监控: eth0 = 2.5MB/s (连接:15, 包/秒:1200)
📶 [00:13:24] RSSI监控: wlan0 = -65dBm (质量:2, 使用:NO)
📋 [00:13:24] 接口汇总: eth0 = RTT:15ms, 质量:1, RSSI:-1000dBm, TCP丢包:0.5%, 流量:2.5MB/s
⭐ [00:13:30] 网络质量: eth0 = good (分数:85.5)
🎯 [00:13:50] RTT监控: eth0 = 18ms (质量:1, 使用:YES, 目标:223.5.5.5)
📈 [00:13:55] TCP详细: eth0 = 0.8% (发送:145, 重传:1, 等级:good)
🌊 [00:13:50] 流量监控: eth0 = 3.2MB/s (连接:18, 包/秒:1500)
    """
    
    print("🚀 真正的RAG网络分析系统")
    print("=" * 60)
    
    # 显示可用时间点
    print("\n" + rag_analyzer.get_available_times(sample_log_data))
    
    # 分析特定时间点
    time_points = ["00:13:24", "00:13:30", "00:13:50"]
    
    for time_point in time_points:
        print(f"\n{'='*60}")
        print(f"🔍 RAG分析时间点: {time_point}")
        print('='*60)
        
        result = rag_analyzer.analyze_time_point(sample_log_data, time_point)
        print(result)

if __name__ == "__main__":
    main()
