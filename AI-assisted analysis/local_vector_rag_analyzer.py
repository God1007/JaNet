#!/usr/bin/env python3
"""
文件职责：把格式化网络日志解析为指标，使用本地特征哈希向量检索静态知识库，再调用大模型生成诊断。
只有向量化和检索在本地完成；最终问题、指标与检索上下文仍会发送给配置的大模型 API。
"""

import os
import re
from typing import List, Optional
from dataclasses import dataclass

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OpenAI = None
    OPENAI_AVAILABLE = False

from knowledge_pipeline import (
    DEFAULT_ARTIFACT_ROOT,
    DEFAULT_GOLDEN_PATH,
    DEFAULT_RAW_PATH,
    DEFAULT_SCHEMA_PATH,
    KnowledgeLifecycle,
    StableHashEmbeddings,
    open_default_store,
)

# 版本化检索核心只依赖标准库，FAISS/LangChain 是构建制品中记录的可选增强。
VECTOR_RAG_AVAILABLE = True

# 表示从日志中解析出的单项网络指标，未出现的字段保持为空。
@dataclass
class NetworkMetric:
    """一条已解析的网络观测；同一时刻、同一接口可能对应多条不同指标记录。"""
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

# 保留旧类名，但实际使用 SHA-256 稳定特征哈希，不再受 PYTHONHASHSEED 影响。
class SimpleEmbeddings(StableHashEmbeddings):
    """旧入口兼容层；向量实现由 ``StableHashEmbeddings`` 统一管理。"""

    def _text_to_embedding(self, text):
        """保留历史调试方法名，转发到稳定 tokenizer/embedding 流程。"""
        return super().embed_query(text)

# 将 log_capture.py 的规范化文本解析为 NetworkMetric 列表。
class LogCaptureParser:
    """将 ``log_capture.py`` 的展示文本还原为可供分析的结构化指标。"""
    
    # 预编译各类指标日志的正则，避免逐行解析时重复构造。
    def __init__(self):
        """预编译每种展示日志对应的正则，避免逐行解析时反复构造表达式。"""
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
    
    # 按行匹配首个指标模式，并把哨兵值转换为空字段。
    def parse_log_capture_output(self, log_data: str) -> List[NetworkMetric]:
        """逐行尝试指标正则；每个成功匹配的行只生成一条 ``NetworkMetric``。"""
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

# 串联日志解析、版本化本地检索、DashScope 生成和规则降级分析。
class LocalVectorRAGAnalyzer:
    """负责知识库索引生命周期、相似度检索、大模型调用与本地降级分析。"""
    
    # 初始化模型客户端和向量库；任一依赖失败时保留本地规则能力。
    def __init__(self, api_key: str):
        """初始化日志解析器、版本化检索制品与可选模型客户端。"""
        self.api_key = api_key
        self.client = None
        self.vector_store = None
        self.knowledge_store = None
        self.embeddings = SimpleEmbeddings()
        self.parser = LogCaptureParser()
        self.use_vector_rag = False
        self.vector_store_path = str(DEFAULT_ARTIFACT_ROOT)
        self.top_k = int(os.getenv("RAG_TOP_K", "4"))
        self.similarity_threshold = float(os.getenv("RAG_SIMILARITY_THRESHOLD", "0.08"))
        
        # 在线模型失败不再阻断本地索引加载，避免把检索可用性错误绑定到 API Key。
        if OPENAI_AVAILABLE and api_key and "YOUR_" not in api_key:
            try:
                os.environ["DASHSCOPE_API_KEY"] = api_key
                self.client = OpenAI(
                    api_key=os.getenv("DASHSCOPE_API_KEY"),
                    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
                )
                print("✅ 阿里百炼API初始化成功")
            except Exception as e:
                print(f"⚠️ 阿里百炼API初始化失败: {e}")
        
        # 初始化本地向量RAG系统
        if VECTOR_RAG_AVAILABLE:
            try:
                self._initialize_vector_store()
                self.use_vector_rag = True
                print("✅ 本地向量RAG系统初始化成功")
            # 向量库不可用时保留解析器和规则分析能力。
            except Exception as e:
                print(f"⚠️ 本地向量RAG系统初始化失败: {e}")
                print("将使用简化模式")
                self.use_vector_rag = False
        else:
            print("⚠️ 向量RAG依赖不可用，使用简化模式")
    
    # 优先加载持久化索引，失败或不存在时全量重建知识库向量。
    def _initialize_vector_store(self):
        """校验 current manifest、源 checksum 和兼容性，必要时从 raw 全量重建。"""
        print("🔨 初始化版本化本地知识制品...")
        self.knowledge_store = open_default_store(auto_rebuild=True)
        # 保留 vector_store 属性，避免破坏检查该属性的旧调用方。
        self.vector_store = self.knowledge_store
        print(f"✅ 知识制品已加载: {self.knowledge_store.artifact_version}")
    
    # 从已审核 raw 全量重建，评测通过后才切换 current 制品。
    def _build_vector_store(self):
        """通过评测门禁后发布新制品，再加载原子切换后的 current。"""
        print("🔨 从结构化 raw knowledge 全量构建...")
        lifecycle = KnowledgeLifecycle(
            raw_path=DEFAULT_RAW_PATH,
            schema_path=DEFAULT_SCHEMA_PATH,
            golden_path=DEFAULT_GOLDEN_PATH,
            artifact_root=DEFAULT_ARTIFACT_ROOT,
        )
        lifecycle.release()
        self.knowledge_store = open_default_store(auto_rebuild=False)
        self.vector_store = self.knowledge_store
        print(f"✅ 新知识制品已发布: {self.knowledge_store.artifact_version}")
    
    # 精确筛选时间点指标，检索 Top-K 知识并调用模型生成诊断报告。
    def analyze_time_point(self, log_data: str, time_point: str) -> str:
        """按时间精确筛选指标，检索相关知识并调用模型；任一步失败都退回规则报告。"""
        print(f"🔍 本地向量RAG分析时间点: {time_point}")
        
        # 解析日志数据
        metrics = self.parser.parse_log_capture_output(log_data)
        
        # 当前实现使用时间字符串精确相等，不会自动聚合同一时间窗口内的异步指标。
        time_metrics = [m for m in metrics if m.timestamp == time_point]
        
        if not time_metrics:
            return f"❌ 未找到时间点 {time_point} 的网络数据"
        
        print(f"📊 找到时间点 {time_point} 的 {len(time_metrics)} 个指标")
        
        # 构建分析问题
        question = self._build_analysis_question(time_point, time_metrics)
        
        # 使用本地向量RAG进行分析
        if self.use_vector_rag and self.knowledge_store:
            try:
                print("🤖 使用本地向量RAG系统分析...")
                
                # Top-K 和最低相似度均可配置；低于阈值的结果不会交给模型猜测。
                retrieval = self.knowledge_store.retrieve(
                    question,
                    top_k=self.top_k,
                    similarity_threshold=self.similarity_threshold,
                )
                if retrieval.insufficient_evidence:
                    fallback = self._fallback_analysis(time_point, time_metrics)
                    return fallback + "\n\n⚠️ 知识库证据不足：无相似度达标的已审核条目。"
                
                # 构建上下文
                context = "\n\n".join(
                    f"[{item.entry_id} | {item.content_hash}]\n{item.content}"
                    for item in retrieval.evidence
                )
                
                # 使用AI进行分析
                if self.client:
                    full_prompt = f"""作为网络问题诊断专家，请基于以下检索到的网络知识库信息分析网络状况：

检索到的知识库信息：
{context}

{question}

请提供详细的分析报告，包括：
1. 网络状况评估
2. 问题识别
3. 原因分析（基于知识库信息）
4. 解决建议（引用知识库中的解决方案）
5. 分析依据（说明使用了哪些知识库信息）

回答："""

                    completion = self.client.chat.completions.create(
                        model="qwen-plus",
                        messages=[
                            {"role": "system", "content": "你是一个专业的网络问题诊断专家，擅长基于知识库进行网络分析。"},
                            {"role": "user", "content": full_prompt}
                        ],
                        extra_body={"enable_thinking": False}
                    )
                    
                    result = completion.choices[0].message.content
                    
                    # 添加来源信息
                    result += "\n\n📚 向量检索来源：\n"
                    for i, item in enumerate(retrieval.evidence, 1):
                        content_preview = item.content[:100] + "..." if len(item.content) > 100 else item.content
                        result += (
                            f"{i}. {item.entry_id} (score={item.score:.4f}, "
                            f"content_hash={item.content_hash[:12]}): {content_preview}\n"
                        )
                    
                    print("✅ 本地向量RAG分析完成")
                    return result
                else:
                    return self._fallback_analysis(time_point, time_metrics, context)
                
            # 检索或模型调用异常时不向上传播，退回确定性本地分析。
            except Exception as e:
                print(f"⚠️ 本地向量RAG分析失败: {e}")
                return self._fallback_analysis(time_point, time_metrics)
        else:
            return self._fallback_analysis(time_point, time_metrics)
    
    # 按网卡聚合指标并拼成同时供检索和生成使用的问题文本。
    def _build_analysis_question(self, time_point: str, metrics: List[NetworkMetric]) -> str:
        """构建分析问题"""
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
    
    # 在向量库或云模型不可用时，按固定阈值生成本地可读报告。
    def _fallback_analysis(self, time_point: str, metrics: List[NetworkMetric], context: str = "") -> str:
        """在索引或模型不可用时，按固定阈值生成确定性的本地文本报告。"""
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
        
        if context:
            analysis += f"\n📚 检索到的知识库信息:\n{context[:200]}...\n"
        
        analysis += f"\n💡 建议: 启用本地向量RAG系统可获得更详细的分析报告"
        
        return analysis
    
    # 汇总日志中出现过的唯一时间点及其指标数量。
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
    
    # 单独暴露可配置 Top-K 相似检索，便于验证召回和引用。
    def search_knowledge(self, query: str) -> str:
        """查询已发布知识制品，结果带稳定 ID、score 和内容指纹。"""
        if not self.use_vector_rag or not self.knowledge_store:
            return "❌ 本地向量RAG系统不可用"
        
        try:
            print(f"🔍 搜索知识库: {query}")
            
            retrieval = self.knowledge_store.retrieve(
                query,
                top_k=self.top_k,
                similarity_threshold=self.similarity_threshold,
            )
            if retrieval.insufficient_evidence:
                return "⚠️ 知识库证据不足：请提供更具体的指标、数值和现象"
            
            result = f"📚 知识库搜索结果 (查询: {query}):\n"
            result += "=" * 50 + "\n"
            
            for i, item in enumerate(retrieval.evidence, 1):
                content = item.content[:200] + "..." if len(item.content) > 200 else item.content
                result += f"\n{i}. {item.entry_id} (score={item.score:.4f}):\n{content}\n"
            
            return result
            
        # 检索异常转换为可读错误，避免交互会话退出。
        except Exception as e:
            return f"❌ 搜索失败: {e}"

# 使用内置样例演示时间点枚举、知识检索和诊断流程。
def main():
    """主函数 - 示例用法"""
    # 初始化本地向量RAG系统
    api_key = "YOUR_DASHSCOPE_API_KEY_HERE"  # 请替换为您的阿里百炼API密钥
    rag_analyzer = LocalVectorRAGAnalyzer(api_key)
    
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
    
    print("🚀 本地向量库RAG网络分析系统")
    print("=" * 60)
    
    # 显示可用时间点
    print("\n" + rag_analyzer.get_available_times(sample_log_data))
    
    # 测试知识库搜索
    print(f"\n{'='*60}")
    print("🔍 测试知识库搜索")
    print('='*60)
    search_result = rag_analyzer.search_knowledge("RTT延迟分析")
    print(search_result)
    
    # 分析特定时间点
    time_points = ["00:13:24", "00:13:30", "00:13:50"]
    
    for time_point in time_points:
        print(f"\n{'='*60}")
        print(f"🔍 本地向量RAG分析时间点: {time_point}")
        print('='*60)
        
        result = rag_analyzer.analyze_time_point(sample_log_data, time_point)
        print(result)

if __name__ == "__main__":
    main()
