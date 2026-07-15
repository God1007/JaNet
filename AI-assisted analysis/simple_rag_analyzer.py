#!/usr/bin/env python3
"""
文件职责：根据已出现的指标类型和固定阈值选择静态知识，再把知识与指标一起交给大模型。
该版本不使用向量库；检索是确定性的规则匹配，模型不可用时输出本地阈值报告。
"""

import os
import re
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

try:
    from openai import OpenAI
    DASHSCOPE_AVAILABLE = True
# OpenAI SDK 缺失时自动保留纯本地分析模式。
except ImportError as e:
    print(f"⚠️ OpenAI依赖不可用: {e}")
    DASHSCOPE_AVAILABLE = False

from network_knowledge_base import get_network_knowledge

# 表示从单条规范化日志中提取的网络指标。
@dataclass
class NetworkMetric:
    """日志解析后的单项网络观测，字段为 ``None`` 表示该行没有该指标。"""
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

# 用预编译正则把日志文本转换为 NetworkMetric。
class LogCaptureParser:
    """解析 ``log_capture.py`` 的展示文本并创建结构化指标。"""
    
    # 初始化各类指标日志的匹配模式。
    def __init__(self):
        """预编译各类指标日志的正则表达式。"""
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
    
    # 逐行匹配日志并输出结构化指标列表。
    def parse_log_capture_output(self, log_data: str) -> List[NetworkMetric]:
        """逐行匹配指标格式；不能识别的日志不会进入诊断输入。"""
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

# 按指标类型规则检索静态知识，再选择 DashScope 或本地报告生成。
class SimpleRAGNetworkAnalyzer:
    """用规则选择知识片段，并编排 AI 分析与本地降级报告。"""
    
    # 初始化知识库、解析器和可选模型客户端。
    def __init__(self, api_key: str):
        """加载静态知识库并尝试初始化模型客户端，失败时切换为本地模式。"""
        self.api_key = api_key
        self.client = None
        self.knowledge_base = get_network_knowledge()
        self.parser = LogCaptureParser()
        self.use_ai = False
        
        # 初始化阿里百炼客户端
        if DASHSCOPE_AVAILABLE and api_key:
            try:
                os.environ["DASHSCOPE_API_KEY"] = api_key
                self.client = OpenAI(
                    api_key=os.getenv("DASHSCOPE_API_KEY"),
                    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
                )
                self.use_ai = True
                print("✅ 阿里百炼API初始化成功")
            # 客户端初始化异常时关闭 AI 分支，后续仍可执行规则诊断。
            except Exception as e:
                print(f"⚠️ 阿里百炼API初始化失败: {e}")
                self.use_ai = False
        else:
            print("⚠️ 使用本地分析模式")
    
    # 根据已出现指标和阈值手工选择相关知识片段，不使用向量检索。
    def _retrieve_relevant_knowledge(self, metrics: List[NetworkMetric]) -> str:
        """依据指标是否存在及是否越过阈值，选择对应症状和排障建议。"""
        relevant_knowledge = []
        
        for metric in metrics:
            # 根据指标类型检索相关知识
            if metric.rtt is not None:
                rtt_knowledge = self.knowledge_base.get("rtt_analysis", {})
                if rtt_knowledge:
                    relevant_knowledge.append(f"RTT分析知识: {rtt_knowledge.get('description', '')}")
                    if metric.rtt > 50:
                        relevant_knowledge.append(f"高RTT问题: {rtt_knowledge.get('symptoms', {}).get('high_rtt', '')}")
                        relevant_knowledge.append(f"解决方案: {rtt_knowledge.get('troubleshooting', {}).get('high_rtt', '')}")
            
            if metric.tcp_loss_rate is not None:
                tcp_knowledge = self.knowledge_base.get("tcp_loss_analysis", {})
                if tcp_knowledge:
                    relevant_knowledge.append(f"TCP丢包分析知识: {tcp_knowledge.get('description', '')}")
                    if metric.tcp_loss_rate > 1:
                        relevant_knowledge.append(f"高丢包问题: {tcp_knowledge.get('symptoms', {}).get('high_loss', '')}")
                        relevant_knowledge.append(f"解决方案: {tcp_knowledge.get('troubleshooting', {}).get('high_loss', '')}")
            
            if metric.rssi is not None:
                rssi_knowledge = self.knowledge_base.get("rssi_analysis", {})
                if rssi_knowledge:
                    relevant_knowledge.append(f"WiFi信号分析知识: {rssi_knowledge.get('description', '')}")
                    if metric.rssi < -70:
                        relevant_knowledge.append(f"弱信号问题: {rssi_knowledge.get('symptoms', {}).get('low_rssi', '')}")
                        relevant_knowledge.append(f"解决方案: {rssi_knowledge.get('troubleshooting', {}).get('low_rssi', '')}")
            
            if metric.traffic_mbps is not None:
                traffic_knowledge = self.knowledge_base.get("traffic_analysis", {})
                if traffic_knowledge:
                    relevant_knowledge.append(f"流量分析知识: {traffic_knowledge.get('description', '')}")
                    if metric.traffic_mbps == 0:
                        relevant_knowledge.append(f"零流量问题: {traffic_knowledge.get('symptoms', {}).get('zero_traffic', '')}")
                        relevant_knowledge.append(f"解决方案: {traffic_knowledge.get('troubleshooting', {}).get('zero_traffic', '')}")
        
        # 通用问题无条件追加，用于补足单项指标规则无法覆盖的场景。
        common_issues = self.knowledge_base.get("common_issues", {})
        for issue_type, issue_info in common_issues.items():
            relevant_knowledge.append(f"{issue_type}: {issue_info.get('symptoms', [])}")
            relevant_knowledge.append(f"解决方案: {issue_info.get('solutions', [])}")
        
        return "\n".join(relevant_knowledge)
    
    # 精确筛选时间点，将规则检索知识和指标一起交给模型分析。
    def analyze_time_point(self, log_data: str, time_point: str) -> str:
        """精确筛选目标时间的指标，检索静态知识，然后选择模型或本地报告。"""
        print(f"🔍 简化RAG分析时间点: {time_point}")
        
        # 解析日志数据
        metrics = self.parser.parse_log_capture_output(log_data)
        
        # 获取该时间点的指标
        time_metrics = [m for m in metrics if m.timestamp == time_point]
        
        if not time_metrics:
            return f"❌ 未找到时间点 {time_point} 的网络数据"
        
        print(f"📊 找到时间点 {time_point} 的 {len(time_metrics)} 个指标")
        
        # 从知识库检索相关知识
        relevant_knowledge = self._retrieve_relevant_knowledge(time_metrics)
        knowledge_lines = relevant_knowledge.split('\n')
        print(f"📚 检索到 {len(knowledge_lines)} 条相关知识")
        
        # 构建分析问题
        question = self._build_analysis_question(time_point, time_metrics)
        
        # 使用AI进行分析
        if self.use_ai and self.client:
            try:
                print("🤖 使用AI+RAG系统分析...")
                
                # 将规则选中的知识和原始指标同时放入 prompt，使回答有可追溯依据。
                full_prompt = f"""作为网络问题诊断专家，请基于以下网络知识库信息分析网络状况：

网络知识库信息：
{relevant_knowledge}

{question}

请提供详细的分析报告，包括：
1. 网络状况评估
2. 问题识别
3. 原因分析
4. 解决建议
5. 分析依据（基于知识库的哪些信息）"""

                completion = self.client.chat.completions.create(
                    model="qwen-plus",
                    messages=[
                        {"role": "system", "content": "你是一个专业的网络问题诊断专家，擅长基于知识库进行网络分析。"},
                        {"role": "user", "content": full_prompt}
                    ],
                    extra_body={"enable_thinking": False}
                )
                
                result = completion.choices[0].message.content
                print("✅ AI+RAG分析完成")
                return result
                
            # 模型请求失败时保留已检索知识，转入本地阈值报告。
            except Exception as e:
                print(f"⚠️ AI分析失败: {e}")
                return self._fallback_analysis(time_point, time_metrics, relevant_knowledge)
        else:
            return self._fallback_analysis(time_point, time_metrics, relevant_knowledge)
    
    # 按接口整理指标，生成模型可读的问题描述。
    def _build_analysis_question(self, time_point: str, metrics: List[NetworkMetric]) -> str:
        """按接口分组指标，生成不包含知识库的事实部分。"""
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
    
    # 无 AI 时按固定阈值解释指标，并附上规则检索到的知识。
    def _fallback_analysis(self, time_point: str, metrics: List[NetworkMetric], knowledge: str) -> str:
        """模型调用不可用时，使用固定阈值和知识摘要生成确定性报告。"""
        print("📊 使用本地RAG分析模式...")
        
        # 基于知识库的本地分析
        analysis = f"🔍 {time_point} 时间点网络情况分析（本地RAG模式）\n"
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
                
                # 基于知识库的分析
                if avg_rtt > 50:
                    analysis += f"    📚 知识库建议: 高RTT可能导致网络延迟增加，影响实时应用性能\n"
            
            if tcp_loss_values:
                avg_loss = sum(tcp_loss_values) / len(tcp_loss_values)
                status = "🟢 优秀" if avg_loss <= 0.5 else "🟡 良好" if avg_loss <= 1 else "🟠 一般" if avg_loss <= 3 else "🔴 较差"
                analysis += f"  • TCP丢包率: {avg_loss:.2f}% {status}\n"
                
                # 基于知识库的分析
                if avg_loss > 1:
                    analysis += f"    📚 知识库建议: 高丢包率会导致数据传输重传，降低网络效率\n"
            
            if traffic_values:
                avg_traffic = sum(traffic_values) / len(traffic_values)
                status = "🟢 正常" if avg_traffic > 0 else "🔴 异常"
                analysis += f"  • 网络流量: {avg_traffic:.1f}MB/s {status}\n"
                
                # 基于知识库的分析
                if avg_traffic == 0:
                    analysis += f"    📚 知识库建议: 零流量可能表示网络中断或监控问题\n"
            
            if rssi_values:
                avg_rssi = sum(rssi_values) / len(rssi_values)
                status = "🟢 优秀" if avg_rssi >= -50 else "🟡 良好" if avg_rssi >= -60 else "🟠 一般" if avg_rssi >= -70 else "🔴 较差"
                analysis += f"  • WiFi信号: {avg_rssi:.0f}dBm {status}\n"
                
                # 基于知识库的分析
                if avg_rssi < -70:
                    analysis += f"    📚 知识库建议: 弱信号会导致连接不稳定、速度慢\n"
        
        # 添加知识库摘要
        analysis += f"\n📚 知识库检索摘要:\n"
        knowledge_lines = knowledge.split('\n')
        analysis += f"检索到 {len(knowledge_lines)} 条相关知识\n"
        analysis += f"💡 建议: 启用AI分析可获得更详细的报告"
        
        return analysis
    
    # 返回日志中可精确查询的时间点及指标数量。
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

# 使用样例日志演示简化检索与时间点分析。
def main():
    """使用内置样例验证解析、知识选择与报告生成链路。"""
    # 初始化简化RAG系统
    api_key = "YOUR_DASHSCOPE_API_KEY_HERE"  # 请替换为您的阿里百炼API密钥
    rag_analyzer = SimpleRAGNetworkAnalyzer(api_key)
    
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
    
    print("🚀 简化版RAG网络分析系统")
    print("=" * 60)
    
    # 显示可用时间点
    print("\n" + rag_analyzer.get_available_times(sample_log_data))
    
    # 分析特定时间点
    time_points = ["00:13:24", "00:13:30", "00:13:50"]
    
    for time_point in time_points:
        print(f"\n{'='*60}")
        print(f"🔍 简化RAG分析时间点: {time_point}")
        print('='*60)
        
        result = rag_analyzer.analyze_time_point(sample_log_data, time_point)
        print(result)

if __name__ == "__main__":
    main()
