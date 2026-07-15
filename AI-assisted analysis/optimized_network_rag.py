#!/usr/bin/env python3
"""
文件职责：解析格式化日志，按目标时间选择指标，并在大模型分析与本地阈值报告之间提供降级切换。
本实现没有向量检索；所谓“RAG”知识直接写入 prompt，主要用于轻量演示。
"""

import os
import re
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from collections import defaultdict

try:
    from openai import OpenAI
    DASHSCOPE_AVAILABLE = True
# OpenAI SDK 不存在时仅启用本地阈值分析。
except ImportError as e:
    print(f"⚠️ OpenAI依赖不可用: {e}")
    DASHSCOPE_AVAILABLE = False

# 表示解析后的单项网络指标及其时间和网卡归属。
@dataclass
class NetworkMetric:
    """日志解析后的单项网络观测，缺失指标使用 ``None`` 表示。"""
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

# 解析日志并提供按时间点筛选的轻量工具。
class LogCaptureParser:
    """把展示型日志转换为时间、接口和指标字段。"""
    
    # 预编译支持的规范化日志格式。
    def __init__(self):
        """预编译日志正则，建立文本格式到指标类型的映射。"""
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
    
    # 将多行日志转换为结构化指标列表。
    def parse_log_capture_output(self, log_data: str) -> List[NetworkMetric]:
        """逐行解析已格式化日志，并忽略无法识别的行。"""
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
    
    # 返回与目标秒级时间戳完全一致的指标。
    def get_metrics_by_time(self, metrics: List[NetworkMetric], target_time: str) -> List[NetworkMetric]:
        """返回时间字符串与目标完全相等的指标集合。"""
        target_metrics = []
        
        for metric in metrics:
            if metric.timestamp == target_time:
                target_metrics.append(metric)
        
        return target_metrics

# 直接把指标和硬编码网络知识发送给模型，并提供本地阈值降级分析。
class OptimizedNetworkRAG:
    """编排日志解析、邻近时间兜底、模型请求与本地规则分析。"""
    
    # 初始化解析器及可选 DashScope 客户端。
    def __init__(self, api_key: str):
        """尝试初始化阿里百炼客户端；依赖或 Key 不可用时保持本地分析模式。"""
        self.api_key = api_key
        self.client = None
        self.parser = LogCaptureParser()
        self.use_dashscope = False
        
        # 初始化阿里百炼客户端
        if DASHSCOPE_AVAILABLE and api_key:
            try:
                os.environ["DASHSCOPE_API_KEY"] = api_key
                self.client = OpenAI(
                    api_key=os.getenv("DASHSCOPE_API_KEY"),
                    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
                )
                self.use_dashscope = True
                print("✅ 阿里百炼API初始化成功")
            # AI 客户端初始化失败时显式切回本地模式。
            except Exception as e:
                print(f"⚠️ 阿里百炼API初始化失败: {e}")
                self.use_dashscope = False
        else:
            print("⚠️ 使用本地分析模式")
    
    # 优先精确匹配时间点，必要时使用一分钟内的最近指标完成分析。
    def analyze_time_point(self, log_data: str, time_point: str) -> str:
        """优先分析精确时间点，缺失时选取 60 秒内最近指标，再选择 AI 或本地分析。"""
        print(f"🔍 分析时间点: {time_point}")
        
        # 解析日志数据
        metrics = self.parser.parse_log_capture_output(log_data)
        print(f"📊 解析到 {len(metrics)} 个网络指标")
        
        # 获取该时间点的指标
        time_metrics = self.parser.get_metrics_by_time(metrics, time_point)
        
        if not time_metrics:
            # 各监控线程采样周期不同，因此精确时间缺失时允许使用最近一批观测。
            time_metrics = self._find_closest_metrics(metrics, time_point)
        
        if not time_metrics:
            return f"❌ 未找到时间点 {time_point} 的网络数据"
        
        print(f"📈 找到时间点 {time_point} 的 {len(time_metrics)} 个指标")
        
        # 构建分析提示
        analysis_prompt = self._build_analysis_prompt(time_point, time_metrics)
        
        # 调用AI分析
        if self.use_dashscope:
            result = self._call_dashscope_api(analysis_prompt)
        else:
            result = self._local_analysis(time_point, time_metrics)
        
        return result
    
    # 计算秒级距离，并仅接受与目标相差不超过一分钟的最近指标。
    def _find_closest_metrics(self, metrics: List[NetworkMetric], target_time: str) -> List[NetworkMetric]:
        """按一天内秒数计算绝对差，返回差值最小且不超过 60 秒的所有指标。"""
        try:
            target_hour, target_minute, target_second = map(int, target_time.split(':'))
            target_total_seconds = target_hour * 3600 + target_minute * 60 + target_second
            
            closest_metrics = []
            min_diff = float('inf')
            
            for metric in metrics:
                metric_hour, metric_minute, metric_second = map(int, metric.timestamp.split(':'))
                metric_total_seconds = metric_hour * 3600 + metric_minute * 60 + metric_second
                diff = abs(metric_total_seconds - target_total_seconds)
                
                if diff < min_diff:
                    min_diff = diff
                    closest_metrics = [metric]
                elif diff == min_diff:
                    closest_metrics.append(metric)
            
            # 如果时间差超过60秒，返回空列表
            if min_diff > 60:
                return []
            
            return closest_metrics
        # 非 HH:MM:SS 输入无法计算秒差，按未找到指标处理。
        except ValueError:
            return []
    
    # 将接口指标和固定诊断阈值拼成完整模型提示词。
    def _build_analysis_prompt(self, time_point: str, metrics: List[NetworkMetric]) -> str:
        """按接口组织指标，并追加硬编码阈值知识和报告要求。"""
        prompt = f"作为网络问题诊断专家，请分析在 {time_point} 时间点的网络情况。\n\n"
        
        prompt += "网络指标数据：\n"
        
        # 按接口分组指标
        interface_metrics = defaultdict(list)
        for metric in metrics:
            interface_metrics[metric.interface].append(metric)
        
        for interface, iface_metrics in interface_metrics.items():
            prompt += f"\n接口 {interface}:\n"
            
            for metric in iface_metrics:
                prompt += f"- 时间: {metric.timestamp}\n"
                if metric.rtt is not None:
                    prompt += f"  RTT延迟: {metric.rtt}ms\n"
                if metric.tcp_loss_rate is not None:
                    prompt += f"  TCP丢包率: {metric.tcp_loss_rate}%\n"
                if metric.traffic_mbps is not None:
                    prompt += f"  网络流量: {metric.traffic_mbps}MB/s\n"
                if metric.rssi is not None:
                    prompt += f"  WiFi信号: {metric.rssi}dBm\n"
                if metric.quality is not None:
                    prompt += f"  质量评分: {metric.quality}\n"
                if metric.flows is not None:
                    prompt += f"  活跃连接: {metric.flows}\n"
                if metric.pps is not None:
                    prompt += f"  包速率: {metric.pps} pps\n"
                if metric.level is not None:
                    prompt += f"  丢包等级: {metric.level}\n"
                prompt += "\n"
        
        prompt += "\n网络分析专业知识：\n"
        prompt += "- RTT正常范围: 1-50ms (优秀: 1-10ms, 良好: 10-30ms, 一般: 30-50ms)\n"
        prompt += "- TCP丢包率正常范围: 0-1% (优秀: 0%, 良好: 0-0.5%, 一般: 0.5-1%)\n"
        prompt += "- WiFi信号强度建议: >-70dBm (优秀: -30~-50dBm, 良好: -50~-60dBm)\n"
        prompt += "- 网络流量异常可能表示连接问题或带宽限制\n"
        prompt += "- 质量评分越高表示网络状况越好\n\n"
        
        prompt += "请提供详细的分析报告，包括：\n"
        prompt += "1. 该时间点的整体网络健康状况\n"
        prompt += "2. 各接口的具体表现\n"
        prompt += "3. 发现的问题或异常\n"
        prompt += "4. 可能的原因分析\n"
        prompt += "5. 改进建议\n"
        prompt += "6. 是否需要进一步监控"
        
        return prompt
    
    # 调用 qwen-plus 生成诊断文本，并把 API 异常转换为可读结果。
    def _call_dashscope_api(self, prompt: str) -> str:
        """向 qwen-plus 发送一次同步请求，并把模型正文或异常信息返回给调用方。"""
        try:
            print("🔄 调用阿里百炼API...")
            
            completion = self.client.chat.completions.create(
                model="qwen-plus",
                messages=[
                    {"role": "system", "content": "你是一个专业的网络问题诊断专家，擅长分析网络日志和指标数据。"},
                    {"role": "user", "content": prompt}
                ],
                extra_body={"enable_thinking": False}
            )
            
            result = completion.choices[0].message.content
            print("✅ 阿里百炼API调用成功")
            return result
            
        # API 错误作为分析文本返回，保持命令行演示不中断。
        except Exception as e:
            print(f"⚠️ API调用失败: {e}")
            return f"API调用失败: {str(e)}"
    
    # 云模型不可用时按固定阈值生成确定性本地报告。
    def _local_analysis(self, time_point: str, metrics: List[NetworkMetric]) -> str:
        """按固定阈值汇总每个接口，在无模型时生成可读但非语义推理的报告。"""
        print("📊 使用本地分析模式...")
        
        # 按接口分组
        interface_metrics = defaultdict(list)
        for metric in metrics:
            interface_metrics[metric.interface].append(metric)
        
        report = []
        report.append(f"🔍 {time_point} 时间点网络情况分析（本地分析）")
        report.append("=" * 60)
        
        # 分析每个接口
        for interface, iface_metrics in interface_metrics.items():
            report.append(f"\n📡 接口 {interface} 分析:")
            
            # 统计指标
            rtt_values = [m.rtt for m in iface_metrics if m.rtt is not None]
            tcp_loss_values = [m.tcp_loss_rate for m in iface_metrics if m.tcp_loss_rate is not None]
            traffic_values = [m.traffic_mbps for m in iface_metrics if m.traffic_mbps is not None]
            rssi_values = [m.rssi for m in iface_metrics if m.rssi is not None]
            
            if rtt_values:
                avg_rtt = sum(rtt_values) / len(rtt_values)
                status = "🟢 优秀" if avg_rtt <= 10 else "🟡 良好" if avg_rtt <= 30 else "🟠 一般" if avg_rtt <= 50 else "🔴 较差"
                report.append(f"  • RTT延迟: {avg_rtt:.1f}ms {status}")
            
            if tcp_loss_values:
                avg_loss = sum(tcp_loss_values) / len(tcp_loss_values)
                status = "🟢 优秀" if avg_loss <= 0.5 else "🟡 良好" if avg_loss <= 1 else "🟠 一般" if avg_loss <= 3 else "🔴 较差"
                report.append(f"  • TCP丢包率: {avg_loss:.2f}% {status}")
            
            if traffic_values:
                avg_traffic = sum(traffic_values) / len(traffic_values)
                status = "🟢 正常" if avg_traffic > 0 else "🔴 异常"
                report.append(f"  • 网络流量: {avg_traffic:.1f}MB/s {status}")
            
            if rssi_values:
                avg_rssi = sum(rssi_values) / len(rssi_values)
                status = "🟢 优秀" if avg_rssi >= -50 else "🟡 良好" if avg_rssi >= -60 else "🟠 一般" if avg_rssi >= -70 else "🔴 较差"
                report.append(f"  • WiFi信号: {avg_rssi:.0f}dBm {status}")
        
        # 整体评估
        report.append(f"\n📊 {time_point} 时间点整体评估:")
        
        all_rtt = [m.rtt for m in metrics if m.rtt is not None]
        all_tcp_loss = [m.tcp_loss_rate for m in metrics if m.tcp_loss_rate is not None]
        all_traffic = [m.traffic_mbps for m in metrics if m.traffic_mbps is not None]
        
        if all_rtt and all_tcp_loss and all_traffic:
            avg_rtt = sum(all_rtt) / len(all_rtt)
            avg_loss = sum(all_tcp_loss) / len(all_tcp_loss)
            avg_traffic = sum(all_traffic) / len(all_traffic)
            
            if avg_rtt <= 30 and avg_loss <= 1 and avg_traffic > 0:
                report.append("🟢 网络状况良好，各项指标正常")
            elif avg_rtt <= 50 and avg_loss <= 3:
                report.append("🟡 网络状况一般，部分指标需要关注")
            else:
                report.append("🔴 网络状况较差，需要立即处理")
        
        report.append(f"\n💡 建议措施:")
        report.append("1. 继续监控网络指标变化趋势")
        report.append("2. 如发现异常，及时检查网络设备和配置")
        report.append("3. 定期分析网络性能报告")
        
        return "\n".join(report)
    
    # 汇总全部可查询时间点及各自指标数。
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

# 使用样例数据演示最近时间匹配和云端/本地分析分支。
def main():
    """使用内置样例日志演示时间列表和多时间点分析。"""
    # 初始化RAG服务
    api_key = "YOUR_DASHSCOPE_API_KEY_HERE"  # 请替换为您的阿里百炼API密钥
    rag_service = OptimizedNetworkRAG(api_key)
    
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
    
    print("🚀 优化的网络RAG分析服务")
    print("=" * 60)
    
    # 显示可用时间点
    print("\n" + rag_service.get_available_times(sample_log_data))
    
    # 分析特定时间点
    time_points = ["00:13:24", "00:13:30", "00:13:50"]
    
    for time_point in time_points:
        print(f"\n{'='*60}")
        print(f"🔍 分析时间点: {time_point}")
        print('='*60)
        
        result = rag_service.analyze_time_point(sample_log_data, time_point)
        print(result)

if __name__ == "__main__":
    main()
