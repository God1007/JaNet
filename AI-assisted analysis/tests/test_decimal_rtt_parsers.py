#!/usr/bin/env python3
"""Regression tests for decimal RTT values flowing through every legacy log analyzer."""

import importlib.util
import sys
import unittest
from pathlib import Path


ANALYSIS_DIR = Path(__file__).resolve().parents[1]
if str(ANALYSIS_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYSIS_DIR))

PARSER_MODULES = (
    "simple_rag_analyzer.py",
    "vector_rag_analyzer.py",
    "true_rag_analyzer.py",
    "local_vector_rag_analyzer.py",
    "optimized_network_rag.py",
)


def load_module(file_name):
    """Load one analyzer by path so the test covers modules that are not packaged imports."""

    module_name = f"decimal_rtt_{Path(file_name).stem}"
    spec = importlib.util.spec_from_file_location(module_name, ANALYSIS_DIR / file_name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class DecimalRttParserTest(unittest.TestCase):
    """Ensure both dedicated RTT lines and interface summaries retain sub-millisecond values."""

    def test_all_analyzers_accept_decimal_rtt(self):
        log_text = "\n".join(
            (
                "🎯 [12:34:56] RTT监控: eth0 = 0.134ms (质量:1, 使用:YES, 目标:223.5.5.5)",
                "📋 [12:34:57] 接口汇总: eth0 = RTT:0.625ms, 质量:1, RSSI:-55dBm, TCP丢包:0.5%, 流量:2.5MB/s",
            )
        )

        for file_name in PARSER_MODULES:
            with self.subTest(module=file_name):
                parser = load_module(file_name).LogCaptureParser()
                metrics = parser.parse_log_capture_output(log_text)
                self.assertEqual([metric.rtt for metric in metrics], [0.134, 0.625])


if __name__ == "__main__":
    unittest.main()
