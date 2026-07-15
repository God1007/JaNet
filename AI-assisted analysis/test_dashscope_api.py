#!/usr/bin/env python3
"""
文件职责：用最小对话请求验证阿里百炼 OpenAI 兼容接口、模型名称和 API Key 是否可用。
它是人工连通性脚本，不属于正式诊断链路。
"""

import os
from openai import OpenAI

# 用最小 chat completion 请求验证 DashScope Key、网络和模型配置。
def test_dashscope_api():
    """初始化客户端并发送一次固定请求，以布尔值表示端到端调用是否成功。"""
    try:
        # 设置API密钥
        api_key = "YOUR_DASHSCOPE_API_KEY_HERE"  # 请替换为您的阿里百炼API密钥
        os.environ["DASHSCOPE_API_KEY"] = api_key
        
        # 按照官方文档初始化客户端
        client = OpenAI(
            api_key=os.getenv("DASHSCOPE_API_KEY"),
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        )
        
        print("✅ 阿里百炼客户端初始化成功")
        
        # 测试简单调用
        print("🔄 测试API调用...")
        completion = client.chat.completions.create(
            model="qwen-plus",
            messages=[
                {"role": "system", "content": "你是一个专业的网络问题诊断专家。"},
                {"role": "user", "content": "请简单分析一下RTT延迟15ms的网络状况。"}
            ],
            extra_body={"enable_thinking": False}
        )
        
        result = completion.choices[0].message.content
        print("✅ API调用成功!")
        print(f"📋 返回结果:\n{result}")
        
        return True
        
    # 统一报告鉴权、网络或响应解析异常，并用布尔值通知脚本退出码分支。
    except Exception as e:
        print(f"❌ API调用失败: {e}")
        return False

if __name__ == "__main__":
    # 直接运行时打印人类可读的测试结果；导入模块时不会自动发起网络请求。
    print("🧪 阿里百炼API测试")
    print("=" * 40)
    
    success = test_dashscope_api()
    
    if success:
        print("\n🎉 API测试成功，可以正常使用!")
    else:
        print("\n❌ API测试失败，请检查配置")
