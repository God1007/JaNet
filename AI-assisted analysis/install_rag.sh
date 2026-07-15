#!/bin/bash
# 文件职责：安装 Python RAG 依赖，并可选创建隔离虚拟环境和示例配置。
# 该脚本会访问包仓库并在当前目录写入环境/配置文件，适合开发机初始化。

echo "🚀 安装WEAK_NET RAG系统依赖..."

# 先确认 python3 可执行，避免后续创建环境和安装依赖时产生难懂错误。
python3 --version
if [ $? -ne 0 ]; then
    echo "❌ Python3未安装，请先安装Python3"
    exit 1
fi

# 只有显式传入 --venv 才创建并激活虚拟环境，否则安装到调用者当前 Python 环境。
if [ "$1" = "--venv" ]; then
    echo "📦 创建虚拟环境..."
    python3 -m venv rag_env
    source rag_env/bin/activate
    echo "✅ 虚拟环境已激活"
fi

# 升级pip
echo "⬆️ 升级pip..."
python3 -m pip install --upgrade pip

# 安装依赖
echo "📚 安装Python依赖包..."
pip install -r requirements.txt

# 通过真实导入核心库验证安装结果，而不是只依赖 pip 的退出状态。
echo "🔍 检查安装状态..."
python3 -c "
import langchain
import openai
import faiss
print('✅ LangChain版本:', langchain.__version__)
print('✅ OpenAI版本:', openai.__version__)
print('✅ FAISS版本:', faiss.__version__)
print('✅ 所有依赖安装成功!')
"

# 写入可编辑的示例配置；重复运行会覆盖当前目录下同名 config.json。
echo "📝 创建配置文件..."
cat > config.json << EOF
{
    "openai_api_key": "YOUR_DASHSCOPE_API_KEY_HERE",
    "log_capture_duration": 300,
    "vector_store_path": "./vector_store",
    "knowledge_base_path": "./network_knowledge_base.py"
}
EOF

echo "✅ RAG系统安装完成!"
echo ""
echo "📖 使用方法:"
echo "1. 交互模式: python3 network_diagnosis_tool.py"
echo "2. 命令行模式: python3 network_diagnosis_tool.py capture 300"
echo "3. 分析模式: python3 network_diagnosis_tool.py analyze 00:13:24 00:13:34"
echo ""
echo "🔧 注意事项:"
echo "- 确保weaknet-grpc-server正在运行"
echo "- 确保有网络连接以访问OpenAI API"
echo "- 首次运行可能需要下载模型，请耐心等待"
