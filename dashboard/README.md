# WeakNet Observatory

Local dashboard for the gRPC version of AI-powered Network Diagnostics.

## What it does

- Reads WeakNet data through `proto/weaknet.proto`.
- Shows interfaces, network quality, event mix, event cadence and ping latency.
- Streams server events over a local WebSocket.
- Runs AI diagnosis from the dashboard server only. The browser never receives the API key.

## Start

Start the gRPC server first:

```bash
cd /path/to/JaNet
sudo bash -lc 'ulimit -l unlimited; WEAKNET_GRPC_ADDRESS=127.0.0.1:50051 ./server/bin/weaknet-grpc-server'
```

Install and run the dashboard:

```bash
cd /path/to/JaNet/dashboard
npm install
npm run dev
```

When the dashboard API starts, it asks:

```text
deepseek API key for dashboard AI (press Enter to skip):
```

Paste the key there for a one-off run. For normal use, put it in `dashboard/.env`
so restarts keep the key:

```bash
DEEPSEEK_API_KEY=sk-your-deepseek-key
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat
DEEPSEEK_THINKING=disabled
```

After editing `.env`, refresh the dashboard page. The dashboard API reloads this
file when status, snapshots or AI analysis are requested.

You can also avoid the prompt for just one command:

```bash
DEEPSEEK_API_KEY=sk-... npm run dev
```

Then open:

```text
http://127.0.0.1:5173
```

## Configuration

- `WEAKNET_GRPC_ADDRESS`: gRPC server address. Default `127.0.0.1:50051`.
- `DASHBOARD_WEB_PORT`: Vite web port. Default `5173`.
- `DASHBOARD_API_PORT`: dashboard API port. Default `5174`.
- `DASHBOARD_PING_TARGETS`: comma-separated default ping targets. Default `127.0.0.1,8.8.8.8,baidu.com`.
- `AI_PROVIDER`: optional provider override. Supported: `deepseek`, `dashscope`, `openai`. Default prefers DeepSeek.
- `DEEPSEEK_API_KEY`: DeepSeek API key for server-side analysis.
- `DEEPSEEK_BASE_URL`: DeepSeek OpenAI-compatible base URL. Default `https://api.deepseek.com`.
- `DEEPSEEK_MODEL`: model name. Default `deepseek-chat`.
- `DEEPSEEK_THINKING`: `disabled` or `enabled`. Default `disabled` for faster dashboard briefs.
- `DEEPSEEK_REASONING_EFFORT`: `high` or `max` when thinking is enabled. Default `high`.
- `DASHSCOPE_API_KEY`, `DASHSCOPE_BASE_URL`, `DASHSCOPE_MODEL`: optional DashScope fallback.
- `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL`: optional OpenAI-compatible fallback.
- `DASHBOARD_AI_PROMPT=0`: skip terminal API key prompt.
