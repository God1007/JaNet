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
npm ci
npm run dev
```

Put the API configuration in `dashboard/.env` so restarts keep it:

```bash
DEEPSEEK_API_KEY=sk-your-deepseek-key
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat
DEEPSEEK_THINKING=disabled
```

After editing `.env`, refresh the dashboard page. The dashboard API reloads this
file when status, snapshots or AI analysis are requested. You can also configure
one command through environment variables:

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
- `DASHBOARD_ANALYZE_MAX_CONCURRENCY`: maximum concurrent `/api/analyze` requests. Default `2`; overflow returns HTTP 429 instead of queuing.
- `DASHBOARD_WS_MAX_CONNECTIONS`: maximum dashboard WebSocket connections. Default `32`.
- `DASHBOARD_WS_MAX_BUFFERED_BYTES`: maximum queued outbound bytes per WebSocket before a slow client is disconnected. Default `262144` (256 KiB).
- `AI_PROVIDER`: optional provider override. Supported: `deepseek`, `dashscope`, `openai`. Default prefers DeepSeek.
- `DEEPSEEK_API_KEY`: DeepSeek API key for server-side analysis.
- `DEEPSEEK_BASE_URL`: DeepSeek OpenAI-compatible base URL. Default `https://api.deepseek.com`.
- `DEEPSEEK_MODEL`: model name. Default `deepseek-chat`.
- `DEEPSEEK_THINKING`: `disabled` or `enabled`. Default `disabled` for faster dashboard briefs.
- `DEEPSEEK_REASONING_EFFORT`: `high` or `max` when thinking is enabled. Default `high`.
- `DASHSCOPE_API_KEY`, `DASHSCOPE_BASE_URL`, `DASHSCOPE_MODEL`: optional DashScope fallback.
- `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL`: optional OpenAI-compatible fallback.

## Runtime limits and history semantics

The dashboard is a bounded real-time view, not a historical database.

| Data | In-memory bound | Reset boundary |
| --- | --- | --- |
| Live traffic | Latest `72` trusted generations; at the default 10-second polling interval this is about 12 minutes | Browser page reload or close |
| Events | BFF keeps `300`; snapshot/UI consume the latest `120`; WebSocket hello sends `30` | Dashboard BFF restart |
| Ping probes | BFF keeps `240` across all targets and snapshot returns the latest `120` | Dashboard BFF restart |

Day- or month-scale history must be exported to a time-series database. Preserve
timestamps, generation and availability/validity fields, control high-cardinality
labels, and serve retention-aware minute/hour downsampling. Increasing frontend
arrays or BFF caches is not a persistence design.
