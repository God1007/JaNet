# WeakNet Observatory

Local dashboard for the gRPC version of AI-powered Network Diagnostics.

## What it does

- Reads WeakNet data through `proto/weaknet.proto`.
- Shows interfaces, network quality, event mix, event cadence and ping latency.
- Streams server events over a local WebSocket.
- Quantifies the Linux Engine and Node BFF process footprint, with browser-local CPU/RSS trends capped at five hours and 1,801 points.
- Gives every trend chart an expanded analysis view with 30-minute, 1-hour and 5-hour ranges, shared series controls and exact timestamp tooltips.
- Aggregates failures from the optional Chrome MV3 collector by host and failure code, then exposes sliding-window alerts and filters.
- Runs AI diagnosis from the dashboard server only. The browser never receives the API key.

## Start

### One-command platform entrypoints

Run the commands from the repository root. `start` launches the stack without opening a browser; `dashboard` performs a health check and opens the page separately.

macOS runs the C++ Engine in Lima and the Dashboard on the host:

```bash
./run-mac.sh setup
./run-mac.sh start
./run-mac.sh dashboard
```

Native Linux and Windows WSL2 use the same Linux runner:

```bash
nvm install 22                 # Skip when Node 20.19+ / 22.12+ is ready
./run-linux.sh setup --install-deps
./run-linux.sh start
./run-linux.sh dashboard
```

`--install-deps` installs the Ubuntu/Debian system packages but deliberately does not run a third-party Node bootstrap script. A compatible Node version is therefore an explicit Dashboard prerequisite; use `--no-dashboard` for an Engine-only deployment.

On WSL2, `dashboard` tries `wslview` or another available opener to launch the Windows browser. If none is installed, open the printed `http://127.0.0.1:5173` URL manually in Windows. This requires WSL2 localhost forwarding. WSL1 is not supported. The Engine still observes the WSL2 Linux network stack, not all Windows host traffic, and `wsl --shutdown` terminates the whole stack rather than preserving it as a Windows service.

Both runners expose the aligned `setup`, `start`, `dashboard`, `browser-monitor`, `stop`, `restart`, `status`, `logs`, `follow`, `test`, `demo`, `intro` and `help` commands. Linux `setup` only installs apt packages when `--install-deps` is explicit; `start --rebuild` forces a clean build. The first Linux/WSL2 release keeps `demo` as an explain-only contract because loopback traffic does not cross the monitored default egress TC. See the root [README](../README.md#快速开始) for the full command table and platform capability boundaries.

### Manual start

If the Engine is already built, start the gRPC server first:

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

## Optional Chrome failure collector

This collector observes failures from the HTTP and HTTPS requests the user already makes in Chrome. It is not an active HTTP probe and does not create requests to GitHub or any other monitored host.

1. Start the Dashboard BFF. From the repository root, `./run-mac.sh browser-monitor` on macOS or `./run-linux.sh browser-monitor` on Linux/WSL2 prints the setup path and tries to open the extension page.
2. Open `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked** and select the repository's `browser-extension/` directory.
5. Leave the default endpoint `http://127.0.0.1:5174/api/browser-failures`, or open **Details → Extension options** and change it when `DASHBOARD_API_PORT` is customized.

By default, ingestion requires both a loopback client and a syntactically valid `chrome-extension://` Origin. `DASHBOARD_BROWSER_EXTENSION_ID` and `DASHBOARD_BROWSER_EXTENSION_TOKEN` are optional pairing hardening: copy the ID shown on `chrome://extensions`, configure the same token in Extension options, and restart or refresh the BFF configuration. When Windows Chrome is paired with a BFF inside WSL2, verify that `http://127.0.0.1:5174` reaches WSL through localhost forwarding **and** is still seen as loopback by the BFF. Some forwarding configurations can fail the latter check with HTTP 403. The extension intentionally refuses non-loopback WSL IP endpoints; do not work around this by binding the BFF to `0.0.0.0` or trusting the whole WSL subnet.

The extension sends a metadata-free heartbeat at most once per minute. Either a successful heartbeat or a successfully ingested failure batch refreshes `lastContactAt`; `connectedRecent` is derived from that latest contact rather than requiring a heartbeat immediately after a real failure.

Both HTTP and HTTPS responses have HTTP status codes. HTTPS protects the exchange with TLS, while Chrome can still expose the final response metadata to its extension API. A DNS lookup, TCP connection, or TLS handshake can fail before any HTTP response exists; those terminal events carry a Chrome `net::ERR_*` error instead of an HTTP status. The collector sends only 4xx/5xx response terminals and browser network-error terminals.

The extension does not proxy traffic, perform MITM decryption, or collect request/response bodies, cookies, authorization headers, pathnames, query strings, fragments, or URL credentials. It keeps the scheme, host, port, method, resource type, server IP when Chrome provides one, cache flag, status/error and timestamps; `safeUrl` is always reduced to `scheme://host[:port]/`, and the BFF enforces that reduction again. WebSocket coverage ends at the HTTP Upgrade attempt: an upgrade failure can be visible, but a close code after a successful connection is not. Application-layer status from non-browser processes is outside this extension's scope.

See [the collector guide](../browser-extension/README.md), the official [Chrome `webRequest` API](https://developer.chrome.com/docs/extensions/reference/api/webRequest), [Chrome storage API](https://developer.chrome.com/docs/extensions/reference/api/storage/) and [Chrome alarms API](https://developer.chrome.com/docs/extensions/reference/api/alarms).

## HTTP API boundaries

| Endpoint | Payload |
| --- | --- |
| `GET /api/snapshot` | Network snapshot, Ping results, recent events, `runtimeResources` and browser request-failure snapshot |
| `GET /api/status` | BFF/gRPC stream state, AI configuration, in-memory limits and a compact browser collector connection summary; it does not return `runtimeResources` |
| `POST /api/browser-failures` | Loopback-only Chrome extension heartbeat or bounded failure batch |
| `POST /api/ping` | Explicit ICMP Ping request |
| `POST /api/analyze` | Diagnosis over a fresh typed network snapshot |

## Configuration

- `WEAKNET_GRPC_ADDRESS`: gRPC server address. Default `127.0.0.1:50051`.
- `DASHBOARD_WEB_PORT`: Vite web port. Default `5173`.
- `DASHBOARD_API_PORT`: dashboard API port. Default `5174`.
- `DASHBOARD_PING_TARGETS`: comma-separated default ping targets. Default `127.0.0.1,8.8.8.8,baidu.com`.
- `DASHBOARD_ANALYZE_MAX_CONCURRENCY`: maximum concurrent `/api/analyze` requests. Default `2`; overflow returns HTTP 429 instead of queuing.
- `DASHBOARD_WS_MAX_CONNECTIONS`: maximum dashboard WebSocket connections. Default `32`.
- `DASHBOARD_WS_MAX_BUFFERED_BYTES`: maximum queued outbound bytes per WebSocket before a slow client is disconnected. Default `262144` (256 KiB).
- `DASHBOARD_REQUEST_FAILURE_WINDOW_SEC`: host + failure-code sliding alert window in seconds. Default `300`.
- `DASHBOARD_REQUEST_FAILURE_THRESHOLD`: matching failures required in the window before an alert fires. Default `5`.
- `DASHBOARD_REQUEST_FAILURE_MAX_RECENT`: maximum recent browser failures retained by the BFF. Default `500`.
- `DASHBOARD_BROWSER_EXTENSION_ID`: optional exact Chrome extension ID allowlist. Empty by default.
- `DASHBOARD_BROWSER_EXTENSION_TOKEN`: optional shared pairing token; configure the same value in Extension options. Empty by default.
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
| Live traffic | Five-hour TTL plus `1,801` trusted-generation cap; the normal 10-second cadence can cover the full window | Browser page reload or close |
| Runtime CPU/RSS trends | Five-hour TTL plus `1,801` shared page samples for Engine and BFF | Browser page reload or close |
| Events | Raw BFF events use a five-hour TTL and `300`-row cap; cadence returns continuous minute buckets so idle gaps remain visible; the UI event list remains `120` rows and WebSocket hello sends `30` | Dashboard BFF restart |
| Ping probes | BFF seeds the page with at most `240` rows; the browser merges target + timestamp increments into a five-hour TTL window with a `9,005`-row fail-safe | Browser page reload or close; BFF seed resets on BFF restart |
| Browser failures | BFF keeps latest `500`; alert groups use a 300-second host + failure-code window by default | Dashboard BFF restart |
| Extension retry queue | Latest `1,000` failures in `chrome.storage.local`, sent in batches of at most `100` with bounded backoff | Extension storage reset/removal |

All five trend charts use numeric timestamps and never display data older than five hours. Traffic, CPU, memory and Probe use browser-local history; Events per minute is built from BFF event evidence. Expanded charts can narrow the visible range without changing retention.

Day- or month-scale history must be exported to a time-series database. Preserve
timestamps, generation and availability/validity fields, control high-cardinality
labels, and serve retention-aware minute/hour downsampling. Increasing frontend
arrays or BFF caches is not a persistence design.

## Runtime resource semantics

The Engine and BFF are always different processes, but the operating-system boundary depends on deployment:

- `engine` is the C++ process in the active Linux runtime: native Linux, WSL2 Linux, or Lima Linux. `ProcessResourceSampler` writes `engine_resources` and `unavailable_metrics` into the protobuf snapshot.
- `dashboard` is the Node.js BFF. It runs in the same Linux environment on native Linux/WSL2, and on the macOS host when Lima is used. It samples its own process and combines the two normalized records under `runtimeResources` in `/api/snapshot`.
- CPU uses the process-CPU convention where one fully busy logical core is `100%`; multi-threaded work can exceed `100%`.
- RSS, thread count and open file descriptors are current point-in-time values. User/system CPU time and voluntary/involuntary context switches are cumulative since process start.
- `combinedResidentMemoryBytes` is present only when both Engine RSS and BFF RSS are valid. A partial sample is never presented as the whole JaNet footprint.
- On Linux, BFF thread count comes from `/proc/self/status`. On macOS, it is refreshed asynchronously through a low-frequency `ps -M` query (at most once per minute); snapshot assembly reads the latest completed value and marks it unavailable before the first refresh completes.
