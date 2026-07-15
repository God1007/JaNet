# JaNet Chrome 真实请求失败采集器

该目录是一份 Chrome Manifest V3 扩展。它通过 `chrome.webRequest` 旁路观察用户在 Chrome 中本来就会发生的 HTTP/HTTPS 请求，只把失败终态的最小元数据发送到本机 JaNet Dashboard BFF。

它不是主动 HTTP probe，不会为了监控去请求 GitHub、业务 API 或任意第三方地址；它也不接管、代理或修改浏览器请求。

## 安装

1. 使用 Chrome 120 或更高版本；先启动 JaNet，确认 Dashboard API 监听在默认的 `127.0.0.1:5174`，或记下自定义 `DASHBOARD_API_PORT`。macOS 可运行 `./run-mac.sh browser-monitor`，原生 Linux/WSL2 可运行 `./run-linux.sh browser-monitor` 来打印本目录路径并尝试打开扩展管理页。
2. 在 Chrome 打开 `chrome://extensions`。
3. 打开右上角 **Developer mode**。
4. 点击 **Load unpacked**。
5. 选择仓库中的 `browser-extension/` 目录，而不是仓库根目录。
6. 打开 JaNet Dashboard；页头的 Browser 状态会在扩展 heartbeat 或失败批次被 BFF 接收后变为已连接。

默认 endpoint 是：

```text
http://127.0.0.1:5174/api/browser-failures
```

如果修改了 Dashboard API 端口，在 `chrome://extensions` 找到扩展，进入 **Details → Extension options**，把 **Local ingest URL** 改成：

```text
http://127.0.0.1:<DASHBOARD_API_PORT>/api/browser-failures
```

Options 只接受 `http://127.0.0.1` 或 `http://localhost` 的本机地址，不能把采集数据配置到远端。Dashboard BFF 默认只监听 IPv4 loopback，因此不接受看似本机、实际无法连接当前 BFF 的 `http://[::1]`。

在 WSL2 部署中，BFF 运行在 WSL2，扩展通常运行在 Windows Chrome。此时必须确认 Windows 浏览器可以通过 WSL2 localhost forwarding 访问 `http://127.0.0.1:5174`，而且转发后的连接仍被 BFF 识别为 loopback；某些环境可能在前者可达时仍因后者不成立而返回 403。如果 localhost forwarding 被关闭或安全校验不通过，本扩展不会接受 WSL 虚拟网卡 IP 作为替代 endpoint，也不应通过绑定 `0.0.0.0` 或信任整个 WSL 子网绕过。`browser-monitor` 会尽量打印 Windows 可见的扩展目录，例如 `\\wsl.localhost\<发行版>\home\<用户>\JaNet\browser-extension`；无法调起 Windows Chrome 时，手动在 Windows Chrome 打开 `chrome://extensions` 并选择该目录。

## HTTP 状态码与浏览器错误

“网络请求”是一个总称，并不存在跨 DNS、TCP、TLS、HTTP 的统一状态码。HTTP status code 属于应用层 HTTP 响应；只有真正收到 HTTP 响应时才存在。“网络请求失败”因此包含两种不同证据：

| 终态 | 是否有 HTTP status code | 本扩展记录 |
| --- | --- | --- |
| HTTP 或 HTTPS 收到 4xx/5xx 响应 | 有，例如 404、429、500 | `statusCode` 与派生的 `HTTP_<code>` |
| DNS、TCP、TLS 等阶段在响应前失败 | 没有 | Chrome `net::ERR_*` 终态错误 |

HTTP 与 HTTPS 都使用 HTTP 状态码。HTTPS 的区别是 HTTP 交换在线路上经过 TLS 保护；Chrome 自己完成协议处理后，可以通过扩展 API 暴露最终 `statusCode` 元数据。扩展没有解密网络数据，也不读取报文内容。

成功的 2xx/3xx 不进入队列，因此 Dashboard 展示的是**失败计数与失败告警**，不是“总请求数”或带成功分母的失败率。

WebSocket 只覆盖连接建立阶段的 HTTP Upgrade 失败或同期浏览器网络错误。Upgrade 成功后，WebSocket 帧和最终 close code 不属于 `webRequest` 终态，本扩展不会采集。Chrome 之外的 curl、原生客户端和其他进程也不在该扩展的应用层状态码范围内；JaNet Linux Engine 对这些流量仍按自身 L3/L4 能力观测。

## 数据最小化

扩展会上报：

- 发生时间、请求方法和 Chrome resource type；
- `http` / `https`、host 与 port；`safeUrl` 只保留 origin，并固定为根路径 `/`；
- Chrome 能提供时的服务端 IP；
- 4xx/5xx 状态码，或无 HTTP 响应时的 `net::ERR_*`；
- cache flag、稳定事件 ID 与浏览器会话 ID。

扩展不采集：

- request/response body；
- Cookie、Authorization 或其他请求/响应 header；
- pathname、query string、fragment、URL username/password；
- 页面 DOM、输入内容或成功响应内容。

URL 会先在扩展内删除 credential、pathname、query 和 fragment，只生成 `scheme://host[:port]/`。pathname 也可能包含用户 ID、文件名或业务主键，因此默认不上传；BFF 收到后会再次强制执行同样的 origin-only 清理，以兼容旧版或被篡改的扩展输入。

## 本机接入与可选配对

`POST /api/browser-failures` 默认同时要求：

- TCP 对端是 loopback；
- `Origin` 是格式合法的 `chrome-extension://<32-char-id>`。

本地 unpacked 演示不需要预先配置 extension ID 或 token。需要收紧到当前扩展实例时，在 `dashboard/.env` 增加：

```bash
DASHBOARD_BROWSER_EXTENSION_ID=<chrome-extension-id>
DASHBOARD_BROWSER_EXTENSION_TOKEN=<random-local-token>
```

Extension ID 可在 `chrome://extensions` 或 Options 页底部查看。再把同一 token 填入 Options 的 **Pairing token**。ID 和 token 是可选加固，不会取代 loopback 与合法 extension Origin 两项基础检查。

## 有界队列与重试

- MV3 service worker 可能随时休眠，待发送失败保存在 `chrome.storage.local`。
- 队列最多 1,000 条，超过时淘汰最旧记录并累计 dropped 数。
- 待发送事件 TTL 固定为 5 分钟，与 BFF 默认告警窗口一致；刚好 5 分钟仍可发送，超过后在本地丢弃并计入 dropped，避免离线或休眠积压在恢复时伪装成当前突发。
- 每批最多发送 100 条，同一时刻只运行一个 flush。
- heartbeat 与失败批次上报都设置约 5 秒硬超时；悬挂请求会被 abort，释放单飞 flush 后进入后续重试。
- BFF 不可用时保留原事件并做指数退避，最长退避 5 分钟。
- `chrome.alarms` 每 30 秒提供 service worker 被回收后的重试入口。
- 扩展每分钟最多发送一次不含浏览记录的 heartbeat，用于区分“在线但没有失败”和“扩展未连接”；任一成功失败批次本身也会刷新 BFF 的 `lastContactAt` 并证明扩展近期在线。
- 上报 endpoint 本身会被排除，避免 BFF 离线时形成递归失败循环。
- Options 保存后会立即唤醒 worker 使用新配置刷新；关闭 Enabled 会清空旧队列，页面明确提示是否已确认清理。

BFF 默认保留最近 500 条失败，并按 `host + failureCode` 聚合。相同组合在 300 秒内累计 5 次时触发告警；服务端再次用有界的 `occurredAt` 判断窗口，过期 backlog 可留在 recent 诊断列表，但不具备单事件告警资格。缺失、远未来或远过去的客户端时间会被钳制且不参与告警，不能借客户端时间操纵当前窗口。配置入口见 `dashboard/.env.example`。

## 源码与测试

| 文件 | 作用 |
| --- | --- |
| `manifest.json` | MV3 权限、host permissions 与 service worker 入口 |
| `service_worker.js` | 注册终态监听、持久化、heartbeat、批量发送与重试 |
| `lib/failure_event.mjs` | 请求终态筛选、URL 脱敏与 ingest 地址约束 |
| `lib/fetch_with_timeout.mjs` | heartbeat / failure fetch 的 5 秒硬超时与 abort |
| `lib/persistent_queue.mjs` | 有界队列、5 分钟 TTL、ACK 和退避状态机 |
| `lib/settings_update.mjs` | Options 保存后的刷新/清队列分支 |
| `options.html` / `options.js` | 开关、本机 endpoint 与可选 token 配置 |
| `tests/*.test.mjs` | 脱敏、失败分类、队列边界与重试测试 |

无需启动 Chrome 即可运行纯逻辑测试：

```bash
node --test browser-extension/tests/*.test.mjs
```

## Chrome 官方资料

- [`chrome.webRequest`](https://developer.chrome.com/docs/extensions/reference/api/webRequest)：HTTP/HTTPS 请求生命周期、`onCompleted`、`onErrorOccurred`、`statusCode` 与 `ip`。
- [`chrome.storage`](https://developer.chrome.com/docs/extensions/reference/api/storage/)：MV3 service worker 可用的持久化状态。
- [`chrome.alarms`](https://developer.chrome.com/docs/extensions/reference/api/alarms)：service worker 休眠后的周期唤醒与重试调度。
