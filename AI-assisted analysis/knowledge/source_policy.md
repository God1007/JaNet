# WeakNet diagnostic knowledge source policy

This file is the human-reviewed authority for deterministic diagnostic thresholds and actions.
Its whole-file SHA-256 is recorded as `source_revision`; each entry also pins a line range and excerpt SHA-256.

<!-- weaknet-anchor:net.rtt.high:start -->
claim: metric=rtt; threshold=gt 50 ms
condition: RTT 持续高于 50ms，交互延迟变得可感知
support: symptoms=[页面或交互响应变慢 | 实时音视频出现卡顿]; root_causes=[链路拥塞 | 路由绕行 | 无线干扰或弱信号]; actions=[对比网关与外部目标 RTT 以界定故障段 | 联合检查 RSSI、TCP 重传与流量突发]. semantic-sha256: condition=b5d3109aac160b1a0b082b37d8c1305a9dcf5d3d1f241b3c714b10ed71e6c3a6 symptoms=6381d1383fef05161ee7eaed88f012519dedbd89ea78661c51e8305f0b6313f5 root_causes=4b962b6e126ffd40a212c13e22d59f0c7b56aeff49f7836f443cb905bb844057 actions=c17d77d48a154fb50d80e2d7552f0cddbc71001228f1651ad431d695a7eb7a8a
<!-- weaknet-anchor:net.rtt.high:end -->

<!-- weaknet-anchor:net.rtt.critical:start -->
claim: metric=rtt; threshold=gt 100 ms
condition: RTT 高于 100ms，实时业务显著劣化
support: symptoms=[请求尾延迟显著升高 | 音视频或远程会话严重卡顿]; root_causes=[严重拥塞 | 跨地域路由异常 | 出口带宽被占满]; actions=[对多个目标执行分层 RTT 采样 | 对齐重传、队列和出口带宽时间窗]. semantic-sha256: condition=30e20b6b41862dbd86734fdc2caec4b6a475e5aa4d707b71a51546d27f2481e1 symptoms=2ff2003532e37fe1c9d2a416f75317efd9a1182aa2ee301c56be098d383af52b root_causes=75e3fb89b273a0c56513b825f1536efc875ba3c837f362429d457871aae1b7d2 actions=07c745e1f1b79c9989df1aac5accf90ebf0e9a5bd5c318d7bb3b5fde031f3527
<!-- weaknet-anchor:net.rtt.critical:end -->

<!-- weaknet-anchor:net.tcp.retransmission_elevated:start -->
claim: metric=tcp_retransmission_rate; threshold=ge 1 percent
condition: TCP 重传代理比率达到 1%，链路可能丢包或拥塞
support: symptoms=[TCP 有效吞吐下降 | 请求延迟和尾延迟升高]; root_causes=[链路丢包 | 队列拥塞 | WiFi 干扰]; actions=[将该值表述为重传代理而非精确丢包率 | 联合 RTT、RSSI 和接口错包计数验证]. semantic-sha256: condition=5fe1c03fd3c66df34f8d28c7f95c55eb5d26a9acb6a2bab30c842028935b23a9 symptoms=d64ec99e7e2976a65fbe8efef0a9426390e41da32886bc0f9d887b2900789e71 root_causes=35dfea9a34b34ef895d30a7935bfe9f29086a0652e6b2b6bd8b120cc9d2ffa13 actions=9279fe77471c2bf4424986dfcd4fd5be9e661018e231e37def253c7c90b9b3a1
<!-- weaknet-anchor:net.tcp.retransmission_elevated:end -->

<!-- weaknet-anchor:net.tcp.retransmission_critical:start -->
claim: metric=tcp_retransmission_rate; threshold=gt 3 percent
condition: TCP 重传代理比率高于 3%，传输质量严重恶化
support: symptoms=[大量重传占用带宽 | 连接超时或吞吐骤降]; root_causes=[持续丢包 | 网络设备或物理链路故障 | 严重拥塞]; actions=[按接口和目标拆分重传时序 | 检查网卡错包、交换机端口和队列丢包]. semantic-sha256: condition=67034c83d4f55f9046a1c34808c9d064e0a336399c76d5163f71db989b4eb1df symptoms=58c09fb67b408fef742f5644d4eeb11e1523a9e427f2e259c08b4a0554969081 root_causes=2dc8dd2b4f81bfe0755a4e79dc68efd3a64a208384ee677208847bf995092731 actions=00fc93e9e65bc1e0675179dd0682903be017a324d38b7a1282f738e62459568d
<!-- weaknet-anchor:net.tcp.retransmission_critical:end -->

<!-- weaknet-anchor:net.traffic.zero:start -->
claim: metric=traffic; threshold=eq 0 MB/s
condition: 当前业务期待有网络活动但观测流量为零
support: symptoms=[流量曲线断流 | 活跃连接与字节计数不一致]; root_causes=[网络中断 | eBPF 程序未挂载 | 监控了错误接口]; actions=[校验当前上行接口 ifindex | 检查 eBPF 加载状态与 map 更新时间]. semantic-sha256: condition=e78afbf46b45bc33e8eea0adf30e1a9685da3f8a3f046ecee86cedd68f7ee40b symptoms=59ac7d973de9e9eb04c453ff54a08e541e7d9efd82248e187208ef913f87a70a root_causes=9bb3ed93ec97b810b82acabaf8a3220f82b51ccc3299f98e74f39452612b11fe actions=a9c4b0ed12925941ce26d2a5fb0336026ba2f9bbf5b57cf2373376e9ad6b00ac
<!-- weaknet-anchor:net.traffic.zero:end -->

<!-- weaknet-anchor:net.bandwidth.high_utilization:start -->
claim: metric=bandwidth_utilization; threshold=ge 80 percent
condition: 带宽利用率达到 80%，需关注排队和突发流量
support: symptoms=[时延随负载升高 | 突发期吞吐抖动]; root_causes=[出口容量不足 | 批量任务竞争带宽 | 限速策略不合理]; actions=[按构建任务或进程拆分流量 | 设置时间窗告警并核查限速策略]. semantic-sha256: condition=e000c13da386417b9e496734aa5eda741d43f51a8b4dd054bcc938f1302a26f7 symptoms=819e6cffc3679f558b3a94fd12dbf962b7f3a3121597941d19ac76cc867fbfb6 root_causes=0830363672cb1f6063e986600b92332f5d10912a4c3eaf78ac9feae57817f60e actions=2da5bf0d8183716a016be61f0dd2da9e9441e94db624a6f3626b28a0edcee863
<!-- weaknet-anchor:net.bandwidth.high_utilization:end -->

<!-- weaknet-anchor:net.wifi.rssi_weak:start -->
claim: metric=rssi; threshold=lt -70 dBm
condition: WiFi RSSI 低于 -70dBm，信号进入较差区间
support: symptoms=[无线链路速率下降 | 重传和时延波动增加]; root_causes=[距离过远 | 物理障碍 | 同频干扰]; actions=[靠近 AP 或调整 AP 位置 | 扫描信道干扰并核对天线与功率配置]. semantic-sha256: condition=24478549346bf60c6da49168a515fb975760b6d157c60a941f4a167f6b65350a symptoms=d41e8a4a05de2bbb9e691b1fb4c0bb64860f4c3d5a27823df7619b7bf39cb622 root_causes=7b5f073239c1d4a77279a90ae7a2c482e618000a44ad4d2c9d84cc257178dc83 actions=febadb4bc00c5acd112b6abc18ec4110ab3f7a18ff50ea440101fb007b94b1ea
<!-- weaknet-anchor:net.wifi.rssi_weak:end -->

<!-- weaknet-anchor:net.wifi.rssi_critical:start -->
claim: metric=rssi; threshold=lt -80 dBm
condition: WiFi RSSI 低于 -80dBm，无线连接可能断开
support: symptoms=[频繁掉线 | 吞吐趋近不可用]; root_causes=[严重衰减 | AP 故障或天线异常 | 强干扰]; actions=[立即验证其他 AP 或有线备用链路 | 检查 AP、天线与环境干扰源]. semantic-sha256: condition=e5d41f100d849fa9dfd3bcdb2f7513a1500fa61732809a65c24e54978b641408 symptoms=de8505278bc4fcf402266dc7a13294a056ae392807bc4278e3750327b7e55fae root_causes=d96a41e8d1f1c33f22c83b5f04d9f4b1b504b1cd08fc78068bdc7ae79595a3c5 actions=61bc916b1821e3cc9cc20c9c7ecc83eb06658a3d1b6e0865f24337a27b623574
<!-- weaknet-anchor:net.wifi.rssi_critical:end -->

<!-- weaknet-anchor:net.interface.down:start -->
claim: metric=interface_state; threshold=eq down state
condition: 当前上行网络接口状态为 down
support: symptoms=[该接口无法传输数据 | 默认路由可能不可用]; root_causes=[物理链路断开 | 驱动或设备故障 | 管理员禁用接口]; actions=[检查 carrier、operstate 和默认路由 | 检查物理连接、驱动日志与接口配置]. semantic-sha256: condition=1102577ad7c367874f170784446cd8d5475d3b0e556e26f17d334acbee676507 symptoms=0f852378cf94262980d5b988ca287274daf5aa7b2e8124a99f681b2448b0ea91 root_causes=f882d3cb594d9bf17a05b60abffa7004c11f7aec6357b4218bb7fc02a261848a actions=786bbdc88584116d7025607853ad7d57cde44ed0fc2bc4b6ccb9c40fd901f3bb
<!-- weaknet-anchor:net.interface.down:end -->

<!-- weaknet-anchor:net.ebpf.collector_unavailable:start -->
claim: metric=ebpf_available; threshold=eq false boolean
condition: eBPF 流量采集器不可用，流量与流级证据不能作为诊断依据
support: symptoms=[流量指标缺失或长期不变 | 诊断结果中缺少流级引用]; root_causes=[BPF 程序加载失败 | 内核或权限不兼容 | map 创建或 attach 失败]; actions=[检查 BPF load/attach 错误和内核 verifier 日志 | 将流量指标标记 unavailable，禁止用零值代替缺失值]. semantic-sha256: condition=e94b79d7bbb3df8c4a68bd3938f1c59b809591bd87f683f10e3a7aa18caab1e4 symptoms=2f05864392ad4ae2ce56218f7a2d12e159a3e5a76211a2067e37fd101a1b5ca5 root_causes=8b41c01aeb25ec4e222f5c0a64e7b3146082c1ba3fcb0627c544fbc27777134f actions=366d8b9b21fea6903df56b14a6442d9f0a98a927e9e1ecdda1f273c6928664c6
<!-- weaknet-anchor:net.ebpf.collector_unavailable:end -->

<!-- weaknet-anchor:net.interface.default_route_switched:start -->
claim: metric=default_route_changed; threshold=eq true boolean
condition: 多网卡环境中默认路由或当前上行接口发生切换
support: symptoms=[切换窗口内 RTT、RSSI 或流量短暂断层 | 旧接口指标被错归因到新上行]; root_causes=[WiFi/有线优先级变化 | VPN 或 DHCP 更新默认路由 | 接口拔插或 carrier 抖动]; actions=[用 ifindex 和路由世代号关联切换前后指标 | 切换后重绑流量采集并保留旧接口短时间历史]. semantic-sha256: condition=660d01102f95406ec26ddb885a95d8a514eb59ea49dae2d23d170a026f397654 symptoms=79545433538bcd28e059d1b91e53665b1fb0583e68a594b3d4f77c30daaac032 root_causes=728aa391f5bec509cc8e0acbb9303125c53be34cd6dc18da0786cd9a300e71c2 actions=97582e4379de29ba6094adac5854d41e185f860e28aaf4d6f09362f3b607f347
<!-- weaknet-anchor:net.interface.default_route_switched:end -->

<!-- weaknet-anchor:net.quality.poor:start -->
claim: metric=quality_score; threshold=lt 60 score
condition: 综合网络质量分低于 60
support: symptoms=[多个网络指标同时恶化 | 业务体验不稳定]; root_causes=[RTT、重传、RSSI 或流量异常共同影响 | 部分指标过期或缺失]; actions=[查看评分构成和每项指标时间戳 | 优先处理严重度最高且证据最新的异常]. semantic-sha256: condition=44df5e341144e80f0a36428f41b157cb0bf2adc6c19b8887a732271bfd680ebb symptoms=29f9284ac08937456b289e24d91bcc4b5d2542c8f6c5ca56fe2c7ca15df03de8 root_causes=216d80cf7b6934076d9bca1886e8c78acd82cbe396c9cb6fa548f951833a03dc actions=eacec6c2539ad009db0c7bcdc47c8741e8c1d31bd1f474188deacd48810d6d31
<!-- weaknet-anchor:net.quality.poor:end -->

<!-- weaknet-anchor:net.test.fixture:start -->
claim: metric=rtt; threshold=gt 50 ms
claim: metric=rtt; threshold=gt 80 ms
claim: metric=interface_state; threshold=eq bad unit
condition/support: alpha latency condition | beta candidate | beta unique collector condition; symptoms=[alpha observable symptom]; root_causes=[alpha verified root cause]; actions=[alpha remediation action | beta remediation action]. semantic-sha256: condition=4a4a028d4b605ca2af700773cf70261b70fa758e033151f70566931f5c46082d condition=eaaedfd963ed45bf4734c437ab3065005d49046ab9d7c0ee85ea841c500629da condition=b9c8d7f748a72ffef8818f6bf9a46b5c7754c00d2dafd4c8f313ce0dd38db30d symptoms=cba48855194b6f91a331fd0580573e182f145d9b5a2f323400853feb894309e1 root_causes=279680fd56ab22a50299b81a0095ce2969e6b66d1930b56fb54f1c29253bf38c actions=dc0c0e8e3bc057a7e36662aeb7daa1be35303157631fdf6b8807c26d39d7c392 actions=45f2c76328d99866428000710d1980501d1069379c30ea8e22c01ea50aa451a1
<!-- weaknet-anchor:net.test.fixture:end -->
