// 端到端契约测试：fake gRPC typed snapshot -> Dashboard BFF -> Python RAG bridge -> /api/analyze。
// HTTP 200/schema 合法、业务 degraded 和 bridge fallback 是三层不同结论：本测试要求首个
// 在线诊断非降级，第二个 route transition 可业务降级但仍有知识证据，不能混同规则 fallback。

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import grpc from "@grpc/grpc-js";
import protoLoader from "@grpc/proto-loader";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dashboardRoot = path.resolve(__dirname, "..");
const projectRoot = path.resolve(dashboardRoot, "..");
const protoPath = path.join(projectRoot, "proto", "weaknet.proto");

// 优先采用显式环境变量，否则从已发布 manifest/系统 PATH 选择带 jsonschema 的 Python；
// 返回可执行路径，确保子进程实际具备完整 bridge 构建依赖。
function resolveRagPython() {
  const candidates = [process.env.WEAKNET_RAG_PYTHON, process.env.PYTHON];
  try {
    const artifactRoot = path.join(projectRoot, "AI-assisted analysis", "knowledge", "artifacts");
    const pointer = JSON.parse(fs.readFileSync(path.join(artifactRoot, "current.json"), "utf8"));
    const manifest = JSON.parse(fs.readFileSync(
      path.join(artifactRoot, "versions", pointer.artifact_version, "manifest.json"),
      "utf8"
    ));
    candidates.push(manifest?.build?.python_executable);
  } catch {
    // Clean checkouts may have no published local artifact; use configured Python or PATH.
  }
  candidates.push("python3");
  for (const candidate of candidates.filter(Boolean)) {
    const probe = spawnSync(candidate, ["-c", "import jsonschema"], { stdio: "ignore" });
    if (!probe.error && probe.status === 0) return candidate;
  }
  throw new Error("No Python interpreter with jsonschema is available for the RAG integration test");
}

// 让内核分配临时 loopback 端口，关闭占位 listener 后返回端口供 Dashboard 绑定。
function reservePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => resolve(address.port));
    });
  });
}

// 将 grpc-js callback 风格 bindAsync 包装成 Promise；返回实际绑定端口供 BFF 连接。
function bindGrpc(server, address) {
  return new Promise((resolve, reject) => {
    server.bindAsync(address, grpc.ServerCredentials.createInsecure(), (error, port) => {
      if (error) reject(error);
      else resolve(port);
    });
  });
}

// 轮询 Dashboard 健康端点直到 HTTP ready；子进程提前退出时附带 stderr 立即失败。
async function waitForHttp(url, child, diagnostics) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (child.exitCode !== null) {
      throw new Error(`Dashboard exited early (${child.exitCode}): ${diagnostics()}`);
    }
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // 服务仍在启动，短暂等待后重试。
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Dashboard did not become ready: ${diagnostics()}`);
}

// 用真实 BFF/Python bridge 和 fake gRPC 完成一次 online 链路，锁定单快照与诊断业务语义。
test("analyze uses one typed snapshot and returns the unified RAG contract", { timeout: 30000 }, async () => {
  // 每次测试复制独立 raw/schema/golden 并发布临时 artifact，避免污染开发者本地 current。
  const temporaryKnowledge = fs.mkdtempSync(path.join(os.tmpdir(), "weaknet-rag-e2e-"));
  const rawPath = path.join(temporaryKnowledge, "raw.json");
  const schemaPath = path.join(temporaryKnowledge, "schema.json");
  const goldenPath = path.join(temporaryKnowledge, "golden.json");
  const artifactRoot = path.join(temporaryKnowledge, "artifacts");
  fs.copyFileSync(
    path.join(projectRoot, "AI-assisted analysis", "knowledge", "raw", "network_knowledge.json"),
    rawPath
  );
  fs.copyFileSync(
    path.join(projectRoot, "AI-assisted analysis", "knowledge", "schema", "knowledge_entry.schema.json"),
    schemaPath
  );
  fs.copyFileSync(
    path.join(projectRoot, "AI-assisted analysis", "knowledge", "golden_set.json"),
    goldenPath
  );
  const definition = protoLoader.loadSync(protoPath, {
    keepCase: false,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true
  });
  const loaded = grpc.loadPackageDefinition(definition);
  const WeakNet = loaded.weaknet.v1.WeakNet;
  // 调用计数用于证明 BFF 只消费 typed GetNetworkSnapshot，没有回退到 legacy 拼装接口。
  const calls = { snapshot: 0, interfaces: 0, health: 0 };
  const grpcServer = new grpc.Server();
  grpcServer.addService(WeakNet.service, {
    get: (_call, callback) => callback(null, { message: "ready" }),
    getInterfaces: (_call, callback) => {
      calls.interfaces += 1;
      callback(null, { interfaces: ["legacy-should-not-be-called"] });
    },
    // 第一次返回高 RTT/重传，期望在线 RAG unhealthy；第二次返回默认路由切换，期望
    // 有知识证据的业务 degraded；第三次供 /api/snapshot 验证 typed 观测字段透传。
    getNetworkSnapshot: (_call, callback) => {
      calls.snapshot += 1;
      if (calls.snapshot === 2) {
        callback(null, {
          observedAtUnixMs: String(Date.now()),
          hasActiveInterface: true,
          activeInterface: "wlan0",
          previousActiveInterface: "eth0",
          currentDefaultRouteInterface: "wlan0",
          defaultRouteChanged: true,
          routeGeneration: "2",
          routeChangedAtUnixMs: String(Date.now()),
          interfaces: [
            {
              interfaceName: "wlan0",
              isDefaultRoute: true,
              interfaceType: "INTERFACE_TYPE_WIFI",
              state: "INTERFACE_STATE_UP",
              usingNow: true,
              rttMs: 20,
              rttAvailability: "METRIC_AVAILABILITY_AVAILABLE",
              rssiDbm: -50,
              rssiAvailability: "METRIC_AVAILABILITY_AVAILABLE",
              tcpRetransmissionRatePercent: 0,
              tcpRetransmissionAvailability: "METRIC_AVAILABILITY_AVAILABLE",
              trafficBytesPerSecond: "1000",
              trafficPacketsPerSecond: "10",
              activeFlows: 1,
              trafficAvailability: "METRIC_AVAILABILITY_AVAILABLE"
            }
          ],
          quality: {
            level: "NETWORK_QUALITY_LEVEL_GOOD",
            score: 90,
            issues: [],
            degraded: false,
            missingMetrics: []
          },
          trafficObservation: {
            availability: "METRIC_AVAILABILITY_AVAILABLE",
            valid: true,
            generation: "10",
            boundIfindex: 2,
            captureMode: "tc",
            captureComplete: true,
            captureCompleteness: "full",
            mapReadComplete: true,
            libbpfAvailable: true,
            bpfLoaded: true,
            ipv4Supported: true,
            ipv6Supported: true,
            bidirectional: true,
            udpInterfaceReliable: true
          }
        });
        return;
      }
      callback(null, {
        observedAtUnixMs: String(Date.now()),
        hasActiveInterface: true,
        activeInterface: "eth0",
        interfaces: [
          {
            interfaceName: "eth0",
            isDefaultRoute: true,
            interfaceType: "INTERFACE_TYPE_ETHERNET",
            state: "INTERFACE_STATE_UP",
            usingNow: true,
            // 第三次 snapshot 用亚毫秒 precise 值，验证 BFF 不会回退到 legacy 整数。
            rttMs: 260,
            rttMsPrecise: calls.snapshot === 3 ? 0.375 : 260.125,
            previousRttMs: 240,
            previousRttMsPrecise: calls.snapshot === 3 ? 0 : 240.125,
            rttAvailability: "METRIC_AVAILABILITY_AVAILABLE",
            linkQuality: "LINK_QUALITY_BAD",
            rssiDbm: -55,
            rssiAvailability: "METRIC_AVAILABILITY_AVAILABLE",
            tcpRetransmissionRatePercent: 3.2,
            tcpRetransmissionLevel: "poor",
            tcpRetransmissionAvailability: "METRIC_AVAILABILITY_AVAILABLE",
            trafficBytesPerSecond: "125000",
            trafficPacketsPerSecond: "800",
            activeFlows: 12,
            trafficAvailability: "METRIC_AVAILABILITY_AVAILABLE"
          }
        ],
        quality: {
          level: "NETWORK_QUALITY_LEVEL_POOR",
          score: 42,
          issues: ["High latency"],
          degraded: false,
          missingMetrics: []
        },
        trafficObservation: {
          availability: "METRIC_AVAILABILITY_AVAILABLE",
          valid: true,
          generation: "9",
          sampledAtUnixMs: String(Date.now()),
          boundIfindex: 2,
          captureMode: "tc",
          captureComplete: true,
          captureCompleteness: "full",
          mapReadComplete: true,
          degradedReason: "",
          libbpfAvailable: true,
          bpfLoaded: true,
          tcIngressAttached: true,
          tcEgressAttached: true,
          ipv4Supported: true,
          ipv6Supported: true,
          bidirectional: true,
          udpInterfaceReliable: true,
          mapObservability: {
            lruCapacity: "65536",
            protectedCapacity: "4096",
            lruEntries: "12",
            protectedEntries: "1",
            lruInsertAttempts: "33",
            lruInsertFailures: "2",
            protectedInsertAttempts: "4",
            protectedInsertFailures: "1",
            interfaceInsertAttempts: "50",
            eventDrops: "3",
            eventsEmitted: "7",
            userEventsTruncated: "5",
            readComplete: true,
            kernelCounters: ["1", "2", "3"]
          },
          recentEvents: [
            {
              type: "TRAFFIC_OBSERVATION_EVENT_TRAFFIC_ANOMALY",
              socketCookie: "18446744073709551614",
              flowKey: "tcp:eth0:test",
              description: "traffic exceeds threshold",
              generation: "9",
              anomalyType: "high_volume",
              severity: 0.8
            }
          ]
        }
      });
    },
    healthCheck: (_call, callback) => {
      calls.health += 1;
      callback(null, { details: "{\"legacy\":true}" });
    },
    ping: (call, callback) => callback(null, {
      success: true,
      result: `PING ${call.request.hostname}: 20ms`,
      error: "",
      latencyMs: 20,
      latencyMsPrecise: 0.25,
      interfaceName: "eth0"
    }),
    subscribeEvents: (call) => call.end()
  });

  // fake gRPC 位于测试进程；Dashboard 是独立 Node 子进程，后者再拉起真实 Python bridge。
  const grpcPort = await bindGrpc(grpcServer, "127.0.0.1:0");
  const apiPort = await reservePort();
  const child = spawn(process.execPath, [path.join(__dirname, "index.mjs")], {
    cwd: dashboardRoot,
    env: {
      ...process.env,
      DASHBOARD_API_PORT: String(apiPort),
      DASHBOARD_PING_TARGETS: "127.0.0.1",
      DASHBOARD_RAG_TIMEOUT_MS: "10000",
      WEAKNET_RAG_PYTHON: resolveRagPython(),
      RAG_RAW_PATH: rawPath,
      RAG_SCHEMA_PATH: schemaPath,
      RAG_GOLDEN_PATH: goldenPath,
      RAG_ARTIFACT_ROOT: artifactRoot,
      WEAKNET_GRPC_ADDRESS: `127.0.0.1:${grpcPort}`
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  // 只保留尾部日志，失败时既提供诊断信息又避免测试错误对象无限膨胀。
  const diagnostics = () => `${stdout}\n${stderr}`.slice(-8000);

  try {
    await waitForHttp(`http://127.0.0.1:${apiPort}/api/status`, child, diagnostics);
    // 首次请求显式覆盖检索参数，覆盖 gRPC→BFF→Python→统一 contract 的完整成功路径。
    const response = await fetch(`http://127.0.0.1:${apiPort}/api/analyze`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ top_k: 6, similarity_threshold: 0.05 })
    });
    const payload = await response.json();

    // HTTP/schema 成功不足以通过：还要求业务 unhealthy、degraded=false 和真实知识证据。
    assert.equal(response.status, 200, JSON.stringify(payload));
    assert.equal(payload.status, "unhealthy");
    assert.equal(payload.degraded, false, JSON.stringify(payload));
    assert.ok(payload.evidence.length > 0);
    assert.ok(payload.knowledge_entry_ids.length > 0);
    assert.ok(payload.confidence > 0);
    assert.ok(payload.actions.length > 0);
    assert.equal(payload.top_k, 6);
    assert.equal(payload.similarity_threshold, 0.05);
    // 第二次是合法业务 degraded（路由切换），但必须带知识 ID/evidence；这与
    // provider=typed-rule-fallback、空知识 ID 的 bridge fallback 有本质区别。
    const routeResponse = await fetch(`http://127.0.0.1:${apiPort}/api/analyze`, { method: "POST" });
    const routePayload = await routeResponse.json();
    assert.equal(routeResponse.status, 200, JSON.stringify(routePayload));
    assert.equal(routePayload.status, "degraded", JSON.stringify(routePayload));
    assert.equal(routePayload.degraded, true, JSON.stringify(routePayload));
    assert.ok(
      routePayload.knowledge_entry_ids.includes("net.interface.default_route_switched"),
      JSON.stringify(routePayload)
    );
    assert.ok(routePayload.evidence.some((item) => item.kind === "route_transition"));
    // 最后验证 BFF 没有在 typed TrafficObservation 中截断 64-bit/counter/event 字段。
    const snapshotResponse = await fetch(`http://127.0.0.1:${apiPort}/api/snapshot`);
    const snapshotPayload = await snapshotResponse.json();
    const activeInterface = snapshotPayload.networkSnapshot.interfaces[0];
    assert.equal(activeInterface.rttMs, 0.375);
    assert.equal(activeInterface.previousRttMs, 0);
    assert.equal(snapshotPayload.health.parsed.rtt_ms, 0.375);
    assert.equal(snapshotPayload.pings[0].latencyMs, 0.25);
    assert.equal(snapshotPayload.latencySeries.at(-1).latencyMs, 0.25);
    const observation = snapshotPayload.networkSnapshot.trafficObservation;
    assert.equal(observation.captureComplete, true);
    assert.equal(observation.mapReadComplete, true);
    assert.equal(observation.mapObservability.lruInsertAttempts, 33);
    assert.equal(observation.mapObservability.userEventsTruncated, 5);
    assert.equal(observation.recentEvents[0].type, "TRAFFIC_ANOMALY");
    assert.equal(observation.recentEvents[0].socketCookie, "18446744073709551614");
    assert.equal(observation.recentEvents[0].generation, 9);
    assert.equal(calls.snapshot, 3);
    assert.equal(calls.interfaces, 0);
    assert.equal(calls.health, 0);
  } finally {
    // 无论断言是否失败都关闭 Node/gRPC 并删除临时制品，避免残留端口和 Python 子进程。
    child.kill("SIGTERM");
    await new Promise((resolve) => grpcServer.tryShutdown(resolve));
    fs.rmSync(temporaryKnowledge, { recursive: true, force: true });
  }
});
