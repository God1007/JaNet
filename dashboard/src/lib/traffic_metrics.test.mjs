// 流量展示纯函数单测：覆盖合法零值、单位缩放、历史窗口和重启边界。

import assert from "node:assert/strict";
import test from "node:test";

import {
  appendTrafficSample,
  capacityPercent,
  counterDelta,
  createTrafficSample,
  formatBytesPerSecond,
  formatCount,
  formatPacketsPerSecond,
  formatPercent
} from "./traffic_metrics.mjs";

function sample(generation, overrides = {}) {
  return {
    timestamp: generation * 1000,
    time: `t${generation}`,
    generation,
    interfaceName: "eth0",
    bytesPerSecond: 0,
    packetsPerSecond: 0,
    activeFlows: 0,
    packetsSeen: generation,
    eventDrops: 0,
    parseFailures: 0,
    continuityLost: 0,
    counterResets: 0,
    ...overrides
  };
}

function validNetworkSnapshot(overrides = {}) {
  const base = {
    observedAt: 1000,
    hasActiveInterface: true,
    activeInterface: "eth0",
    interfaces: [
      {
        interfaceName: "eth0",
        usingNow: true,
        trafficBytesPerSecond: 4096,
        trafficPacketsPerSecond: 40,
        activeFlows: 4,
        trafficAvailability: "AVAILABLE"
      }
    ],
    trafficObservation: {
      availability: "AVAILABLE",
      valid: true,
      baselineOnly: false,
      mapReadComplete: true,
      sampledAt: 2000,
      generation: 7,
      mapObservability: {
        readComplete: true,
        packetsSeen: 90,
        eventDrops: 1,
        parseFailures: 2,
        continuityLostThisWindow: 3,
        counterResetsThisWindow: 4
      }
    }
  };

  return {
    ...base,
    ...overrides,
    interfaces: overrides.interfaces ?? base.interfaces,
    trafficObservation: {
      ...base.trafficObservation,
      ...overrides.trafficObservation,
      mapObservability: {
        ...base.trafficObservation.mapObservability,
        ...overrides.trafficObservation?.mapObservability
      }
    }
  };
}

test("formats valid zero values and unavailable metrics separately", () => {
  assert.equal(formatBytesPerSecond(0), "0 B/s");
  assert.equal(formatPacketsPerSecond(0), "0 pkt/s");
  assert.equal(formatCount(0), "0");
  assert.equal(formatPercent(0), "0%");
  assert.equal(formatBytesPerSecond(null), "n/a");
  assert.equal(formatPacketsPerSecond(undefined, "unavailable"), "unavailable");
  assert.equal(formatCount(Number.NaN), "n/a");
});

test("uses binary byte units and decimal packet units", () => {
  assert.equal(formatBytesPerSecond(1536), "1.5 KiB/s");
  assert.equal(formatBytesPerSecond(1024 * 1024), "1 MiB/s");
  assert.equal(formatPacketsPerSecond(1500), "1.5 K pkt/s");
  assert.equal(formatPacketsPerSecond(1_000_000), "1 M pkt/s");
  assert.equal(formatCount(12_345), "12,345");
  assert.equal(formatPercent(12.34), "12.3%");
});

test("builds a sample from the interface marked as currently in use", () => {
  const trafficSample = createTrafficSample(validNetworkSnapshot({
    activeInterface: "eth0",
    interfaces: [
      {
        interfaceName: "fallback0",
        usingNow: false,
        trafficBytesPerSecond: 1,
        trafficPacketsPerSecond: 2,
        activeFlows: 3,
        trafficAvailability: "AVAILABLE"
      },
      {
        interfaceName: "eth0",
        usingNow: true,
        trafficBytesPerSecond: 4096,
        trafficPacketsPerSecond: 40,
        activeFlows: 4,
        trafficAvailability: "AVAILABLE"
      }
    ]
  }));

  assert.equal(trafficSample.interfaceName, "eth0");
  assert.equal(trafficSample.timestamp, 2000);
  assert.equal(trafficSample.bytesPerSecond, 4096);
  assert.equal(trafficSample.packetsSeen, 90);
});

test("preserves a complete observation whose rates and counters are valid zero", () => {
  const trafficSample = createTrafficSample(validNetworkSnapshot({
    interfaces: [{
      interfaceName: "eth0",
      usingNow: true,
      trafficBytesPerSecond: 0,
      trafficPacketsPerSecond: 0,
      activeFlows: 0,
      trafficAvailability: "AVAILABLE"
    }],
    trafficObservation: {
      mapObservability: {
        packetsSeen: 0,
        eventDrops: 0,
        parseFailures: 0,
        continuityLostThisWindow: 0,
        counterResetsThisWindow: 0
      }
    }
  }));

  assert.equal(trafficSample.bytesPerSecond, 0);
  assert.equal(trafficSample.packetsPerSecond, 0);
  assert.equal(trafficSample.activeFlows, 0);
  assert.equal(trafficSample.packetsSeen, 0);
});

test("rejects snapshots without a resolvable active interface", () => {
  assert.equal(createTrafficSample(validNetworkSnapshot({ hasActiveInterface: false })), null);
  assert.equal(createTrafficSample(validNetworkSnapshot({
    activeInterface: "missing0",
    interfaces: [{
      interfaceName: "eth9",
      usingNow: false,
      trafficBytesPerSecond: 10,
      trafficPacketsPerSecond: 1,
      activeFlows: 1,
      trafficAvailability: "AVAILABLE"
    }]
  })), null);
});

test("rejects unavailable, invalid, or baseline-only observations", () => {
  assert.equal(createTrafficSample(validNetworkSnapshot({
    trafficObservation: { availability: "UNAVAILABLE" }
  })), null);
  assert.equal(createTrafficSample(validNetworkSnapshot({
    trafficObservation: { valid: false }
  })), null);
  assert.equal(createTrafficSample(validNetworkSnapshot({
    trafficObservation: { baselineOnly: true }
  })), null);
  assert.equal(createTrafficSample(validNetworkSnapshot({
    interfaces: [{
      interfaceName: "eth0",
      usingNow: true,
      trafficBytesPerSecond: null,
      trafficPacketsPerSecond: null,
      activeFlows: null,
      trafficAvailability: "UNAVAILABLE"
    }]
  })), null);
});

test("rejects partial Map reads instead of presenting their zeros as healthy", () => {
  assert.equal(createTrafficSample(validNetworkSnapshot({
    trafficObservation: { mapReadComplete: false }
  })), null);
  assert.equal(createTrafficSample(validNetworkSnapshot({
    trafficObservation: { mapObservability: { readComplete: false } }
  })), null);
});

test("keeps a bounded immutable history and replaces the same generation", () => {
  const first = [sample(1), sample(2)];
  const replaced = appendTrafficSample(first, sample(2, { bytesPerSecond: 99 }), 3);
  assert.equal(first[1].bytesPerSecond, 0);
  assert.equal(replaced.length, 2);
  assert.equal(replaced[1].bytesPerSecond, 99);

  const bounded = appendTrafficSample(replaced, sample(3), 2);
  assert.deepEqual(bounded.map((item) => item.generation), [2, 3]);
});

test("clears history when generation moves backwards after a service restart", () => {
  const restarted = appendTrafficSample([sample(41), sample(42)], sample(1));
  assert.deepEqual(restarted.map((item) => item.generation), [1]);
});

test("returns null for a reset counter and computes monotonic deltas", () => {
  assert.equal(counterDelta(120, 100), 20);
  assert.equal(counterDelta(0, 0), 0);
  assert.equal(counterDelta(3, 9), null);
  assert.equal(counterDelta(null, 9), null);
});

test("calculates defensive capacity percentages", () => {
  assert.equal(capacityPercent(25, 100), 25);
  assert.equal(capacityPercent(150, 100), 100);
  assert.equal(capacityPercent(0, 0), null);
  assert.equal(capacityPercent(null, 100), null);
});
