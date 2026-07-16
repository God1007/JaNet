// Node 内建测试：锁定 Dashboard 长时运行所需的并发、资源退休和 WebSocket 背压边界。

import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";
import {
  admitWebSocketConnection,
  boundedInteger,
  createCachedSingleFlight,
  createConcurrencyGate,
  createRetiringResourceTracker,
  sendWebSocketMessage
} from "./resource_guards.mjs";

test("boundedInteger rejects invalid config and clamps valid values", () => {
  assert.equal(boundedInteger(undefined, 2, { min: 1, max: 8 }), 2);
  assert.equal(boundedInteger("", 2, { min: 1, max: 8 }), 2);
  assert.equal(boundedInteger("oops", 2, { min: 1, max: 8 }), 2);
  assert.equal(boundedInteger("0", 2, { min: 1, max: 8 }), 1);
  assert.equal(boundedInteger("99", 2, { min: 1, max: 8 }), 8);
});

test("concurrency gate rejects overflow and releases exactly once", () => {
  const gate = createConcurrencyGate(2);
  const releaseFirst = gate.tryAcquire();
  const releaseSecond = gate.tryAcquire();

  assert.equal(gate.active, 2);
  assert.equal(gate.tryAcquire(), null);
  releaseFirst();
  releaseFirst();
  assert.equal(gate.active, 1);

  const releaseThird = gate.tryAcquire();
  assert.equal(typeof releaseThird, "function");
  releaseSecond();
  releaseThird();
  assert.equal(gate.active, 0);
});

test("cached single-flight coalesces concurrent work and caches from completion time", async () => {
  let now = 1000;
  let calls = 0;
  let resolveLoad;
  const loader = createCachedSingleFlight(() => {
    calls += 1;
    return new Promise((resolve) => {
      resolveLoad = resolve;
    });
  }, { ttlMs: 2000, clock: () => now });

  const first = loader.load();
  const second = loader.load({ force: true });
  const third = loader.load();
  await Promise.resolve();
  assert.equal(calls, 1);
  now = 5000;
  resolveLoad({ generation: 1 });
  assert.deepEqual(await Promise.all([first, second, third]), [
    { generation: 1 },
    { generation: 1 },
    { generation: 1 }
  ]);

  now = 6999;
  assert.deepEqual(await loader.load(), { generation: 1 });
  assert.equal(calls, 1, "TTL starts when the expensive load resolves");
});

test("cached single-flight expires, force bypasses cache, and invalidation is explicit", async () => {
  let now = 1000;
  let calls = 0;
  const loader = createCachedSingleFlight(async () => ({ generation: ++calls }), {
    ttlMs: 2000,
    clock: () => now
  });

  assert.deepEqual(await loader.load(), { generation: 1 });
  assert.deepEqual(await loader.load({ force: true }), { generation: 2 });
  now = 4001;
  assert.deepEqual(await loader.load(), { generation: 3 });
  loader.invalidate();
  assert.deepEqual(await loader.load(), { generation: 4 });
});

test("cached single-flight never caches a rejection", async () => {
  let calls = 0;
  const loader = createCachedSingleFlight(async () => {
    calls += 1;
    if (calls === 1) throw new Error("temporary failure");
    return "recovered";
  }, { ttlMs: 2000 });

  await assert.rejects(loader.load(), /temporary failure/);
  assert.equal(loader.inFlight, false);
  assert.equal(await loader.load(), "recovered");
  assert.equal(calls, 2);
});

test("invalidation during an in-flight load prevents that result from repopulating cache", async () => {
  let calls = 0;
  let resolveFirst;
  const loader = createCachedSingleFlight(() => {
    calls += 1;
    if (calls === 1) {
      return new Promise((resolve) => {
        resolveFirst = resolve;
      });
    }
    return Promise.resolve(`value-${calls}`);
  }, { ttlMs: 2000 });

  const first = loader.load();
  await Promise.resolve();
  loader.invalidate();
  resolveFirst("stale-for-cache");
  assert.equal(await first, "stale-for-cache");
  assert.equal(await loader.load(), "value-2");
  assert.equal(calls, 2);
});

test("retiring resource waits for in-flight operations before closing", () => {
  const closed = [];
  const tracker = createRetiringResourceTracker((resource) => closed.push(resource.id));
  const resource = tracker.register({ id: "old-client" });
  const release = tracker.acquire(resource);

  tracker.retire(resource);
  assert.deepEqual(closed, []);
  release();
  release();
  tracker.retire(resource);
  assert.deepEqual(closed, ["old-client"]);
});

test("over-limit websocket installs its error handler before immediate termination", () => {
  let terminateCalls = 0;
  class FakeSocket extends EventEmitter {
    terminate() {
      assert.ok(this.listenerCount("error") > 0, "error handler must exist before terminate");
      terminateCalls += 1;
    }
  }
  const socket = new FakeSocket();

  assert.equal(admitWebSocketConnection(socket, 33, 32), false);
  assert.equal(terminateCalls, 1, "over-limit socket must terminate immediately");
  // EventEmitter 没有 error listener 时这里会抛异常并令 Node 测试失败。
  assert.doesNotThrow(() => socket.emit("error", new Error("late socket error")));
  assert.equal(terminateCalls, 2, "late errors remain handled after rejection");
});

test("websocket sender terminates a slow client before adding more buffered data", () => {
  let sent = false;
  let terminated = false;
  const socket = {
    readyState: 1,
    bufferedAmount: 90,
    send() {
      sent = true;
    },
    terminate() {
      terminated = true;
    }
  };

  assert.equal(sendWebSocketMessage(socket, "12345678901", 100), "terminated");
  assert.equal(sent, false);
  assert.equal(terminated, true);
});

test("websocket sender sends while the bounded buffer has room", () => {
  let sentMessage = "";
  const socket = {
    readyState: 1,
    bufferedAmount: 0,
    send(message, callback) {
      sentMessage = message;
      callback(null);
    },
    terminate() {
      assert.fail("healthy socket must not be terminated");
    }
  };

  assert.equal(sendWebSocketMessage(socket, "event", 100), "sent");
  assert.equal(sentMessage, "event");
});
