// Node 内建测试：锁定实时事件批处理、去重窗口与重连退避边界。

import assert from "node:assert/strict";
import test from "node:test";
import {
  createEventBatcher,
  mergeEventHistory,
  reconnectDelay
} from "./realtime_lifecycle.mjs";

function event(id, timestamp) {
  return { id, timestamp };
}

test("merges event batches once while deduplicating and sorting by timestamp", () => {
  const result = mergeEventHistory(
    [event("b", 2000), event("a", 1000)],
    [event("b", 2500), event("c", 3000)],
    { now: 3000, windowMs: 5000, maxPoints: 10 }
  );

  assert.deepEqual(result.map(({ id, timestamp }) => [id, timestamp]), [
    ["a", 1000],
    ["b", 2500],
    ["c", 3000]
  ]);
});

test("keeps an event burst within the render history cap", () => {
  const incoming = Array.from({ length: 1000 }, (_, index) => event(`event-${index}`, index + 1));
  const result = mergeEventHistory(incoming.slice(0, 100), [...incoming, ...incoming.slice(700)], {
    now: 1000,
    windowMs: 2000,
    maxPoints: 300
  });

  assert.equal(result.length, 300);
  assert.equal(result[0].id, "event-700");
  assert.equal(result.at(-1).id, "event-999");
  assert.equal(new Set(result.map((item) => item.id)).size, result.length);
});

test("batches burst events into one scheduled flush", () => {
  const flushed = [];
  let scheduled = null;
  const batcher = createEventBatcher((items) => flushed.push(items), {
    delayMs: 80,
    schedule(callback) {
      scheduled = callback;
      return 1;
    },
    cancel() {}
  });

  batcher.push(event("a", 1));
  batcher.push(event("b", 2));
  assert.equal(batcher.size, 2);
  assert.equal(flushed.length, 0);
  scheduled();
  assert.deepEqual(flushed[0].map((item) => item.id), ["a", "b"]);
  assert.equal(batcher.size, 0);
});

test("flushes immediately at the burst cap and delivers leftovers on close", () => {
  const flushed = [];
  const batcher = createEventBatcher((items) => flushed.push(items), {
    maxBatchSize: 2,
    schedule() {
      return 1;
    },
    cancel() {}
  });

  batcher.push(event("a", 1));
  batcher.push(event("b", 2));
  batcher.push(event("c", 3));
  batcher.close();
  assert.deepEqual(flushed.map((items) => items.map((item) => item.id)), [["a", "b"], ["c"]]);
});

test("discards a pending batch during component cleanup", () => {
  const flushed = [];
  const batcher = createEventBatcher((items) => flushed.push(items), {
    schedule() {
      return 1;
    },
    cancel() {}
  });

  batcher.push(event("stale", 1));
  batcher.discard();
  batcher.flush();
  assert.deepEqual(flushed, []);
  assert.equal(batcher.size, 0);
});

test("uses bounded exponential reconnect delay with deterministic jitter", () => {
  assert.equal(reconnectDelay(0, { initialMs: 750, maxMs: 15_000 }), 750);
  assert.equal(reconnectDelay(3, { initialMs: 750, maxMs: 15_000 }), 6000);
  assert.equal(reconnectDelay(10, { initialMs: 750, maxMs: 15_000 }), 15_000);
  assert.equal(reconnectDelay(1, {
    initialMs: 1000,
    maxMs: 15_000,
    jitterRatio: 0.2,
    random: () => 1
  }), 2400);
});
