import assert from "node:assert/strict";
import test from "node:test";
import {
  DEFAULT_QUEUE_TTL_MS,
  acknowledgeBatch,
  emptyQueueState,
  enqueueBounded,
  markBatchRetry,
  pruneExpired,
  resetQueueRetry,
  takeBatch
} from "../lib/persistent_queue.mjs";

test("explicit queue clear resets events drops and retry state", () => {
  assert.deepEqual(emptyQueueState(), {
    items: [],
    droppedSinceLastAck: 0,
    retryCount: 0,
    nextAttemptAt: 0
  });
});

test("settings refresh removes backoff without dropping queued events", () => {
  let state = enqueueBounded(undefined, { eventId: "retry-me" }, 5, 1000);
  state = markBatchRetry(state, 1000);
  state = resetQueueRetry(state);
  assert.deepEqual(takeBatch(state).events.map((event) => event.eventId), ["retry-me"]);
  assert.equal(state.retryCount, 0);
  assert.equal(state.nextAttemptAt, 0);
});

test("queue deduplicates and drops the oldest item at its fixed bound", () => {
  let state;
  state = enqueueBounded(state, { eventId: "a" }, 2);
  state = enqueueBounded(state, { eventId: "a" }, 2);
  state = enqueueBounded(state, { eventId: "b" }, 2);
  state = enqueueBounded(state, { eventId: "c" }, 2);
  assert.deepEqual(state.items.map((item) => item.eventId), ["b", "c"]);
  assert.equal(state.droppedSinceLastAck, 1);
});

test("ack removes only the transmitted IDs and preserves concurrent enqueue", () => {
  let state;
  state = enqueueBounded(state, { eventId: "a" }, 5);
  state = enqueueBounded(state, { eventId: "b" }, 5);
  const sent = takeBatch(state, 1);
  state = enqueueBounded(state, { eventId: "c" }, 5);
  state = acknowledgeBatch(state, sent.events.map((event) => event.eventId), sent.droppedSinceLastAck);
  assert.deepEqual(state.items.map((item) => item.eventId), ["b", "c"]);
});

test("retry retains events and applies bounded exponential backoff", () => {
  let state = enqueueBounded(undefined, { eventId: "a" }, 5);
  state = markBatchRetry(state, 1000);
  assert.equal(state.items.length, 1);
  assert.equal(state.nextAttemptAt, 2000);
  for (let index = 0; index < 20; index += 1) state = markBatchRetry(state, 1000);
  assert.equal(state.retryCount, 10);
  assert.equal(state.nextAttemptAt, 301000);
});

test("queue TTL keeps the exact boundary and drops stale backlog one millisecond later", () => {
  const enqueuedAt = 1_000_000;
  let state = enqueueBounded(undefined, { eventId: "boundary", occurredAt: enqueuedAt }, 5, enqueuedAt);

  state = pruneExpired(state, enqueuedAt + DEFAULT_QUEUE_TTL_MS);
  assert.deepEqual(takeBatch(state).events.map((event) => event.eventId), ["boundary"]);

  state = pruneExpired(state, enqueuedAt + DEFAULT_QUEUE_TTL_MS + 1);
  assert.equal(state.items.length, 0);
  assert.equal(state.droppedSinceLastAck, 1);
  assert.equal(state.retryCount, 0);
  assert.equal(state.nextAttemptAt, 0);
});

test("queue TTL uses persisted enqueue time and never sends its internal metadata", () => {
  const enqueuedAt = 2_000_000;
  let state = enqueueBounded(undefined, {
    eventId: "future-client-clock",
    occurredAt: enqueuedAt + 99_000_000
  }, 5, enqueuedAt);
  const event = takeBatch(state).events[0];
  assert.deepEqual(Object.keys(event).sort(), ["eventId", "occurredAt"]);

  state = pruneExpired(state, enqueuedAt + DEFAULT_QUEUE_TTL_MS + 1);
  assert.equal(state.items.length, 0, "a future client timestamp cannot extend local queue retention");
});

test("enqueue prunes stale items before enforcing the fixed capacity", () => {
  const start = 3_000_000;
  let state = enqueueBounded(undefined, { eventId: "old" }, 2, start);
  state = enqueueBounded(
    state,
    { eventId: "fresh" },
    2,
    start + DEFAULT_QUEUE_TTL_MS + 1
  );
  assert.deepEqual(takeBatch(state).events.map((event) => event.eventId), ["fresh"]);
  assert.equal(state.droppedSinceLastAck, 1);
});
