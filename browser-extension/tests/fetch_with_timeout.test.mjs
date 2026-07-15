import assert from "node:assert/strict";
import test from "node:test";
import {
  FetchTimeoutError,
  fetchWithTimeout
} from "../lib/fetch_with_timeout.mjs";

test("hanging fetch is aborted at the deadline and its timer is cleared", async () => {
  let observedSignal;
  let clearedTimer = null;
  const hangingFetch = (_input, init) => {
    observedSignal = init.signal;
    return new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
    });
  };

  await assert.rejects(
    fetchWithTimeout(hangingFetch, "http://127.0.0.1/", {}, {
      timeoutMs: 10,
      clearTimeoutImpl: (timer) => {
        clearedTimer = timer;
        clearTimeout(timer);
      }
    }),
    (error) => error instanceof FetchTimeoutError && error.timeoutMs === 10
  );
  assert.equal(observedSignal.aborted, true);
  assert.notEqual(clearedTimer, null);
});

test("a timed-out attempt does not poison a later retry", async () => {
  let attempts = 0;
  const fetchImpl = (_input, init) => {
    attempts += 1;
    if (attempts === 1) {
      return new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
      });
    }
    return Promise.resolve({ ok: true, status: 202 });
  };

  await assert.rejects(
    fetchWithTimeout(fetchImpl, "http://127.0.0.1/", {}, { timeoutMs: 5 }),
    FetchTimeoutError
  );
  const response = await fetchWithTimeout(fetchImpl, "http://127.0.0.1/", {}, { timeoutMs: 50 });
  assert.equal(response.ok, true);
  assert.equal(attempts, 2);
});

test("success and ordinary rejection both clear the deadline timer", async () => {
  const cleared = [];
  const setTimeoutImpl = () => Symbol("timer");
  const clearTimeoutImpl = (timer) => cleared.push(timer);

  const response = await fetchWithTimeout(
    async () => ({ ok: true }),
    "http://127.0.0.1/",
    {},
    { setTimeoutImpl, clearTimeoutImpl }
  );
  assert.equal(response.ok, true);

  await assert.rejects(
    fetchWithTimeout(
      async () => { throw new Error("connection refused"); },
      "http://127.0.0.1/",
      {},
      { setTimeoutImpl, clearTimeoutImpl }
    ),
    /connection refused/
  );
  assert.equal(cleared.length, 2);
});
