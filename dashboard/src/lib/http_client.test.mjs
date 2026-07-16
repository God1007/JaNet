// Node 内建测试：锁定 Dashboard 请求的成功、错误、限流、取消和超时语义。

import assert from "node:assert/strict";
import test from "node:test";
import {
  fetchJson,
  HttpRequestError,
  HttpTimeoutError,
  isAbortError
} from "./http_client.mjs";

test("returns parsed JSON for a successful response", async () => {
  const value = await fetchJson("http://dashboard.test/snapshot", {}, {
    fetchImpl: async () => new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" }
    })
  });

  assert.deepEqual(value, { ok: true });
});

test("uses the server JSON error and Retry-After for overload feedback", async () => {
  await assert.rejects(
    fetchJson("http://dashboard.test/analyze", {}, {
      label: "AI analysis",
      fetchImpl: async () => new Response(JSON.stringify({ error: "analysis capacity is busy" }), {
        status: 429,
        headers: { "retry-after": "2" }
      })
    }),
    (error) => {
      assert.ok(error instanceof HttpRequestError);
      assert.equal(error.status, 429);
      assert.equal(error.retryAfterMs, 2000);
      assert.match(error.message, /analysis capacity is busy.*Retry in 2s/);
      return true;
    }
  );
});

test("rejects a successful non-JSON payload instead of leaking a parse exception", async () => {
  await assert.rejects(
    fetchJson("http://dashboard.test/snapshot", {}, {
      label: "Snapshot refresh",
      fetchImpl: async () => new Response("not json", { status: 200 })
    }),
    /Snapshot refresh returned invalid JSON/
  );
});

test("aborts a hanging request at its deadline", async () => {
  await assert.rejects(
    fetchJson("http://dashboard.test/snapshot", {}, {
      timeoutMs: 10,
      label: "Snapshot refresh",
      fetchImpl: (_input, init) => new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => {
          reject(new DOMException("aborted", "AbortError"));
        }, { once: true });
      })
    }),
    (error) => {
      assert.ok(error instanceof HttpTimeoutError);
      assert.match(error.message, /Snapshot refresh timed out after 1s/);
      return true;
    }
  );
});

test("preserves caller cancellation as AbortError", async () => {
  const controller = new AbortController();
  const request = fetchJson("http://dashboard.test/snapshot", { signal: controller.signal }, {
    timeoutMs: 1000,
    fetchImpl: (_input, init) => new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => {
        reject(new DOMException("aborted", "AbortError"));
      }, { once: true });
    })
  });

  controller.abort();
  await assert.rejects(request, (error) => isAbortError(error));
});
