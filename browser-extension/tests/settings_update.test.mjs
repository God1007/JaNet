import assert from "node:assert/strict";
import test from "node:test";
import { applySettingsUpdate } from "../lib/settings_update.mjs";

test("disabling collector clears old queue without requesting a refresh", async () => {
  const calls = [];
  const outcome = await applySettingsUpdate({ enabled: false }, {
    clearQueue: async () => calls.push("clear"),
    refresh: async () => calls.push("refresh")
  });
  assert.deepEqual(calls, ["clear"]);
  assert.deepEqual(outcome, {
    enabled: false,
    queueCleared: true,
    refreshRequested: false
  });
});

test("enabled settings request an immediate worker refresh without clearing queue", async () => {
  const calls = [];
  const outcome = await applySettingsUpdate({ enabled: true }, {
    clearQueue: async () => calls.push("clear"),
    refresh: async () => calls.push("refresh")
  });
  assert.deepEqual(calls, ["refresh"]);
  assert.deepEqual(outcome, {
    enabled: true,
    queueCleared: false,
    refreshRequested: true
  });
});
