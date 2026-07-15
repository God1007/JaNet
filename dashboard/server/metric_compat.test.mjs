// Unit tests for precise/legacy RTT field selection across rolling schema upgrades.

import assert from "node:assert/strict";
import test from "node:test";

import { preferredMetricNumber } from "./metric_compat.mjs";

test("prefers an explicitly present precise RTT over the legacy integer", () => {
  assert.equal(preferredMetricNumber({ rttMs: 0, rttMsPrecise: 0.375 }, "rttMsPrecise", "rttMs"), 0.375);
});

test("preserves an explicitly measured precise zero", () => {
  assert.equal(preferredMetricNumber({ rttMs: 12, rttMsPrecise: 0 }, "rttMsPrecise", "rttMs"), 0);
});

test("falls back to the legacy RTT when the optional precise field is absent or invalid", () => {
  assert.equal(preferredMetricNumber({ rttMs: 12 }, "rttMsPrecise", "rttMs"), 12);
  assert.equal(preferredMetricNumber({ rttMs: 12, rttMsPrecise: "not-a-number" }, "rttMsPrecise", "rttMs"), 12);
});

test("does not manufacture zero for a missing metric", () => {
  assert.equal(preferredMetricNumber({}, "rttMsPrecise", "rttMs"), null);
});
