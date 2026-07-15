// Unit tests for sub-millisecond RTT rendering and missing-value semantics.

import assert from "node:assert/strict";
import test from "node:test";

import { formatMilliseconds } from "./rtt_format.mjs";

test("keeps at most three decimal places for RTT", () => {
  assert.equal(formatMilliseconds(0.134), "0.134 ms");
  assert.equal(formatMilliseconds(12.34567), "12.346 ms");
  assert.equal(formatMilliseconds(15.5), "15.5 ms");
});

test("renders a valid zero instead of treating it as missing", () => {
  assert.equal(formatMilliseconds(0), "0 ms");
});

test("renders absent and non-finite metrics as unavailable", () => {
  assert.equal(formatMilliseconds(null), "n/a");
  assert.equal(formatMilliseconds(undefined), "n/a");
  assert.equal(formatMilliseconds(Number.NaN), "n/a");
});
