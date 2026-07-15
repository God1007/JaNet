// 多序列选择单测：覆盖默认单选、叠加、最少一条保护和动态 Probe target 变更。

import assert from "node:assert/strict";
import test from "node:test";

import {
  reconcileSeriesSelection,
  toggleSeriesSelection
} from "./series_selection.mjs";

test("defaults to one preferred series or the first available series", () => {
  const available = ["throughput", "packets", "flows"];

  assert.deepEqual(reconcileSeriesSelection([], available, "packets"), ["packets"]);
  assert.deepEqual(reconcileSeriesSelection([], available, "missing"), ["throughput"]);
});

test("adds another available series without replacing the current selection", () => {
  assert.deepEqual(
    toggleSeriesSelection(["throughput"], "packets", ["throughput", "packets", "flows"]),
    ["throughput", "packets"]
  );
});

test("does not allow the final visible series to be deselected", () => {
  assert.deepEqual(
    toggleSeriesSelection(["throughput"], "throughput", ["throughput", "packets"]),
    ["throughput"]
  );

  assert.deepEqual(
    toggleSeriesSelection(["throughput", "packets"], "packets", ["throughput", "packets"]),
    ["throughput"]
  );
});

test("retains surviving Probe targets and does not auto-select newly discovered targets", () => {
  assert.deepEqual(
    reconcileSeriesSelection(
      ["8.8.8.8", "baidu.com"],
      ["baidu.com", "one.one.one.one"]
    ),
    ["baidu.com"]
  );
});

test("falls back to a new Probe target when every previous target disappears", () => {
  assert.deepEqual(
    reconcileSeriesSelection(["8.8.8.8"], ["one.one.one.one"]),
    ["one.one.one.one"]
  );
});

test("returns no selection only when the data source has no available series", () => {
  assert.deepEqual(reconcileSeriesSelection(["8.8.8.8"], []), []);
  assert.deepEqual(toggleSeriesSelection([], "8.8.8.8", []), []);
});
