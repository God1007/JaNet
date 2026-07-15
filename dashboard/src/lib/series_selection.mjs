// 多序列图表选择状态：统一默认值、切换保护和动态数据源变更时的状态收敛。

// 仅保留非空且不重复的字符串 id，避免异常状态污染图表选择。
function uniqueSeriesIds(values) {
  if (!Array.isArray(values)) return [];

  const seen = new Set();
  const result = [];
  for (const value of values) {
    if (typeof value !== "string" || value.length === 0 || seen.has(value)) continue;
    seen.add(value);
    result.push(value);
  }
  return result;
}

/**
 * 将已有选择与当前可用序列对齐。
 *
 * 动态序列新增时不擅自勾选；已选项全部消失时，才回退到首选项或第一条可用序列。
 * 数据源确实为空时允许返回空数组，这与用户主动取消最后一条序列是两种语义。
 */
export function reconcileSeriesSelection(selectedIds, availableIds, preferredId) {
  const available = uniqueSeriesIds(availableIds);
  if (available.length === 0) return [];

  const availableSet = new Set(available);
  const retained = uniqueSeriesIds(selectedIds).filter((id) => availableSet.has(id));
  if (retained.length > 0) return retained;

  if (typeof preferredId === "string" && availableSet.has(preferredId)) {
    return [preferredId];
  }
  return [available[0]];
}

/**
 * 切换单条序列；可以叠加或移除，但可用数据存在时始终至少保留一条。
 */
export function toggleSeriesSelection(selectedIds, seriesId, availableIds) {
  const available = uniqueSeriesIds(availableIds);
  const current = reconcileSeriesSelection(selectedIds, available);
  if (!available.includes(seriesId)) return current;

  if (!current.includes(seriesId)) return [...current, seriesId];
  if (current.length === 1) return current;
  return current.filter((id) => id !== seriesId);
}
