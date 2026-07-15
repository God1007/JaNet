// 多序列选择纯函数的 TypeScript 契约，供静态指标和动态 Probe target 共用。

export function reconcileSeriesSelection(
  selectedIds: readonly string[] | null | undefined,
  availableIds: readonly string[] | null | undefined,
  preferredId?: string | null
): string[];

export function toggleSeriesSelection(
  selectedIds: readonly string[] | null | undefined,
  seriesId: string,
  availableIds: readonly string[] | null | undefined
): string[];
