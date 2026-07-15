// RTT presentation helper shared by the React view and dependency-free Node unit tests.

// Render milliseconds with microsecond-derived precision without confusing a valid zero with missing data.
export function formatMilliseconds(value, fallback = "n/a") {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }

  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return fallback;
  }

  const rounded = Math.round((numeric + Math.sign(numeric || 1) * Number.EPSILON) * 1000) / 1000;
  const text = rounded.toFixed(3).replace(/\.?0+$/, "");
  return `${text === "-0" ? "0" : text} ms`;
}
