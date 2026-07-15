// Dashboard gRPC metric compatibility helpers: prefer optional precise fields while accepting legacy integers.

// Only an explicitly present, finite precise value may override the legacy field. This preserves a valid 0 while
// avoiding proto3/default-value ambiguity during mixed-version rollouts.
export function preferredMetricNumber(source, preciseKey, legacyKey, fallback = null) {
  if (source && Object.prototype.hasOwnProperty.call(source, preciseKey)) {
    const precise = finiteNumber(source[preciseKey]);
    if (precise !== null) {
      return precise;
    }
  }

  const legacy = finiteNumber(source?.[legacyKey]);
  return legacy === null ? fallback : legacy;
}

// Reject absent, empty and non-finite values instead of silently converting them to a measured 0 ms.
function finiteNumber(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}
