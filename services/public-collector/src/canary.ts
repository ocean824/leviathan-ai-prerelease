export function canarySignature(records: Record<string, unknown>[]): string | null {
  if (!records.length) return null;
  const signatures = records.map((record) => {
    const values = record.values;
    if (!values || typeof values !== "object" || Array.isArray(values)) return null;
    return JSON.stringify(Object.fromEntries(
      Object.entries(values as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, value]) => [key, Array.isArray(value) ? "array" : value === null ? "null" : typeof value]),
    ));
  });
  if (signatures.some((signature) => signature === null)) return null;
  return [...new Set(signatures)].sort().join("|");
}

export function canaryCompatible(
  baseline: Record<string, unknown>[],
  candidate: Record<string, unknown>[],
): boolean {
  const priorSignature = canarySignature(baseline);
  return Boolean(
    priorSignature &&
    candidate.length > 0 &&
    priorSignature === canarySignature(candidate) &&
    candidate.length <= Math.max(2, baseline.length * 4),
  );
}
