import { type Finding, isWebReachable, normalizeVulnSlug } from "@agentgg/core";

// The predicate itself lives in core, because the viewer has to explain a
// missing live result with the same rule that produced it.
export { isWebReachable, normalizeVulnSlug };

export function selectWebReachable(findings: Finding[]) {
  const selected: Finding[] = [];
  const skipped: Finding[] = [];
  for (const f of findings) (isWebReachable(f) ? selected : skipped).push(f);
  return { selected, skipped };
}
export function logSkips(skipped: Finding[]): void {
  if (skipped.length === 0) return;
  console.log(`  live validation: skipped ${skipped.length} finding(s) (not web-reachable)`);
}
