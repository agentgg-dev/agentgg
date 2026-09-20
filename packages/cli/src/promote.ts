import type { Finding } from "@agentgg/core";

const REJECTED = new Set(["false-positive", "out-of-scope"]);
const isRejected = (f: Finding) => REJECTED.has(f.validation?.verdict ?? "");

/** Clusters keyed by primary id, duplicates in their stored order. */
function clusters(findings: Finding[]): Map<string, { primary: Finding; dupes: Finding[] }> {
  const byId = new Map(findings.map((f) => [f.id, f]));
  const out = new Map<string, { primary: Finding; dupes: Finding[] }>();
  for (const f of findings) {
    const primaryId = f.dedup?.duplicateOf;
    if (!primaryId) continue;
    const primary = byId.get(primaryId);
    // A "primary" that carries a marker of its own is a chain, not a
    // cluster: leave it to the next dedupe run rather than promoting into it.
    if (!primary || primary.dedup) continue;
    const entry = out.get(primaryId) ?? { primary, dupes: [] };
    entry.dupes.push(f);
    out.set(primaryId, entry);
  }
  return out;
}

/** Duplicates worth validating: their primary was rejected, so one of them
 *  may be the finding that ships. */
export function duplicatesOfRejected(findings: Finding[]): Finding[] {
  const out: Finding[] = [];
  for (const { primary, dupes } of clusters(findings).values()) {
    if (!isRejected(primary)) continue;
    for (const d of dupes) if (!d.validation) out.push(d);
  }
  return out;
}

/** Hand a rejected primary's place to the first duplicate validation kept.
 *  Returns every finding whose marker changed. */
export function promote(findings: Finding[], canMark: (f: Finding) => boolean): Finding[] {
  const changed: Finding[] = [];
  for (const { primary, dupes } of clusters(findings).values()) {
    if (!isRejected(primary)) continue;
    const heir = dupes.find((d) => d.validation && !isRejected(d));
    if (!heir) continue;
    const cluster = [primary, ...dupes];
    if (!cluster.every(canMark)) continue;
    const heirReasoning = heir.dedup?.reasoning ?? "";
    const heirRunId = heir.dedup?.runId;
    heir.dedup = undefined;
    for (const f of cluster) {
      if (f.id === heir.id) continue;
      if (f.id === primary.id) {
        // Demoted primary: gets heir's original reasoning/runId (that pair was actually compared).
        f.dedup = {
          duplicateOf: heir.id,
          reasoning: heirReasoning,
          ...(heirRunId ? { runId: heirRunId } : {}),
        };
      } else {
        // Non-primary duplicates: keep their own reasoning/runId (never directly compared to heir).
        f.dedup = {
          duplicateOf: heir.id,
          reasoning: f.dedup?.reasoning ?? "",
          ...(f.dedup?.runId ? { runId: f.dedup.runId } : {}),
        };
      }
    }
    changed.push(...cluster);
  }
  return changed;
}
