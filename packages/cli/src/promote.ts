import type { Finding, ValidationVerdict } from "@agentgg/core";

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
 *  may be the finding that ships. `only` limits them to ids the group
 *  verdict never saw. */
export function duplicatesOfRejected(findings: Finding[], only?: Set<string>): Finding[] {
  const out: Finding[] = [];
  for (const { primary, dupes } of clusters(findings).values()) {
    if (!isRejected(primary)) continue;
    for (const d of dupes) if (!d.validation && (!only || only.has(d.id))) out.push(d);
  }
  return out;
}

/** Duplicates keyed by their primary's id, sorted by id so a resumed run
 *  splits a capped group the same way. */
export function membersOf(findings: Finding[]): Map<string, Finding[]> {
  const out = new Map<string, Finding[]>();
  for (const { primary, dupes } of clusters(findings).values()) {
    out.set(
      primary.id,
      [...dupes].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
    );
  }
  return out;
}

/** Make `heir` the primary of `primary`'s group. The demoted primary takes
 *  the heir's reasoning (that pair was compared); the rest keep their own.
 *  Its score, live result and fix judged its own text, so they go too. */
function handOver(primary: Finding, dupes: Finding[], heir: Finding): void {
  const heirReasoning = heir.dedup?.reasoning ?? "";
  const heirRunId = heir.dedup?.runId;
  heir.dedup = undefined;
  primary.cvss = undefined;
  primary.severity = undefined;
  primary.live = undefined;
  primary.suggestedFix = undefined;
  for (const f of [primary, ...dupes]) {
    if (f.id === heir.id) continue;
    const reasoning = f.id === primary.id ? heirReasoning : (f.dedup?.reasoning ?? "");
    const runId = f.id === primary.id ? heirRunId : f.dedup?.runId;
    f.dedup = { duplicateOf: heir.id, reasoning, ...(runId ? { runId } : {}) };
  }
}

/** Hand a rejected primary's place to the first duplicate validation kept.
 *  `onlyHeirs` limits heirs to ids the group verdict never saw: a member it
 *  showed was rejected with the group, whatever verdict it carries.
 *  Returns every finding whose marker changed. */
export function promote(
  findings: Finding[],
  canMark: (f: Finding) => boolean,
  onlyHeirs?: Set<string>,
): Finding[] {
  const changed: Finding[] = [];
  for (const { primary, dupes } of clusters(findings).values()) {
    if (!isRejected(primary)) continue;
    const heir = dupes.find(
      (d) => d.validation && !isRejected(d) && (!onlyHeirs || onlyHeirs.has(d.id)),
    );
    if (!heir) continue;
    const cluster = [primary, ...dupes];
    if (!cluster.every(canMark)) continue;
    handOver(primary, dupes, heir);
    changed.push(...cluster);
  }
  return changed;
}

export type GroupVerdict = {
  verdict: ValidationVerdict;
  reasoning: string;
  confirmedImpact?: string;
  unconfirmedImpact?: string;
  leadId?: string;
  primaryClaimHolds?: boolean;
  refused?: boolean;
};

/** Record one group verdict. The group moves to the `leadId` member only
 *  when the verdict is confirmed and the primary's own claim failed; the
 *  primary is the class specialist, so it keeps the group otherwise. The
 *  model can set `leadId` when it should not, so both checks are needed. */
export function applyGroupVerdict(
  findings: Finding[],
  primary: Finding,
  result: GroupVerdict,
  canMark: (f: Finding) => boolean,
): Finding[] {
  const { leadId, primaryClaimHolds, ...rest } = result;
  const confirmed = rest.verdict === "confirmed";
  const validation = {
    verdict: rest.verdict,
    reasoning: rest.reasoning,
    ...(confirmed && rest.confirmedImpact ? { confirmedImpact: rest.confirmedImpact } : {}),
    ...(confirmed && rest.unconfirmedImpact ? { unconfirmedImpact: rest.unconfirmedImpact } : {}),
    ...(rest.refused ? { refused: true } : {}),
  };
  const dupes = membersOf(findings).get(primary.id) ?? [];
  const heir =
    confirmed && primaryClaimHolds === false && leadId && leadId !== primary.id
      ? dupes.find((d) => d.id === leadId)
      : undefined;
  // A fix was written for the verdict it had then; the fix phase writes a
  // new one for this verdict.
  if (!heir || ![primary, ...dupes].every(canMark)) {
    primary.validation = validation;
    primary.suggestedFix = undefined;
    return [primary];
  }
  handOver(primary, dupes, heir);
  heir.validation = validation;
  heir.suggestedFix = undefined;
  primary.validation = undefined;
  return [primary, ...dupes];
}
