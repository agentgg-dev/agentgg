import type { Finding } from "@agentgg/core";
import { z } from "zod";
import { languageFromPath } from "./detect.js";

/**
 * De-duplication operates on a single source file at a time. All findings
 * that share a `filePath` (unioned across agent shards) are handed to the
 * model in one call; it returns clusters of findings that describe the
 * SAME underlying vulnerability at the SAME code location, each with one
 * primary kept and the rest marked duplicate.
 *
 * This is the third post-detection pass, peer to validation and scoring,
 * but it is a *gather* step: unlike those it needs every finding for a
 * file co-located, so it can only run after the distributed
 * scan/validate/score phases have all completed.
 */

/**
 * One equivalence class the model produced for a file. `primaryId` is the
 * finding to keep (canonical); `duplicateIds` are the findings folded into
 * it. The model only returns clusters that contain at least one duplicate
 * — singletons are implicit (any finding not named here is unique).
 */
export const LlmDedupCluster = z.object({
  primaryId: z
    .string()
    .describe(
      "The `id` of the finding to KEEP as the canonical report for this root cause. Pick the most precise / highest-confidence statement (prefer a 'confirmed' finding over an 'uncertain' one).",
    ),
  duplicateIds: z
    .array(z.string())
    .min(1)
    .describe(
      "`id`s of the OTHER findings that describe the same vulnerability at the same location and should be folded into the primary. Must not include `primaryId`. Must be non-empty.",
    ),
  reasoning: z
    .string()
    .describe(
      "Short prose (max 4 sentences) explaining why these findings share one root cause. Cite the shared sink / line range.",
    ),
});
export type LlmDedupCluster = z.infer<typeof LlmDedupCluster>;

export const LlmDedup = z.object({
  clusters: z
    .array(LlmDedupCluster)
    .describe(
      "One entry per group of duplicates. Return an empty array if every finding is distinct. Do NOT include singletons.",
    ),
});
export type LlmDedup = z.infer<typeof LlmDedup>;

/**
 * Build the prompt for de-duplicating one file's findings. The model sees
 * every finding's stable `id` plus the fields that distinguish root cause
 * (agent, vuln class, line range, summary, details) and, when available,
 * the source file itself so it can confirm two findings point at the same
 * sink. It returns clusters keyed by `id`.
 */
export function buildDedupePrompt(args: {
  filePath: string;
  findings: Finding[];
  /** Source file content, when readable — grounds the "same location" judgment. */
  fileContent?: string;
}): string {
  const { filePath, findings, fileContent } = args;
  const lang = languageFromPath(filePath);

  const findingBlocks = findings
    .map((f) => {
      const lineHint = f.lineRange
        ? `lines ${f.lineRange[0]}-${f.lineRange[1]}`
        : "unspecified lines";
      const verdict = f.validation?.verdict ? ` | verdict: ${f.validation.verdict}` : "";
      return `### Finding id: ${f.id}
- **Agent:** ${f.agentSlug}
- **Vuln class:** ${f.vulnSlug}
- **Title:** ${f.title}
- **Location:** ${lineHint}${verdict}
- **Summary:** ${f.summary}
- **Details:** ${truncate(f.details, 800)}`;
    })
    .join("\n\n");

  const sourceBlock = fileContent
    ? `

## The source file (\`${filePath}\`)

\`\`\`${lang}
${fileContent}
\`\`\`
`
    : "";

  return `You are de-duplicating security findings for a single source file.
Multiple detection agents reviewed this file, and some reported the SAME
underlying vulnerability more than once — for example, one agent flagged
each interpolated variable in a single SQL query as its own finding, or
two agents flagged the same injection sink from different angles.

Your job: group findings that describe the **same root cause at the same
code location**, and for each group pick ONE primary to keep.

## Rules (read carefully)

- A duplicate is the **same vulnerability** at the **same location** — the
  same sink, the same tainted flow, the same line range. Wording or which
  agent found it does not matter.
- The **same vulnerability class at a DIFFERENT location is NOT a
  duplicate** (e.g. two separate SQL queries on different lines are two
  findings, not one).
- Different vulnerability classes are never duplicates of each other.
- For each group, exactly ONE finding is the primary (kept). Pick the most
  precise / highest-confidence one; prefer a \`confirmed\` finding as the
  primary over an \`uncertain\` one. Every other member is a duplicate of
  it.
- When in doubt, do NOT merge. Folding two distinct bugs into one is worse
  than leaving a real duplicate un-merged.

## The findings in \`${filePath}\`

${findingBlocks}
${sourceBlock}
## Your task

Return \`clusters\`: one entry per group that has at least one duplicate.
Each entry has \`primaryId\` (the id to keep), \`duplicateIds\` (the ids to
fold in, non-empty, never including the primary), and \`reasoning\`. If
every finding above is distinct, return an empty \`clusters\` array.`;
}

/**
 * One resolved duplicate assignment: this finding id is a duplicate of
 * `duplicateOf`, with the model's reasoning.
 */
export interface DedupAssignment {
  id: string;
  duplicateOf: string;
  reasoning: string;
}

/**
 * Turn the model's clusters into a flat, validated set of duplicate
 * assignments for one file. Enforces the single-primary invariant the
 * same way deepsec does:
 *
 *   - every id referenced must exist in this file's finding set
 *   - a primary may not also be someone else's duplicate
 *   - a duplicate may not equal its primary, and is assigned to at most
 *     one primary (first cluster wins)
 *   - a primary that is itself only ever a duplicate elsewhere is rejected
 *
 * Clusters that violate the invariant are dropped wholesale (their members
 * stay unmarked and get retried on the next `dedup --force`), rather than
 * producing a tangled half-applied state.
 */
export function resolveDedup(findings: Finding[], clusters: LlmDedupCluster[]): DedupAssignment[] {
  const byId = new Map(findings.map((f) => [f.id, f]));
  const primaries = new Set<string>();
  const claimedDuplicates = new Set<string>();

  // Pass 1: register every well-formed cluster's primary. A primary that is
  // claimed as a duplicate by another cluster is contradictory — skip it.
  const dupeOfAcrossClusters = new Set<string>();
  for (const c of clusters) {
    for (const d of c.duplicateIds) {
      // A self-reference (a cluster listing its own primary as a duplicate)
      // is dropped below; it must not count toward the "primary is also a
      // duplicate" guard, or it would reject the entire cluster.
      if (d !== c.primaryId) dupeOfAcrossClusters.add(d);
    }
  }

  const assignments: DedupAssignment[] = [];
  for (const c of clusters) {
    if (!byId.has(c.primaryId)) continue; // unknown primary
    if (dupeOfAcrossClusters.has(c.primaryId)) continue; // primary is also a duplicate — contradictory
    if (primaries.has(c.primaryId)) {
      // already the primary of an earlier cluster; merge duplicates into it
    } else {
      primaries.add(c.primaryId);
    }
    for (const dupId of c.duplicateIds) {
      if (dupId === c.primaryId) continue; // self-reference
      if (!byId.has(dupId)) continue; // unknown duplicate
      if (primaries.has(dupId)) continue; // can't be a duplicate AND a primary
      if (claimedDuplicates.has(dupId)) continue; // already assigned to a primary
      claimedDuplicates.add(dupId);
      assignments.push({ id: dupId, duplicateOf: c.primaryId, reasoning: c.reasoning });
    }
  }
  return assignments;
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}
