import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { Finding, Severity } from "@agentgg/core";

/**
 * Sort order for rendered findings: severity bucket descending, then
 * CVSS base score descending within the bucket, then by file path for
 * stability. Findings with no severity sort last so unscored items
 * don't crowd the top of the report.
 */
const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

function severityRank(f: Finding): number {
  return f.severity ? SEVERITY_ORDER[f.severity] : 5;
}

function compareForReport(a: Finding, b: Finding): number {
  const rankDiff = severityRank(a) - severityRank(b);
  if (rankDiff !== 0) return rankDiff;
  const scoreDiff = (b.cvss?.baseScore ?? -1) - (a.cvss?.baseScore ?? -1);
  if (scoreDiff !== 0) return scoreDiff;
  return a.filePath.localeCompare(b.filePath);
}

export interface ScanReportInput {
  outDir: string;
  root: string;
  startedAt: Date;
  completedAt: Date;
  findings: ReadonlyArray<Finding>;
  /** Files scanned, for the summary stats. */
  filesScanned: number;
  /** Per-agent findings count (slug → count). */
  byAgent: Record<string, number>;
  /**
   * When false (default), every finding gets a per-finding `.md`
   * regardless of verdict — including those with `validation.verdict
   * === "false-positive"`. When true, false-positive findings are
   * skipped when writing per-finding `.md` files; the summary still
   * reports the FP count so the user can see how many were filtered
   * out.
   */
  excludeFalsePositives?: boolean;
}

export interface ScanReportOutput {
  summaryPath: string;
  findingPaths: string[];
}

/**
 * Write the markdown report: one `summary.md` plus one `.md` per
 * finding. Findings live flat in `findings/` for v0.1 — once scoring
 * lands, the layout can switch to `findings/<severity>/...` without
 * the rest of the pipeline noticing.
 */
export function writeMarkdownReport(input: ScanReportInput): ScanReportOutput {
  const outDir = resolve(input.outDir);
  const findingsDir = join(outDir, "findings");
  // Clear any stale finding `.md` files from a prior run before
  // re-rendering. Filenames are stable per finding `id`, so a finding
  // that disappears between runs (e.g. revalidate drops a
  // false-positive, or a code change removes the issue) would otherwise
  // leave its orphaned `.md` behind. `findings/` is fully generated —
  // nothing user-authored lives here.
  //
  // NB: this full clear is correct for a single all-in-one render. When
  // the distributed `summary` step lands, it must render every agent's
  // findings in ONE pass over the merged shards (not once per agent),
  // or each agent would wipe the previous agent's files.
  rmSync(findingsDir, { recursive: true, force: true });
  mkdirSync(findingsDir, { recursive: true });

  // Findings the de-duplication phase marked as duplicates are collapsed
  // under their primary: they don't get their own `.md` or a line in the
  // All-findings list, and the primary's `.md` notes how many were folded
  // in. They remain on disk in state/files/* regardless (deletion is a
  // separate opt-in in the dedup command), so this is purely a reporting
  // choice. Map primary id → its duplicates so we can annotate the primary.
  const duplicatesByPrimary = new Map<string, Finding[]>();
  for (const f of input.findings) {
    if (!f.dedup) continue;
    const list = duplicatesByPrimary.get(f.dedup.duplicateOf);
    if (list) list.push(f);
    else duplicatesByPrimary.set(f.dedup.duplicateOf, [f]);
  }

  // False-positives get their own `.md` by default (and always stay
  // in the FileRecord state as an audit trail). The caller can opt out
  // of rendering them with `excludeFalsePositives`; the summary still
  // counts them so the operator sees how many the validator flagged.
  // Duplicates are always collapsed out of the rendered set.
  const renderable = (
    input.excludeFalsePositives
      ? input.findings.filter((f) => f.validation?.verdict !== "false-positive")
      : [...input.findings]
  )
    .filter((f) => !f.dedup)
    .slice()
    .sort(compareForReport);

  const findingPaths: string[] = [];
  for (const f of renderable) {
    const fullPath = join(findingsDir, findingFilename(f));
    writeFileSync(fullPath, renderFindingMd(f, duplicatesByPrimary.get(f.id)), "utf8");
    findingPaths.push(fullPath);
  }

  const summaryPath = join(outDir, "summary.md");
  writeFileSync(
    summaryPath,
    renderSummaryMd(input, findingPaths, renderable, duplicatesByPrimary),
    "utf8",
  );

  return { summaryPath, findingPaths };
}

/**
 * Filename convention: `<agentSlug>-<short-title-slug>-<id>.md`. No
 * sequence prefix — the `id` suffix (a content hash of
 * agentSlug|filePath|title|lineRange, see `hydrateFinding`) makes the
 * name globally unique AND stable, so:
 *   - findings from N independently-run agents merge into one
 *     `findings/` dir by plain copy, with zero collisions;
 *   - a retried/duplicated worker regenerates the SAME filename and
 *     idempotently overwrites, instead of leaving a uuid-suffixed dupe.
 * UIs sort by score (then title), so on-disk ordering is irrelevant.
 */
export function findingFilename(f: Finding): string {
  return findingFilenameSlug(f);
}

/**
 * Canonical per-finding filename. Same value used in streaming logs
 * (e.g. the scoring phase) and as the written `.md` filename, so a
 * slug printed mid-scan tab-completes to the real file in `findings/`.
 */
export function findingFilenameSlug(f: Finding): string {
  const titleSlug = slugify(f.title).slice(0, 40);
  return `${f.agentSlug}-${titleSlug}-${f.id}.md`;
}

export function renderFindingMd(f: Finding, duplicates?: ReadonlyArray<Finding>): string {
  const lines: string[] = [];
  lines.push(`# ${f.title}`);
  lines.push("");

  const meta: string[] = [];
  meta.push(`**Agent:** \`${f.agentSlug}\``);
  meta.push(`**Vuln class:** \`${f.vulnSlug}\``);
  meta.push(`**File:** \`${f.filePath}\``);
  if (f.lineRange) meta.push(`**Lines:** ${f.lineRange[0]}–${f.lineRange[1]}`);
  meta.push(`**Confidence:** ${(f.confidence * 100).toFixed(0)}%`);
  if (f.severity) {
    meta.push(`**Severity:** ${f.severity}`);
  } else {
    meta.push("**Severity:** _pending (scoring phase not yet run)_");
  }
  if (f.cvss) {
    meta.push(`**CVSS:** ${f.cvss.baseScore.toFixed(1)} (\`${f.cvss.vector}\`)`);
  }
  if (f.validation) {
    meta.push(`**Validation:** \`${f.validation.verdict}\``);
  } else {
    meta.push("**Validation:** _not run_");
  }
  lines.push(meta.join("  \n"));
  lines.push("");

  if (f.validation) {
    lines.push("### Validation");
    lines.push(`**Verdict:** \`${f.validation.verdict}\``);
    lines.push("");
    lines.push(f.validation.reasoning);
    lines.push("");
  }

  // De-duplication folded other findings into this one as the canonical
  // report for the shared root cause. List them so the reviewer sees the
  // full picture without separate tickets.
  if (duplicates && duplicates.length > 0) {
    lines.push(`### Duplicates collapsed (${duplicates.length})`);
    lines.push("");
    lines.push("These findings describe the same root cause and were folded into this one:");
    lines.push("");
    for (const d of duplicates) {
      const loc = d.lineRange ? `:${d.lineRange[0]}` : "";
      lines.push(`- \`${d.agentSlug}\`: ${d.title} (\`${d.filePath}${loc}\`)`);
      if (d.dedup?.reasoning) lines.push(`  - ${d.dedup.reasoning}`);
    }
    lines.push("");
  }

  // If this finding is itself a duplicate (only rendered when a caller
  // opts to show collapsed items), flag it.
  if (f.dedup) {
    lines.push(`**Duplicate of:** \`${f.dedup.duplicateOf}\``);
    lines.push("");
    lines.push(f.dedup.reasoning);
    lines.push("");
  }

  lines.push("### Summary");
  lines.push(f.summary);
  lines.push("");

  lines.push("### Details");
  lines.push(f.details);
  lines.push("");

  lines.push("### PoC");
  lines.push(f.poc);
  lines.push("");

  lines.push("### Impact");
  lines.push(f.impact);
  lines.push("");

  if (f.references.length > 0) {
    lines.push("### References");
    for (const r of f.references) lines.push(`- ${r}`);
    lines.push("");
  }

  return lines.join("\n");
}

export function renderSummaryMd(
  input: ScanReportInput,
  _findingPaths: string[],
  /**
   * Findings actually rendered to disk, in the same order their `.md`
   * files were emitted. Used to drive the All-findings list so the
   * links line up with the index-prefixed filenames. When omitted,
   * falls back to `input.findings` for back-compat with older callers
   * (the standalone `renderSummaryMd` tests still pass an unsorted
   * list).
   */
  rendered?: ReadonlyArray<Finding>,
  /** primary id → folded-in duplicates, for the collapsed-count line. */
  duplicatesByPrimary?: ReadonlyMap<string, ReadonlyArray<Finding>>,
): string {
  const renderedList = rendered ?? input.findings;
  const durationMs = input.completedAt.getTime() - input.startedAt.getTime();
  const durationSec = (durationMs / 1000).toFixed(1);
  const lines: string[] = [];
  lines.push("# Scan summary");
  lines.push("");
  lines.push(`**Root:** \`${input.root}\``);
  lines.push(`**Started:** ${input.startedAt.toISOString()}`);
  lines.push(`**Completed:** ${input.completedAt.toISOString()}`);
  lines.push(`**Duration:** ${durationSec}s`);
  lines.push(`**Files scanned:** ${input.filesScanned}`);
  lines.push(`**Total findings:** ${input.findings.length}`);
  const collapsedDuplicates = duplicatesByPrimary
    ? [...duplicatesByPrimary.values()].reduce((n, ds) => n + ds.length, 0)
    : input.findings.filter((f) => f.dedup).length;
  if (collapsedDuplicates > 0) {
    const primaries = duplicatesByPrimary
      ? duplicatesByPrimary.size
      : new Set(input.findings.filter((f) => f.dedup).map((f) => f.dedup?.duplicateOf)).size;
    lines.push(
      `**Duplicates collapsed:** ${collapsedDuplicates} (folded into ${primaries} primary finding(s))`,
    );
  }
  lines.push("");

  lines.push("## Findings by agent");
  lines.push("");
  const agentSlugs = Object.keys(input.byAgent).sort();
  if (agentSlugs.length === 0) {
    lines.push("_No findings._");
  } else {
    for (const slug of agentSlugs) {
      lines.push(`- \`${slug}\`: ${input.byAgent[slug]}`);
    }
  }
  lines.push("");

  const byVerdict: Record<string, number> = {};
  let unvalidated = 0;
  for (const f of input.findings) {
    if (f.validation) {
      byVerdict[f.validation.verdict] = (byVerdict[f.validation.verdict] ?? 0) + 1;
    } else {
      unvalidated++;
    }
  }
  if (input.findings.length > 0) {
    lines.push("## Findings by validation verdict");
    lines.push("");
    const verdictKeys = Object.keys(byVerdict).sort();
    if (verdictKeys.length === 0 && unvalidated === input.findings.length) {
      lines.push("_Validation phase did not run (pass `--validate` to enable)._");
    } else {
      for (const v of verdictKeys) lines.push(`- \`${v}\`: ${byVerdict[v]}`);
      if (unvalidated > 0) lines.push(`- _unvalidated_: ${unvalidated}`);
    }
    lines.push("");
  }

  // Severity breakdown — only shown when the scoring phase has run on
  // at least one finding. Order matches the CVSS severity rubric:
  // CRITICAL first, INFO last.
  if (input.findings.length > 0) {
    const bySeverity: Record<string, number> = {};
    let unscored = 0;
    for (const f of input.findings) {
      if (f.severity) {
        bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
      } else {
        unscored++;
      }
    }
    const anyScored = Object.keys(bySeverity).length > 0;
    if (anyScored) {
      lines.push("## Findings by severity");
      lines.push("");
      const order: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
      for (const s of order) {
        if (bySeverity[s]) lines.push(`- \`${s}\`: ${bySeverity[s]}`);
      }
      if (unscored > 0) lines.push(`- _unscored_: ${unscored}`);
      lines.push("");
    }
  }

  if (renderedList.length > 0) {
    lines.push("## All findings");
    lines.push("");
    renderedList.forEach((f) => {
      const rel = `findings/${findingFilename(f)}`;
      const loc = f.lineRange ? `:${f.lineRange[0]}` : "";
      const sevTag = f.severity
        ? ` \`${f.severity}${f.cvss ? ` ${f.cvss.baseScore.toFixed(1)}` : ""}\``
        : "";
      lines.push(`-${sevTag} [${f.title}](${rel}) — \`${f.filePath}${loc}\``);
    });
    lines.push("");
  }

  return lines.join("\n");
}

function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}
