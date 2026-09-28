import { cpSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { Finding, Severity } from "@agentgg/core";
import { effectiveVerdict, getEvidenceDir } from "@agentgg/core";

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
   * regardless of verdict. When true, findings whose combined verdict is
   * `false-positive` are skipped when writing per-finding `.md` files;
   * the summary still reports the FP count so the user can see how many
   * were filtered out.
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
      ? input.findings.filter((f) => effectiveVerdict(f) !== "false-positive")
      : [...input.findings]
  )
    .filter((f) => !f.dedup)
    .slice()
    .sort(compareForReport);

  const findingPaths: string[] = [];
  // Findings whose evidence was actually copied to findings/, keyed by id.
  // The summary table must use this same eligibility instead of
  // re-deriving it, or it can link to a directory that was never written
  // (metadata survives a rerun even after state/files/<agentSlug>/ is gone).
  const evidenceDirs = new Map<string, string>();
  for (const f of renderable) {
    const fullPath = join(findingsDir, findingFilename(f));
    // Evidence lives under state/ so a rerun cleans it up with the rest of the
    // slice. Copy it beside the .md too: nobody browsing the report will find
    // it otherwise. `findings/` was just cleared, so this cannot go stale.
    let evidenceDir: string | undefined;
    if (f.live?.evidence) {
      const src = getEvidenceDir(outDir, f.agentSlug, f.id);
      if (existsSync(src)) {
        evidenceDir = evidenceDirName(f);
        cpSync(src, join(findingsDir, evidenceDir), { recursive: true });
        evidenceDirs.set(f.id, evidenceDir);
      }
    }
    writeFileSync(fullPath, renderFindingMd(f, duplicatesByPrimary.get(f.id), evidenceDir), "utf8");
    findingPaths.push(fullPath);
  }

  const summaryPath = join(outDir, "summary.md");
  writeFileSync(
    summaryPath,
    renderSummaryMd(input, findingPaths, renderable, duplicatesByPrimary, evidenceDirs),
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

/**
 * Directory carrying a finding's live-validation evidence inside `findings/`.
 * Same basename as the finding's `.md`, so the two sort together and a link
 * from the `.md` is a plain relative path.
 */
export function evidenceDirName(f: Finding): string {
  return findingFilename(f).replace(/\.md$/, "");
}

export function renderFindingMd(
  f: Finding,
  duplicates?: ReadonlyArray<Finding>,
  /** Relative directory holding the copied evidence. Absent when nothing was
   *  copied, in which case the artifacts are named but not linked. */
  evidenceDir?: string,
): string {
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
  if (f.validation || f.live) {
    // Undefined here means no static verdict plus an inconclusive live
    // result, which settles on no verdict at all.
    const verdict = effectiveVerdict(f);
    meta.push(verdict ? `**Validation:** \`${verdict}\`` : "**Validation:** _not settled_");
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

  const live = f.live;
  if (live) {
    lines.push("### Live validation");
    lines.push(`**Result:** \`${live.result}\``);
    lines.push("");
    lines.push(live.reasoning);
    lines.push("");
    if (live.counterevidence.trim().length > 0) {
      lines.push(`**Counterevidence:** ${live.counterevidence}`);
      lines.push("");
    }
    // The control is what separates the effect from the agent's own setup, so
    // it sits with the verdict rather than among the evidence files.
    if ((live.negativeControl ?? "").trim().length > 0) {
      lines.push(`**Negative control:** ${live.negativeControl}`);
      lines.push("");
    }
    const ev = live.evidence;
    if (ev) {
      const link = (name: string) =>
        evidenceDir ? `[${name}](${evidenceDir}/${name})` : `\`${name}\``;
      if (ev.script) {
        // A refuted finding's script is a negative control, never replayed:
        // calling it a reproduction would read as a partial exploit.
        if (live.result === "refuted") {
          lines.push(`- Negative control script: ${link(ev.script.path)}`);
        } else {
          lines.push(
            `- Reproduction script: ${link(ev.script.path)} (${ev.script.passed ? "replays" : "unverified"})`,
          );
        }
      }
      if (ev.trace) lines.push(`- Trace: ${link(ev.trace)}`);
      if (ev.video) lines.push(`- Video: ${link(ev.video)}`);
      if (ev.har) lines.push(`- HAR: ${link(ev.har)}`);
      for (const s of ev.screenshots ?? []) lines.push(`- Screenshot: ${link(s)}`);
      if (ev.requestsFile) lines.push(`- Requests: ${link(ev.requestsFile)}`);
      lines.push("");

      // The request table is the protocol-level proof: it shows what was sent
      // and the status it got back, which the video and screenshots cannot.
      if (ev.requests && ev.requests.length > 0) {
        lines.push("### Requests");
        lines.push("");
        lines.push("| Method | URL | Status | Payload |");
        lines.push("| --- | --- | --- | --- |");
        for (const r of ev.requests) {
          // The payload is what separates one attempt from the next: without
          // it every login try reads as the same row.
          const body = r.requestBody ? `\`${r.requestBody.replace(/\|/g, "\\|")}\`` : "";
          lines.push(`| ${r.method} | \`${r.url}\` | ${r.status} | ${body} |`);
        }
        if (ev.requestsFile)
          lines.push("", `Full request and response headers: ${link(ev.requestsFile)}.`);
        lines.push("");
      }
    }
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
  /** finding id -> the relative directory its evidence was copied to. A
   *  finding missing from the map had no evidence on disk, so its artifacts
   *  are named but not linked. */
  evidenceDirs?: ReadonlyMap<string, string>,
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

  // Primaries only, on the combined verdict: a duplicate is represented by
  // its primary and never gets a verdict of its own, and a live result can
  // move the one a primary carries.
  const primaries = input.findings.filter((f) => !f.dedup);
  const byVerdict: Record<string, number> = {};
  let unvalidated = 0;
  for (const f of primaries) {
    const verdict = effectiveVerdict(f);
    if (verdict) byVerdict[verdict] = (byVerdict[verdict] ?? 0) + 1;
    else unvalidated++;
  }
  if (primaries.length > 0) {
    lines.push("## Findings by validation verdict");
    lines.push("");
    const verdictKeys = Object.keys(byVerdict).sort();
    if (verdictKeys.length === 0 && unvalidated === primaries.length) {
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

  const liveValidated = renderedList.filter((f) => f.live);
  if (liveValidated.length > 0) {
    lines.push("## Live validation");
    lines.push("");
    lines.push("| Finding | Result | Evidence |");
    lines.push("| --- | --- | --- |");
    for (const f of liveValidated) {
      const live = f.live;
      // Only link when this finding's evidence was actually copied. A
      // finding can carry evidence metadata with nothing on disk (e.g. a
      // rerun cleaned up state/files/<agentSlug>/ after the fact), in which
      // case linking would produce a dangling href.
      const dir = evidenceDirs?.get(f.id);
      const ev = live?.evidence;
      const link = (label: string, name: string) =>
        dir ? `[${label}](findings/${dir}/${name})` : `${label} \`${name}\``;
      const parts: string[] = [];
      if (ev?.video) parts.push(link("video", ev.video));
      if (ev?.trace) parts.push(link("trace", ev.trace));
      if (ev?.script) parts.push(link("script", ev.script.path));
      if (ev?.screenshots?.length) parts.push(`${ev.screenshots.length} screenshot(s)`);
      lines.push(
        `| [${f.title}](findings/${findingFilename(f)}) | \`${live?.result}\` | ${
          parts.length > 0 ? parts.join(", ") : "none"
        } |`,
      );
    }
    lines.push("");
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
