import { readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import type { Finding, ReconReport } from "@agentgg/core";
import { effectiveVerdict, readFileRecord, updateRunStage, writeFileRecord } from "@agentgg/core";
import { runConcurrent } from "./concurrent.js";
import type { Detector } from "./detect.js";
import { looksLikeRefusal } from "./detectors/refusal.js";
import { FatalScanError, handleDetectorError } from "./diagnostics.js";
import { finishFix } from "./fix-edits.js";
import type { FixRetry } from "./fixer.js";
import { logError, logWarn } from "./log.js";

const shardPath = (f: Finding): string => f.filePath.replace(/\\/g, "/");

/** Primaries the combined verdict confirmed that carry no fix yet; `force`
 *  takes the ones that carry one too. A duplicate never ships on its own;
 *  its primary carries the fix. A finding with no shard to write to is left
 *  out, or every run would pay for a fix it cannot keep. */
export function selectForFix(findings: ReadonlyArray<Finding>, force = false): Finding[] {
  return findings.filter(
    (f) =>
      !f.dedup &&
      (force || !f.suggestedFix) &&
      f.filePath !== "(unknown)" &&
      !isAbsolute(shardPath(f)) &&
      effectiveVerdict(f) === "confirmed",
  );
}

export interface FixPhaseResult {
  written: number;
  total: number;
  /** Set when a fatal provider error stopped the phase early. */
  fatal?: FatalScanError;
}

/** Write one finding's fix into its shard. Read-modify-write with no await
 *  in between, so concurrent workers on the same shard can't lose a fix. */
function persistFix(outDir: string, finding: Finding, provider: string, runId: string): boolean {
  const record = readFileRecord(outDir, finding.agentSlug, shardPath(finding));
  if (!record) return false;
  record.findings = record.findings.map((rec) =>
    rec.id === finding.id ? { ...rec, suggestedFix: finding.suggestedFix } : rec,
  );
  record.analysisHistory.push({
    runId,
    phase: "fix",
    ranAt: new Date().toISOString(),
    durationMs: 0,
    provider,
    agentSlugs: [finding.agentSlug],
    findingCount: 1,
  });
  try {
    writeFileRecord(outDir, record);
    return true;
  } catch (err) {
    logError(`[fix:${finding.id}] persist failed: ${(err as Error).message}`);
    return false;
  }
}

/**
 * Write a suggested fix for every confirmed primary. Runs after the
 * combined verdict (static plus live) has settled, so it pays only for
 * findings the report shows as confirmed. Each fix is persisted as soon as
 * its call returns, so an interrupted phase keeps what it finished.
 *
 * The phase is optional, so it never throws on a provider failure: a failed
 * call costs that one finding its fix, and a fatal error (no credit, bad
 * key) stops the phase and is returned for the caller to act on.
 */
export async function runFixPhase(args: {
  findings: ReadonlyArray<Finding>;
  detector: Detector;
  outDir: string;
  root: string;
  runId: string;
  concurrency: number;
  verbose?: boolean;
  /** Write a fix again for findings that already carry one. */
  force?: boolean;
  /** The scan's recon brief, when it has one. */
  recon?: ReconReport;
  /** The caller's abort signal. Aborting it cancels the phase's calls. */
  signal?: AbortSignal;
}): Promise<FixPhaseResult> {
  const { detector, outDir, root, runId } = args;
  const work = selectForFix(args.findings, args.force);
  const result: FixPhaseResult = { written: 0, total: work.length };
  if (work.length === 0) return result;
  if (!detector.suggestFix) {
    console.log("\nSuggested fixes: backend does not support them, skipping");
    return result;
  }

  console.log(`\nWriting a suggested fix for ${work.length} confirmed finding(s)`);
  updateRunStage(outDir, runId, "fix", { done: 0, total: work.length });

  // Own controller: a fatal error here cancels this phase's in-flight calls,
  // not the caller's run, which still has a report to write.
  const phaseAbort = new AbortController();
  const onParentAbort = () => phaseAbort.abort(args.signal?.reason);
  if (args.signal?.aborted) onParentAbort();
  else args.signal?.addEventListener("abort", onParentAbort, { once: true });

  let done = 0;
  const fileCache = new Map<string, string | null>();
  try {
    await runConcurrent(work, args.concurrency, async (finding) => {
      try {
        if (!readFileRecord(outDir, finding.agentSlug, shardPath(finding))) {
          logWarn(`[fix:${finding.id}] skipped: no file record for "${finding.filePath}"`);
          return;
        }
        let content = fileCache.get(finding.filePath);
        if (content === undefined) {
          try {
            content = readFileSync(resolve(root, finding.filePath), "utf8");
          } catch {
            content = null;
          }
          fileCache.set(finding.filePath, content);
        }
        if (content === null) {
          if (args.verbose) console.log(`    skip fix ${finding.id}: file not readable`);
          return;
        }
        const source = content;
        try {
          const ask = (retry?: FixRetry) =>
            detector.suggestFix?.({
              finding,
              fileContent: source,
              recon: args.recon,
              retry,
              signal: phaseAbort.signal,
            });
          let answer = await ask();
          let checked = finishFix(answer, source, shardPath(finding));
          if (checked.kind === "rejected") {
            // One more ask, with what the check found. After a second miss the
            // finding gets no fix: code the check could not place is not shown.
            if (args.verbose) console.log(`    retry fix ${finding.id}: ${checked.problems[0]}`);
            answer = await ask({ answer: answer ?? "", problems: checked.problems });
            checked = finishFix(answer, source, shardPath(finding));
          }
          if (checked.kind === "rejected") {
            logWarn(
              `[fix:${finding.id}] no fix: the answer did not match ${finding.filePath}. ${checked.problems[0]}`,
            );
            return;
          }
          if (checked.kind === "empty") {
            if (args.verbose) console.log(`    no fix ${finding.id}: the model returned nothing`);
            return;
          }
          if (looksLikeRefusal(checked.fix)) {
            logWarn(`[fix:${finding.id}] the model declined to write a fix`);
            return;
          }
          finding.suggestedFix = checked.fix;
          if (!persistFix(outDir, finding, detector.name, runId)) return;
          result.written++;
          if (args.verbose) {
            console.log(`    fix ${finding.id}: ${checked.edits} edit(s)  ${finding.filePath}`);
          }
        } catch (err) {
          handleDetectorError(args, `fix:${finding.id}`, err, phaseAbort);
        }
      } finally {
        done++;
        updateRunStage(outDir, runId, "fix", { done, total: work.length });
      }
    });
  } catch (err) {
    if (!(err instanceof FatalScanError)) throw err;
    result.fatal = err;
    logWarn(`Suggested fixes stopped early: ${err.message}`);
  } finally {
    args.signal?.removeEventListener("abort", onParentAbort);
  }

  console.log(`  Fixes: ${result.written} of ${work.length} written`);
  return result;
}
