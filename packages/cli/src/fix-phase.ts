import { readFileSync, statSync } from "node:fs";
import { isAbsolute, join, resolve, sep } from "node:path";
import type { Finding, ReconReport } from "@agentgg/core";
import {
  effectiveVerdict,
  getEvidenceDir,
  readFileRecord,
  updateRunStage,
  writeFileRecord,
} from "@agentgg/core";
import { runConcurrent } from "./concurrent.js";
import type { Detector } from "./detect.js";
import { looksLikeRefusal } from "./detectors/refusal.js";
import { FatalScanError, handleDetectorError } from "./diagnostics.js";
import { type FileReader, finishFix } from "./fix-edits.js";
import type { FixRetry, LiveScript } from "./fixer.js";
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

/** A source file is far below this; a file above it is data or a bundle. */
const MAX_EDITABLE_BYTES = 2 * 1024 * 1024;

/**
 * The files a fix may edit: regular files under `root`. A path the model
 * writes is untrusted, so one that is absolute or climbs out of the
 * repository reads as no file.
 */
export function repoReader(root: string): FileReader {
  const base = resolve(root);
  const cache = new Map<string, string | undefined>();
  return (path) => {
    if (cache.has(path)) return cache.get(path);
    let content: string | undefined;
    const full = resolve(base, path);
    if (!isAbsolute(path) && full.startsWith(base + sep)) {
      try {
        const stat = statSync(full);
        if (stat.isFile() && stat.size <= MAX_EDITABLE_BYTES) content = readFileSync(full, "utf8");
      } catch {
        // not there
      }
    }
    cache.set(path, content);
    return content;
  };
}

/** The reproduction script a reproduced live run left in the finding's evidence. */
function liveScriptOf(outDir: string, finding: Finding): LiveScript | undefined {
  const script = finding.live?.result === "reproduced" ? finding.live.evidence?.script : undefined;
  if (!script) return undefined;
  try {
    const dir = getEvidenceDir(outDir, finding.agentSlug, finding.id);
    return { source: readFileSync(join(dir, script.path), "utf8"), passed: script.passed };
  } catch {
    return undefined;
  }
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
  /** The scan's walk filters, so the fix's read tools see the files the scan saw. */
  excludePatterns?: string[];
  maxFileSizeKb?: number;
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
  const readFile = repoReader(root);
  try {
    await runConcurrent(work, args.concurrency, async (finding) => {
      try {
        if (!readFileRecord(outDir, finding.agentSlug, shardPath(finding))) {
          logWarn(`[fix:${finding.id}] skipped: no file record for "${finding.filePath}"`);
          return;
        }
        const source = readFile(shardPath(finding));
        if (source === undefined) {
          if (args.verbose) console.log(`    skip fix ${finding.id}: file not readable`);
          return;
        }
        const liveScript = liveScriptOf(outDir, finding);
        try {
          const ask = (retry?: FixRetry) =>
            detector.suggestFix?.({
              finding,
              fileContent: source,
              recon: args.recon,
              liveScript,
              // With a root the call gets read tools, and its blocks may edit
              // any file of the repository.
              root,
              excludePatterns: args.excludePatterns,
              maxFileSizeKb: args.maxFileSizeKb,
              retry,
              signal: phaseAbort.signal,
            });
          let answer = await ask();
          let checked = finishFix(answer, readFile, shardPath(finding));
          if (checked.kind === "rejected") {
            // One more ask, with what the check found. After a second miss the
            // finding gets no fix: code the check could not place is not shown.
            if (args.verbose) console.log(`    retry fix ${finding.id}: ${checked.problems[0]}`);
            answer = await ask({ answer: answer ?? "", problems: checked.problems });
            checked = finishFix(answer, readFile, shardPath(finding));
          }
          if (checked.kind === "rejected") {
            logWarn(
              `[fix:${finding.id}] no fix: the answer did not match the repository. ${checked.problems[0]}`,
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
            const where = checked.files.length > 0 ? checked.files.join(", ") : "in words only";
            console.log(`    fix ${finding.id}: ${checked.edits} edit(s)  ${where}`);
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
