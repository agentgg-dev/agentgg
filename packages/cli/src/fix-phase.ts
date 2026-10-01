import { readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import type { Finding } from "@agentgg/core";
import { effectiveVerdict, readFileRecord, updateRunStage, writeFileRecord } from "@agentgg/core";
import { runConcurrent } from "./concurrent.js";
import type { Detector } from "./detect.js";
import { handleDetectorError } from "./diagnostics.js";
import { cleanFix } from "./fixer.js";
import { logError } from "./log.js";

/** Primaries the combined verdict confirmed that carry no fix yet; `force`
 *  takes the ones that carry one too. A duplicate never ships on its own;
 *  its primary carries the fix. */
export function selectForFix(findings: ReadonlyArray<Finding>, force = false): Finding[] {
  return findings.filter(
    (f) =>
      !f.dedup &&
      (force || !f.suggestedFix) &&
      f.filePath !== "(unknown)" &&
      effectiveVerdict(f) === "confirmed",
  );
}

/**
 * Write a suggested fix for every confirmed primary. Runs after the
 * combined verdict (static plus live) has settled, so it pays only for
 * findings the report shows as confirmed. A failed call costs that one
 * finding its fix, never the scan.
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
  abortController: AbortController;
}): Promise<void> {
  const { detector, outDir, root, runId, abortController } = args;
  const work = selectForFix(args.findings, args.force);
  if (work.length === 0) return;
  if (!detector.suggestFix) {
    console.log("\nSuggested fixes: backend does not support them, skipping");
    return;
  }

  console.log(`\nWriting a suggested fix for ${work.length} confirmed finding(s)`);
  updateRunStage(outDir, runId, "fix", { done: 0, total: work.length });

  let done = 0;
  const fileCache = new Map<string, string | null>();
  const fixedByShard = new Map<string, { agentSlug: string; filePath: string; ids: Set<string> }>();
  // fixedByShard is mutated only after the await (no yield in between), so
  // concurrent workers can't lose an entry.
  await runConcurrent(work, args.concurrency, async (finding) => {
    try {
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
      try {
        const fix = cleanFix(
          await detector.suggestFix?.({
            finding,
            fileContent: content,
            signal: abortController.signal,
          }),
        );
        if (!fix) {
          if (args.verbose) console.log(`    no fix ${finding.id}: the model returned nothing`);
          return;
        }
        finding.suggestedFix = fix;
        const filePath = finding.filePath.replace(/\\/g, "/");
        const key = `${finding.agentSlug} ${filePath}`;
        const entry = fixedByShard.get(key) ?? {
          agentSlug: finding.agentSlug,
          filePath,
          ids: new Set<string>(),
        };
        entry.ids.add(finding.id);
        fixedByShard.set(key, entry);
      } catch (err) {
        handleDetectorError(args, `fix:${finding.id}`, err, abortController);
      }
    } finally {
      done++;
      updateRunStage(outDir, runId, "fix", { done, total: work.length });
    }
  });

  const byId = new Map(work.map((f) => [f.id, f] as const));
  let written = 0;
  for (const { agentSlug, filePath, ids } of fixedByShard.values()) {
    if (isAbsolute(filePath)) continue;
    const record = readFileRecord(outDir, agentSlug, filePath);
    if (!record) continue;
    record.findings = record.findings.map((rec) =>
      ids.has(rec.id) ? { ...rec, suggestedFix: byId.get(rec.id)?.suggestedFix } : rec,
    );
    record.analysisHistory.push({
      runId,
      phase: "fix",
      ranAt: new Date().toISOString(),
      durationMs: 0,
      provider: detector.name,
      agentSlugs: [agentSlug],
      findingCount: ids.size,
    });
    try {
      writeFileRecord(outDir, record);
      written += ids.size;
    } catch (err) {
      if (args.verbose) {
        logError(`persist failed for ${agentSlug}/${filePath}: ${(err as Error).message}`);
      }
    }
  }
  console.log(`  Fixes: ${written} of ${work.length} written`);
}
