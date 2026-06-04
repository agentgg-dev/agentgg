import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { FileRecord, Finding, Provider } from "@agentgg/core";
import {
  completeRun,
  createRunMeta,
  loadAllFileRecords,
  readScanMeta,
  writeFileRecord,
  writeRunMeta,
} from "@agentgg/core";
import type { Command } from "commander";
import { runConcurrent } from "../concurrent.js";
import { resolveDedup } from "../deduper.js";
import { handleDetectorError } from "../diagnostics.js";
import { loadOrSynthesizeConfig, resolveDetector } from "../llm.js";
import { buildCredentialsFromOpts, validateProviderFlags } from "../providers/index.js";
import { writeMarkdownReport } from "../reporters/md.js";
import { buildInvocation } from "./invocation.js";

interface DedupOpts {
  provider?: string;
  apiKey?: string;
  oauthToken?: string;
  baseUrl?: string;
  region?: string;
  model?: string;
  /** Re-run dedup over files that already carry dedup markers (clears them first). */
  force?: boolean;
  /**
   * Physically remove duplicate findings from their FileRecords instead of
   * just marking them. Off by default — the safe default keeps every
   * finding on disk and only adds the `dedup` marker.
   */
  deleteDuplicates?: boolean;
  verbose?: boolean;
  /** Override the scanned root recorded in scan.json — rare. */
  root?: string;
  /** Drop false-positive findings from the markdown report (kept by default). */
  excludeFalsePositives?: boolean;
  /** `--no-summary` → skip re-rendering the markdown report. */
  summary?: boolean;
  /** Files de-duplicated in parallel (in-flight LLM calls). Default 5. */
  concurrency?: number;
}

/** A finding is disqualified (won't ship) when validation rejected it. */
function isDisqualified(f: Finding): boolean {
  const v = f.validation?.verdict;
  return v === "false-positive" || v === "out-of-scope";
}

/**
 * De-duplication phase — the final gather pass over persisted findings.
 *
 * Findings are sharded on disk by `(agentSlug, filePath)`, so the same
 * source file's full finding set is the union of every agent's record for
 * that path. Dedup groups findings by `filePath` ACROSS agent shards, asks
 * the model to cluster same-root-cause findings within each file, and
 * marks the non-primary members with a `dedup` field pointing at the
 * primary's stable `id`. The marker is orthogonal to the validation
 * verdict — a `confirmed` finding can still be a duplicate.
 *
 * This cannot run distributed: it needs every finding for a file
 * co-located. Run it after scan/validate/score have all completed.
 *
 * By default a duplicate is only MARKED (kept on disk); `--delete-
 * duplicates` strips it from its FileRecord instead. Files that already
 * carry dedup markers are skipped unless `--force` (which clears the old
 * markers and recomputes).
 */
export async function runDedup(
  outputArg: string,
  opts: DedupOpts,
  env: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  const outputDir = resolve(outputArg);
  const scanMeta = readScanMeta(outputDir);
  if (!scanMeta) {
    throw new Error(
      `No scan state at ${outputDir}. Run \`agentgg scan <path> -o ${outputArg}\` first.`,
    );
  }
  const rootPath = opts.root ? resolve(opts.root) : scanMeta.root;

  const config = loadOrSynthesizeConfig(env, opts.provider);
  const activeProvider = (opts.provider ?? config.provider) as Provider;
  validateProviderFlags(activeProvider, opts);
  const credentials = buildCredentialsFromOpts(opts);
  const detector = resolveDetector(config, {
    provider: opts.provider,
    model: opts.model,
    credentials,
    verbose: opts.verbose,
  });

  // Same abort-on-fatal-diagnostic pattern as scan/revalidate.
  const dedupAbortController = new AbortController();

  const records = loadAllFileRecords(outputDir);
  if (records.length === 0) {
    console.log(`No FileRecords in ${outputDir}/state/files/.`);
    console.log("  Run `agentgg scan` first to populate findings.");
    return;
  }

  // Index every finding by id → {finding, record}, and group the
  // shippable findings by source filePath (unioning across agent shards).
  const index = new Map<string, { finding: Finding; record: FileRecord }>();
  const byFile = new Map<string, Finding[]>();
  const dirtyRecords = new Set<FileRecord>();
  for (const record of records) {
    for (const finding of record.findings) {
      index.set(finding.id, { finding, record });
      // --force clears prior markers up front so a recompute starts clean.
      if (opts.force && finding.dedup) {
        finding.dedup = undefined;
        dirtyRecords.add(record);
      }
      if (isDisqualified(finding)) continue;
      const bucket = byFile.get(finding.filePath);
      if (bucket) bucket.push(finding);
      else byFile.set(finding.filePath, [finding]);
    }
  }

  // Candidate files: 2+ shippable findings. Without --force, skip files
  // that already carry any dedup marker (already processed).
  type Task = { filePath: string; findings: Finding[] };
  const tasks: Task[] = [];
  let skippedAlready = 0;
  for (const [filePath, findings] of byFile) {
    if (findings.length < 2) continue;
    if (!opts.force && findings.some((f) => f.dedup)) {
      skippedAlready++;
      continue;
    }
    tasks.push({ filePath, findings });
  }

  if (tasks.length === 0) {
    console.log(
      `Nothing to de-duplicate. ${byFile.size} file(s) with shippable findings; none have 2+ to compare${
        skippedAlready > 0 ? ` (${skippedAlready} already de-duplicated)` : ""
      }.`,
    );
    console.log("  Pass --force to re-run de-duplication over already-processed files.");
    return;
  }

  console.log(`De-duplicating findings across ${tasks.length} file(s) in ${outputDir}`);
  console.log(`  Root:        ${rootPath}`);
  console.log(`  Provider:    ${detector.name}`);
  if (skippedAlready > 0) console.log(`  Skipped:     ${skippedAlready} already de-duplicated`);
  if (opts.force) console.log(`  Force:       cleared prior markers, recomputing`);
  if (opts.deleteDuplicates) console.log(`  Mode:        deleting duplicates (not just marking)`);
  console.log("");

  const runMeta = createRunMeta({
    type: "dedup",
    invocation: buildInvocation({ command: "dedup" }),
  });
  writeRunMeta(outputDir, runMeta);

  const startedAt = new Date();
  const fileCache = new Map<string, string | null>();
  let totalDuplicates = 0;
  let filesWithDuplicates = 0;

  // One bounded pool over files. Each file's findings belong to distinct
  // records (per agent), and different files never share a record, so
  // concurrent workers never mutate the same record. dirtyRecords /
  // counters are only touched in await-free regions.
  const concurrency = Math.max(1, opts.concurrency ?? 5);
  await runConcurrent(tasks, concurrency, async ({ filePath, findings }) => {
    let content = fileCache.get(filePath);
    if (content === undefined) {
      try {
        content = readFileSync(resolve(rootPath, filePath), "utf8");
      } catch {
        content = null;
      }
      fileCache.set(filePath, content);
    }

    try {
      const clusters = await detector.dedupeFindings({
        filePath,
        findings,
        fileContent: content ?? undefined,
        signal: dedupAbortController.signal,
      });
      const assignments = resolveDedup(findings, clusters);
      if (assignments.length === 0) {
        if (opts.verbose) console.log(`  ${filePath}: no duplicates`);
        return;
      }
      filesWithDuplicates++;
      for (const a of assignments) {
        const entry = index.get(a.id);
        if (!entry) continue;
        if (opts.deleteDuplicates) {
          entry.record.findings = entry.record.findings.filter((f) => f.id !== a.id);
        } else {
          entry.finding.dedup = {
            duplicateOf: a.duplicateOf,
            reasoning: a.reasoning,
            runId: runMeta.runId,
          };
        }
        dirtyRecords.add(entry.record);
        totalDuplicates++;
      }
      if (opts.verbose) {
        const verb = opts.deleteDuplicates ? "deleted" : "marked";
        console.log(`  ${filePath}: ${verb} ${assignments.length} duplicate(s)`);
      }
    } catch (err) {
      handleDetectorError(opts, `dedup:${filePath}`, err, dedupAbortController);
    }
  });

  // Persist dirtied records, appending a dedup-phase AnalysisRun entry.
  for (const record of dirtyRecords) {
    record.analysisHistory.push({
      runId: runMeta.runId,
      phase: "dedup",
      ranAt: new Date().toISOString(),
      durationMs: 0,
      provider: detector.name,
      agentSlugs: [record.agentSlug],
      findingCount: record.findings.length,
    });
    try {
      writeFileRecord(outputDir, record);
    } catch (err) {
      console.error(`  persist failed for ${record.filePath}: ${(err as Error).message}`);
    }
  }

  const completedAt = new Date();
  completeRun(outputDir, runMeta.runId, "done", {
    findingsCount: totalDuplicates,
    totalDurationMs: completedAt.getTime() - startedAt.getTime(),
  });

  // Re-render so the report collapses the freshly-marked duplicates.
  if (opts.summary !== false) {
    const allFindings = records.flatMap((r) => r.findings);
    const byAgent: Record<string, number> = {};
    for (const f of allFindings) {
      byAgent[f.agentSlug] = (byAgent[f.agentSlug] ?? 0) + 1;
    }
    writeMarkdownReport({
      outDir: outputDir,
      root: rootPath,
      startedAt,
      completedAt,
      findings: allFindings,
      filesScanned: records.length,
      byAgent,
      excludeFalsePositives: opts.excludeFalsePositives,
    });
  }

  const verb = opts.deleteDuplicates ? "Deleted" : "Marked";
  console.log(
    `Done. ${verb} ${totalDuplicates} duplicate(s) across ${filesWithDuplicates} file(s).`,
  );
  console.log(`  Rewrote ${dirtyRecords.size} FileRecord(s).`);
  if (opts.summary === false) {
    console.log("  Summary: skipped (--no-summary). Run `agentgg summary` to render it.");
  }
}

export function registerDedupCommand(program: Command): void {
  program
    .command("dedup")
    .description(
      "de-duplicate findings: group same-root-cause findings per file (across agents) and mark the non-primary ones",
    )
    .argument(
      "[output-dir]",
      "path to the scan's --output directory (defaults to ./scan-results)",
      "./scan-results",
    )
    .option(
      "--root <path>",
      "override the scanned root recorded in scan.json (only needed if the working copy moved)",
    )
    .option(
      "--provider <name>",
      "LLM provider for this run: anthropic | openai | ollama | bedrock | vertex (overrides saved default)",
    )
    .option("--api-key <key>", "One-shot API key (not persisted). Valid for: anthropic, openai.")
    .option(
      "--oauth-token <token>",
      "One-shot Anthropic OAuth token (sk-ant-oat…). Not persisted. Anthropic only.",
    )
    .option("--base-url <url>", "One-shot Ollama base URL (not persisted). Ollama only.")
    .option(
      "--region <name>",
      "AWS region for Bedrock (e.g. us-east-1). Falls back to $AWS_REGION / $AWS_DEFAULT_REGION. Bedrock only.",
    )
    .option("--model <name>", "One-shot model override for the selected provider (not persisted)")
    .option(
      "--delete-duplicates",
      "Physically remove duplicate findings from their FileRecords (default: keep them and only add a `dedup` marker).",
    )
    .option(
      "--exclude-false-positives",
      "Drop false-positive findings from the markdown report (default: keep them).",
    )
    .option(
      "--no-summary",
      "Skip re-rendering the markdown report after de-duplication. Markers still persist to state/files/*; render later with `agentgg summary`.",
    )
    .option(
      "--force",
      "re-run de-duplication over files that already have dedup markers (clears them first)",
    )
    .option(
      "--concurrency <n>",
      "files de-duplicated in parallel (in-flight LLM calls)",
      (v) => parseInt(v, 10),
      5,
    )
    .option("-v, --verbose", "verbose output")
    .action(async (outputDir: string, opts: DedupOpts) => {
      try {
        await runDedup(outputDir, opts);
      } catch (err) {
        console.error(`dedup failed: ${err instanceof Error ? err.message : String(err)}`);
        process.exitCode = 1;
      }
    });
}
