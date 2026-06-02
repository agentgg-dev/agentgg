import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { FileRecord, Finding } from "@agentgg/core";
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
import { handleDetectorError } from "../diagnostics.js";
import { type CredentialOverrides, loadOrSynthesizeConfig, resolveDetector } from "../llm.js";
import { findingFilenameSlug, writeMarkdownReport } from "../reporters/md.js";
import { buildInvocation } from "./invocation.js";

interface ScoreOpts {
  provider?: string;
  apiKey?: string;
  oauthToken?: string;
  baseUrl?: string;
  model?: string;
  /** Re-score findings that already carry a CVSS score on disk. */
  force?: boolean;
  /**
   * Include findings the validator marked false-positive / out-of-scope.
   * Off by default — same logic as the in-scan phase: don't pay tokens
   * scoring findings that won't ship.
   */
  includeDisqualified?: boolean;
  /** Drop false-positive findings from the markdown report (kept by default). */
  excludeFalsePositives?: boolean;
  verbose?: boolean;
  /** Override the scanned root recorded in scan.json — rare. */
  root?: string;
  /**
   * `--no-summary` → `summary: false`. Skip re-rendering the markdown report
   * (`summary.md` + `findings/*.md`) after scoring. Scores are still persisted
   * to `state/files/*`; render later with `agentgg summary`. Commander
   * defaults this to `true`; the bare flag sets it `false`.
   */
  summary?: boolean;
  /** Findings scored in parallel (in-flight LLM calls). Default 5. */
  concurrency?: number;
}

/**
 * Stand-alone scoring command — pick CVSS 3.1 metrics for every
 * confirmed/uncertain finding on disk, assemble the full `CvssScore`
 * deterministically from those metrics, and write it back into the
 * per-file FileRecord. Mirrors `revalidate` in shape so the two
 * post-scan passes feel symmetric.
 *
 * By default skips findings that already have `cvss`. Pass `--force`
 * to redo them. By default skips findings the validator disqualified
 * (false-positive / out-of-scope); pass `--include-disqualified` to
 * score them anyway (useful when you want a score column for *every*
 * finding regardless of verdict).
 */
export async function runScore(
  outputArg: string,
  opts: ScoreOpts,
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
  const credentials: CredentialOverrides = {
    ...(opts.apiKey ? { anthropicApiKey: opts.apiKey, openaiApiKey: opts.apiKey } : {}),
    ...(opts.oauthToken ? { anthropicOauthToken: opts.oauthToken } : {}),
    ...(opts.baseUrl ? { ollamaBaseUrl: opts.baseUrl } : {}),
  };
  const detector = resolveDetector(config, {
    provider: opts.provider,
    model: opts.model,
    credentials,
    verbose: opts.verbose,
  });

  // See scan.ts for the design note. On a fatal quota / auth diagnostic,
  // sibling in-flight scoring calls cancel at the SDK layer.
  const scoreAbortController = new AbortController();

  const records = loadAllFileRecords(outputDir);
  if (records.length === 0) {
    console.log(`No FileRecords in ${outputDir}/state/files/.`);
    console.log("  Run `agentgg scan` first to populate findings.");
    return;
  }

  const isDisqualified = (f: Finding): boolean => {
    const v = f.validation?.verdict;
    return v === "false-positive" || v === "out-of-scope";
  };

  type Task = { record: FileRecord; finding: Finding };
  const tasks: Task[] = [];
  let skippedHasScore = 0;
  let skippedDisq = 0;
  for (const record of records) {
    for (const finding of record.findings) {
      if (!opts.force && finding.cvss) {
        skippedHasScore++;
        continue;
      }
      if (!opts.includeDisqualified && isDisqualified(finding)) {
        skippedDisq++;
        continue;
      }
      tasks.push({ record, finding });
    }
  }

  if (tasks.length === 0) {
    console.log(
      `Nothing to score. ${records.length} file(s) on disk; ${skippedHasScore} already scored, ${skippedDisq} disqualified by validation.`,
    );
    console.log(
      "  Pass --force to rescore everything, --include-disqualified to include FP/out-of-scope findings.",
    );
    return;
  }

  console.log(`Scoring ${tasks.length} finding(s) in ${outputDir}`);
  console.log(`  Root:        ${rootPath}`);
  console.log(`  Provider:    ${detector.name}`);
  if (skippedHasScore > 0) console.log(`  Skipped:     ${skippedHasScore} already scored`);
  if (skippedDisq > 0) console.log(`  Skipped:     ${skippedDisq} FP/out-of-scope`);
  if (opts.force) console.log(`  Force:       re-scoring everything`);
  console.log("");

  const runMeta = createRunMeta({
    type: "scan",
    invocation: buildInvocation({ command: "score" }),
  });
  writeRunMeta(outputDir, runMeta);

  const startedAt = new Date();
  const buckets: Record<string, number> = {};
  const fileCache = new Map<string, string | null>();
  const dirtyRecords = new Set<FileRecord>();

  // One bounded pool over findings, same as revalidate. Each finding is a
  // distinct object; buckets, fileCache, and dirtyRecords are only touched
  // in await-free regions, so concurrent workers can't race.
  const concurrency = Math.max(1, opts.concurrency ?? 5);
  await runConcurrent(tasks, concurrency, async ({ record, finding }) => {
    const absPath = resolve(rootPath, finding.filePath);
    let content = fileCache.get(finding.filePath);
    if (content === undefined) {
      try {
        content = readFileSync(absPath, "utf8");
      } catch {
        content = null;
      }
      fileCache.set(finding.filePath, content);
    }
    if (content === null) {
      if (opts.verbose) {
        console.log(`  skip ${finding.filePath}: file not readable`);
      }
      return;
    }
    try {
      const cvss = await detector.scoreFinding({
        finding,
        fileContent: content,
        signal: scoreAbortController.signal,
      });
      // Mutate in place — the record holds the same Finding object.
      finding.cvss = cvss;
      finding.severity = cvss.severity;
      buckets[cvss.severity] = (buckets[cvss.severity] ?? 0) + 1;
      dirtyRecords.add(record);
      if (opts.verbose) {
        const loc = finding.lineRange ? `:${finding.lineRange[0]}` : "";
        console.log(
          `  ${cvss.severity.padEnd(8)} ${cvss.baseScore.toFixed(1).padStart(4)}  ${findingFilenameSlug(finding)}  ${finding.filePath}${loc}`,
        );
      }
    } catch (err) {
      handleDetectorError(opts, `score:${finding.id}`, err, scoreAbortController);
    }
  });

  for (const record of dirtyRecords) {
    const scoredHere = record.findings.filter((f) => f.cvss);
    record.analysisHistory.push({
      runId: runMeta.runId,
      phase: "detect",
      ranAt: new Date().toISOString(),
      durationMs: 0,
      provider: detector.name,
      agentSlugs: Array.from(new Set(scoredHere.map((f) => f.agentSlug))),
      findingCount: scoredHere.length,
    });
    try {
      writeFileRecord(outputDir, record);
    } catch (err) {
      console.error(`  persist failed for ${record.filePath}: ${(err as Error).message}`);
    }
  }

  const completedAt = new Date();
  completeRun(outputDir, runMeta.runId, "done", {
    findingsCount: tasks.length,
    totalDurationMs: completedAt.getTime() - startedAt.getTime(),
  });

  // Re-render reports so `findings/*.md` and `summary.md` reflect the
  // new scores. Mirrors the post-revalidate re-render. `--no-summary`
  // skips it — scores are already persisted to state/files/*, so
  // `agentgg summary` can render the report later.
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

  const summary = Object.entries(buckets)
    .sort()
    .map(([s, n]) => `${s}=${n}`)
    .join(", ");
  console.log(`Done. Severity: ${summary || "(none)"}`);
  console.log(`  Rewrote ${dirtyRecords.size} FileRecord(s).`);
  if (opts.summary === false) {
    console.log("  Summary: skipped (--no-summary). Run `agentgg summary` to render it.");
  }
}

export function registerScoreCommand(program: Command): void {
  program
    .command("score")
    .description(
      "run the CVSS 3.1 scoring phase against persisted findings in an --output directory",
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
      "LLM provider for this run: anthropic | openai | ollama (overrides saved default)",
    )
    .option("--api-key <key>", "One-shot API key for the selected provider (not persisted).")
    .option("--oauth-token <token>", "One-shot Anthropic OAuth token (sk-ant-oat…). Not persisted.")
    .option("--base-url <url>", "One-shot Ollama base URL (not persisted)")
    .option("--model <name>", "One-shot model override for the selected provider (not persisted)")
    .option("--force", "re-score findings that already carry a CVSS score (default: skip them)")
    .option(
      "--include-disqualified",
      "score findings the validator marked false-positive or out-of-scope (default: skip them)",
    )
    .option(
      "--exclude-false-positives",
      "Drop false-positive findings from the markdown report (default: keep them).",
    )
    .option(
      "--no-summary",
      "Skip re-rendering the markdown report (summary.md + findings/*.md) after scoring. Scores still persist to state/files/*; render later with `agentgg summary`.",
    )
    .option(
      "--concurrency <n>",
      "findings scored in parallel (in-flight LLM calls)",
      (v) => parseInt(v, 10),
      5,
    )
    .option("-v, --verbose", "verbose output")
    .action(async (outputDir: string, opts: ScoreOpts) => {
      try {
        await runScore(outputDir, opts);
      } catch (err) {
        console.error(`score failed: ${err instanceof Error ? err.message : String(err)}`);
        // See scan.ts comment — let the event loop drain so libuv can
        // close in-flight subprocess handles cleanly on Windows.
        process.exitCode = 1;
      }
    });
}
