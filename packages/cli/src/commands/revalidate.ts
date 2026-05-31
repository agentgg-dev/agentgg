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
import { handleDetectorError } from "../diagnostics.js";
import { loadOrSynthesizeConfig, resolveDetector } from "../llm.js";
import { buildCredentialsFromOpts, validateProviderFlags } from "../providers/index.js";
import { writeMarkdownReport } from "../reporters/md.js";

interface RevalidateOpts {
  /**
   * Path to a SECURITY.md-style scope document. Two meanings, matching
   * `scan`:
   *   - with --validate: threaded into full validation; `out-of-scope`
   *     joins the usual confirmed/false-positive/uncertain verdicts.
   *   - WITHOUT --validate: triggers scope-only validation — the model
   *     never re-reads source; only `out-of-scope` is persisted.
   */
  scope?: string;
  /**
   * Force full validation (re-reads source). Without this, `--scope`
   * alone runs scope-only; absence of both runs full validation with
   * no scope context (revalidate's default).
   */
  validate?: boolean;
  provider?: string;
  apiKey?: string;
  oauthToken?: string;
  baseUrl?: string;
  region?: string;
  model?: string;
  force?: boolean;
  verbose?: boolean;
  /** Override the scanned root recorded in scan.json — rare. */
  root?: string;
  /** Max tool-use turns per validator call. */
  validateMaxTurns?: number;
  /** Drop false-positive findings from the markdown report instead of keeping them (kept by default). */
  excludeFalsePositives?: boolean;
}

/**
 * Re-run the validation phase against findings already on disk in
 * one `--output` directory. By default skips findings that already
 * have a verdict; pass `--force` to re-classify everything.
 *
 * Operates entirely off the persisted `FileRecord`s — no walker,
 * no detection phase. The source root comes from the scan-meta
 * sidecar so the user doesn't have to retype it (override with
 * `--root` if the working copy moved).
 */
export async function runRevalidate(
  outputArg: string,
  opts: RevalidateOpts,
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
    validateMaxTurns: opts.validateMaxTurns,
  });

  // Same abort-on-fatal-diagnostic pattern as scan — see scan.ts for the
  // full design note. `handleDetectorError` aborts this controller on a
  // fatal quota/auth diagnostic; sibling in-flight validator calls then
  // cancel at the SDK layer instead of churning through a dead credential.
  // Resume safety: validation only writes verdicts on the happy path of
  // each task, so cancelled findings retain their prior state.
  const revalidateAbortController = new AbortController();

  // Re-read --scope at revalidate time. Treat a missing path as fatal
  // (same fail-fast contract scan uses).
  let scopeContent: string | undefined;
  if (opts.scope) {
    const scopePath = resolve(opts.scope);
    try {
      scopeContent = readFileSync(scopePath, "utf8");
    } catch (err) {
      throw new Error(`--scope: cannot read ${scopePath}: ${(err as Error).message}`);
    }
  }

  // `--scope` without `--validate` selects the cheap scope-only path.
  // `--validate` (with or without `--scope`) selects full re-reading
  // validation. Absence of both is the historical revalidate default
  // (full validation, no scope context).
  const scopeOnlyValidate = !opts.validate && !!scopeContent;

  const records = loadAllFileRecords(outputDir);
  if (records.length === 0) {
    console.log(`No FileRecords in ${outputDir}/state/files/.`);
    console.log("  Run `agentgg scan` first to populate findings.");
    return;
  }

  // (record, finding) pairs we'll actually re-validate.
  type Task = { record: FileRecord; finding: Finding };
  const tasks: Task[] = [];
  for (const record of records) {
    for (const finding of record.findings) {
      if (!opts.force && finding.validation) continue;
      tasks.push({ record, finding });
    }
  }

  if (tasks.length === 0) {
    console.log(
      `Nothing to revalidate. ${records.length} file(s) on disk; every finding already has a verdict.`,
    );
    console.log("  Pass --force to re-classify every finding.");
    return;
  }

  console.log(`Revalidating ${tasks.length} finding(s) in ${outputDir}`);
  console.log(`  Root:        ${rootPath}`);
  console.log(`  Provider:    ${detector.name}`);
  if (scopeContent) console.log(`  Scope:       ${opts.scope}`);
  if (scopeOnlyValidate) {
    console.log(
      `  Mode:        scope-only (file content not read; only out-of-scope verdicts persisted)`,
    );
  } else {
    console.log(`  Mode:        full${scopeContent ? " (with scope context)" : ""}`);
  }
  if (opts.force) console.log(`  Force:       re-classifying everything`);
  console.log("");

  const runMeta = createRunMeta({ type: "validate" });
  writeRunMeta(outputDir, runMeta);

  const startedAt = new Date();
  const verdicts: Record<string, number> = {};
  const fileCache = new Map<string, string | null>();
  // Track which records actually changed so we don't rewrite every
  // FileRecord on disk for no reason.
  const dirtyRecords = new Set<FileRecord>();

  // Sequential — one finding at a time so each verdict lands
  // before the next call starts. Validation is the per-report step;
  // parallelism would only tangle progress and rate-limit pressure.
  await runConcurrent(tasks, 1, async ({ record, finding }) => {
    // Scope-only branch: never read the file, only ask the LLM to
    // classify against the scope document, and only persist when the
    // verdict is `out-of-scope`. In-scope/uncertain results are logged
    // but the finding's validation field is left untouched so a
    // follow-up full `revalidate` can still assess technical merit.
    if (scopeOnlyValidate) {
      try {
        const result = await detector.validateFindingByScope({
          finding,
          scope: scopeContent!,
          signal: revalidateAbortController.signal,
        });
        verdicts[result.verdict] = (verdicts[result.verdict] ?? 0) + 1;
        if (result.verdict === "out-of-scope") {
          finding.validation = {
            verdict: result.verdict,
            reasoning: result.reasoning,
          };
          dirtyRecords.add(record);
        }
        if (opts.verbose) {
          const note =
            result.verdict === "out-of-scope"
              ? "marked out-of-scope"
              : "kept (scope did not disqualify)";
          console.log(`  ${finding.filePath} (${finding.id}): ${result.verdict} — ${note}`);
        }
      } catch (err) {
        handleDetectorError(opts, `scope-validate:${finding.id}`, err, revalidateAbortController);
      }
      return;
    }

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
      const result = await detector.validateFinding({
        finding,
        fileContent: content,
        scope: scopeContent,
        signal: revalidateAbortController.signal,
      });
      // Mutate in place — the record points to the same Finding
      // object we got from loadAllFileRecords.
      finding.validation = {
        verdict: result.verdict,
        reasoning: result.reasoning,
      };
      verdicts[result.verdict] = (verdicts[result.verdict] ?? 0) + 1;
      dirtyRecords.add(record);
      if (opts.verbose) {
        console.log(`  ${finding.filePath} (${finding.id}): ${result.verdict}`);
      }
    } catch (err) {
      handleDetectorError(opts, `validate:${finding.id}`, err, revalidateAbortController);
    }
  });

  // Write dirtied records back. Append a validate-phase AnalysisRun
  // entry so the history reflects this revalidate pass.
  for (const record of dirtyRecords) {
    const validatedHere = record.findings.filter((f) => f.validation);
    record.analysisHistory.push({
      runId: runMeta.runId,
      phase: "validate",
      ranAt: new Date().toISOString(),
      durationMs: 0,
      provider: detector.name,
      agentSlugs: Array.from(new Set(validatedHere.map((f) => f.agentSlug))),
      findingCount: validatedHere.length,
    });
    record.status = "validated";
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

  // Re-render the per-finding markdown + summary so the on-disk
  // reports reflect the new verdicts. Without this, `findings/*.md`
  // keeps showing "Validation: _not run_" even though the underlying
  // FileRecord has the verdict.
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

  const summary = Object.entries(verdicts)
    .sort()
    .map(([v, n]) => `${v}=${n}`)
    .join(", ");
  console.log(`Done. Verdicts: ${summary || "(none)"}`);
  console.log(`  Rewrote ${dirtyRecords.size} FileRecord(s).`);
}

export function registerRevalidateCommand(program: Command): void {
  program
    .command("revalidate")
    .description("re-run the validation phase against persisted findings in an --output directory")
    .argument(
      "[output-dir]",
      "path to the scan's --output directory (defaults to ./scan-results)",
      "./scan-results",
    )
    .option(
      "--scope <path>",
      "path to a SECURITY.md-style scope file. With --validate, scope rules are threaded into the full classifier (verdicts include `out-of-scope`). WITHOUT --validate, triggers scope-only validation: the model never re-reads the source and only persists `out-of-scope` verdicts (cheap pre-filter).",
    )
    .option(
      "--validate",
      "force full validation (re-reads source) even when --scope is set. Without this, `--scope` alone selects the cheap scope-only path; absence of both runs full validation with no scope context.",
    )
    .option(
      "--root <path>",
      "override the scanned root recorded in scan.json (only needed if the working copy moved)",
    )
    .option(
      "--provider <name>",
      "LLM provider for this run: anthropic | openai | ollama | bedrock (overrides saved default)",
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
      "--validate-max-turns <n>",
      "Max tool-use turns per validator call (default: 30). Bump if the validator hits the turn cap.",
      (v) => parseInt(v, 10),
      30,
    )
    .option(
      "--exclude-false-positives",
      "Drop false-positive findings from the markdown report (default: keep them). FP findings always stay in state/files/* regardless.",
    )
    .option("--force", "re-validate findings that already have a verdict (default: skip them)")
    .option("-v, --verbose", "verbose output")
    .action(async (outputDir: string, opts: RevalidateOpts) => {
      try {
        await runRevalidate(outputDir, opts);
      } catch (err) {
        console.error(`revalidate failed: ${err instanceof Error ? err.message : String(err)}`);
        // See scan.ts comment — let the event loop drain so libuv can
        // close in-flight subprocess handles cleanly on Windows.
        process.exitCode = 1;
      }
    });
}
