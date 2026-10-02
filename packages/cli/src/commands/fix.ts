import { resolve } from "node:path";
import type { Provider } from "@agentgg/core";
import {
  completeRun,
  createRunMeta,
  loadAllFileRecords,
  readScanMeta,
  writeRunMeta,
} from "@agentgg/core";
import type { Command } from "commander";
import { runFixPhase, selectForFix } from "../fix-phase.js";
import { loadOrSynthesizeConfig, resolveDetector } from "../llm.js";
import { logError } from "../log.js";
import {
  buildCredentialsFromOpts,
  REGION_FLAG_HELP,
  validateProviderFlags,
} from "../providers/index.js";
import { writeMarkdownReport } from "../reporters/md.js";
import { createUsageMeter } from "../usage-meter.js";
import { buildInvocation } from "./invocation.js";

interface FixOpts {
  provider?: string;
  apiKey?: string;
  oauthToken?: string;
  baseUrl?: string;
  region?: string;
  project?: string;
  model?: string;
  /** `--openrouter-routing`: see the twin option on `scan`. */
  openrouterRouting?: string;
  /** Write a fix again for findings that already carry one. */
  force?: boolean;
  /** Drop false-positive findings from the markdown report (kept by default). */
  excludeFalsePositives?: boolean;
  verbose?: boolean;
  /** Override the scanned root recorded in scan.json — rare. */
  root?: string;
  /** `--no-summary` → `summary: false`. Skip re-rendering the markdown report. */
  summary?: boolean;
  /** Findings fixed in parallel (in-flight LLM calls). Default 5. */
  concurrency?: number;
}

/**
 * Stand-alone fix command — write a suggested fix for every confirmed
 * primary on disk. Same selection as the in-scan phase, so it is the way
 * to fill in fixes after `revalidate` or `live-validate` changed a
 * verdict. It writes report text only; the scanned source is never
 * modified.
 */
export async function runFix(
  outputArg: string,
  opts: FixOpts,
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
  const detector = resolveDetector(config, {
    provider: opts.provider,
    model: opts.model,
    credentials: buildCredentialsFromOpts(opts),
    verbose: opts.verbose,
    openrouterRouting: opts.openrouterRouting,
  });

  const records = loadAllFileRecords(outputDir);
  const findings = records.flatMap((r) => r.findings);
  const work = selectForFix(findings, opts.force);
  if (work.length === 0) {
    const fixed = findings.filter((f) => f.suggestedFix).length;
    console.log(
      `Nothing to fix. ${findings.length} finding(s) on disk; ${fixed} already have a fix. Only confirmed findings get one.`,
    );
    if (fixed > 0) console.log("  Pass --force to write the fixes again.");
    return;
  }

  console.log(`Suggested fixes for ${outputDir}`);
  console.log(`  Root:        ${rootPath}`);
  console.log(`  Provider:    ${detector.name}`);
  if (opts.force) console.log(`  Force:       writing every fix again`);

  const runMeta = createRunMeta({
    type: "scan",
    invocation: buildInvocation({ command: "fix" }),
  });
  writeRunMeta(outputDir, runMeta);

  const usageMeter = createUsageMeter(outputDir, detector.name);
  detector.attachUsageMeter?.(usageMeter);

  const startedAt = new Date();
  const { fatal } = await runFixPhase({
    findings,
    detector,
    outDir: outputDir,
    root: rootPath,
    runId: runMeta.runId,
    concurrency: Math.max(1, opts.concurrency ?? 5),
    verbose: opts.verbose,
    force: opts.force,
  });

  const completedAt = new Date();
  completeRun(outputDir, runMeta.runId, fatal ? "error" : "done", {
    findingsCount: work.length,
    totalDurationMs: completedAt.getTime() - startedAt.getTime(),
  });
  usageMeter.flush();

  // Rendered even after a fatal error: the fixes written before it are on
  // disk, and the report should show them.
  if (opts.summary === false) {
    console.log("  Summary: skipped (--no-summary). Run `agentgg summary` to render it.");
  } else {
    const byAgent: Record<string, number> = {};
    for (const f of findings) byAgent[f.agentSlug] = (byAgent[f.agentSlug] ?? 0) + 1;
    writeMarkdownReport({
      outDir: outputDir,
      root: rootPath,
      startedAt,
      completedAt,
      findings,
      filesScanned: records.length,
      byAgent,
      excludeFalsePositives: opts.excludeFalsePositives,
    });
  }
  if (fatal) throw fatal;
}

export function registerFixCommand(program: Command): void {
  program
    .command("fix")
    .description(
      "write a suggested fix into the report of each confirmed finding in an --output directory (does not change source code)",
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
      "LLM provider for this run: anthropic | openai | ollama | bedrock | vertex | openrouter (overrides saved default)",
    )
    .option(
      "--api-key <key>",
      "One-shot API key (not persisted). Valid for: anthropic, openai, openrouter.",
    )
    .option(
      "--oauth-token <token>",
      "One-shot Anthropic OAuth token (sk-ant-oat…). Not persisted. Anthropic only.",
    )
    .option("--base-url <url>", "One-shot Ollama base URL (not persisted). Ollama only.")
    .option("--region <name>", REGION_FLAG_HELP)
    .option(
      "--project <id>",
      "GCP project ID for Vertex AI. Falls back to $GOOGLE_CLOUD_PROJECT / $GCLOUD_PROJECT. Vertex only.",
    )
    .option("--model <name>", "One-shot model override for the selected provider (not persisted)")
    .option(
      "--openrouter-routing <json|file>",
      "OpenRouter provider-routing block, overriding OPENROUTER_* env for this run: inline JSON (must start with {) or a path to a .json file (avoids shell-quoting JSON on Windows). Invalid JSON aborts before any LLM call. OpenRouter only.",
    )
    .option("--force", "write a fix again for findings that already have one (default: skip them)")
    .option(
      "--exclude-false-positives",
      "Drop false-positive findings from the markdown report (default: keep them).",
    )
    .option(
      "--no-summary",
      "Skip re-rendering the markdown report (summary.md + findings/*.md). Fixes still persist to state/files/*; render later with `agentgg summary`.",
    )
    .option(
      "--concurrency <n>",
      "findings fixed in parallel (in-flight LLM calls)",
      (v) => parseInt(v, 10),
      5,
    )
    .option("-v, --verbose", "verbose output")
    .action(async (outputDir: string, opts: FixOpts) => {
      try {
        await runFix(outputDir, opts);
      } catch (err) {
        logError(`fix failed: ${err instanceof Error ? err.message : String(err)}`);
        // See scan.ts comment — let the event loop drain so libuv can
        // close in-flight subprocess handles cleanly on Windows.
        process.exitCode = 1;
      }
    });
}
