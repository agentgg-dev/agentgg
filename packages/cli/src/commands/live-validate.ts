import { resolve } from "node:path";
import type { Finding, Provider } from "@agentgg/core";
import {
  completeRun,
  createRunMeta,
  loadAllFileRecords,
  readScanMeta,
  writeRunMeta,
} from "@agentgg/core";
import type { Command } from "commander";
import { loadOrSynthesizeConfig, resolveDetector } from "../llm.js";
import { logError } from "../log.js";
import {
  buildCredentialsFromOpts,
  REGION_FLAG_HELP,
  validateProviderFlags,
} from "../providers/index.js";
import { writeMarkdownReport } from "../reporters/md.js";
import { runReproducePhase } from "../validation/reproduce.js";
import { DEFAULT_SANDBOX_IMAGE } from "../validation/sandbox.js";
import { parseTargetAuth } from "../validation/target-auth.js";
import { buildInvocation } from "./invocation.js";

interface LiveValidateOpts {
  targetUrl: string;
  targetCredentials?: string;
  targetContext?: string;
  targetImage?: string;
  reproduceTimeout?: number;
  reproduceBudget?: number;
  reproduceMax?: number;
  reproduceMaxTurns?: number;
  force?: boolean;
  provider?: string;
  apiKey?: string;
  oauthToken?: string;
  baseUrl?: string;
  region?: string;
  model?: string;
  verbose?: boolean;
}

/**
 * Re-run only the reproduce sub-phase against findings already on disk in
 * one `--output` directory — the standalone counterpart to `scan
 * --live-validate`, for reproducing against a target that wasn't up yet
 * (or with different credentials) when the scan ran.
 */
export async function runLiveValidate(
  outputArg: string,
  opts: LiveValidateOpts,
  env: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  const outputDir = resolve(outputArg);
  const scanMeta = readScanMeta(outputDir);
  if (!scanMeta) {
    throw new Error(
      `No scan state at ${outputDir}. Run \`agentgg scan <path> -o ${outputArg}\` first.`,
    );
  }

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

  const records = loadAllFileRecords(outputDir);
  if (records.length === 0) {
    console.log(`No FileRecords in ${outputDir}/state/files/.`);
    console.log("  Run `agentgg scan` first to populate findings.");
    return;
  }
  const findings: Finding[] = records.flatMap((r) => r.findings);

  const runMeta = createRunMeta({
    type: "validate",
    invocation: buildInvocation({ command: "live-validate" }),
  });
  writeRunMeta(outputDir, runMeta);

  console.log(`Live validation: ${outputDir}`);
  console.log(`  Target:   ${opts.targetUrl}`);
  console.log(`  Provider: ${detector.name}`);
  console.log("");

  const startedAt = new Date();
  const abortController = new AbortController();
  await runReproducePhase({
    findings,
    detector,
    outDir: outputDir,
    targetUrl: opts.targetUrl,
    auth: parseTargetAuth(opts),
    context: opts.targetContext,
    image: opts.targetImage ?? DEFAULT_SANDBOX_IMAGE,
    timeoutMs: Number(opts.reproduceTimeout ?? 300) * 1000,
    budgetMs: Number(opts.reproduceBudget ?? 1800) * 1000,
    max: Number(opts.reproduceMax ?? 50),
    reproduceMaxTurns: Number(opts.reproduceMaxTurns ?? 50),
    force: opts.force ?? false,
    signal: abortController.signal,
  });
  const completedAt = new Date();

  completeRun(outputDir, runMeta.runId, "done", {
    findingsCount: findings.length,
    totalDurationMs: completedAt.getTime() - startedAt.getTime(),
  });

  // Re-render the report so findings/*.md and summary.md pick up the new
  // live results — runReproducePhase already persisted each finding
  // incrementally to state/files/*.
  const byAgent: Record<string, number> = {};
  for (const f of findings) byAgent[f.agentSlug] = (byAgent[f.agentSlug] ?? 0) + 1;
  writeMarkdownReport({
    outDir: outputDir,
    root: scanMeta.root,
    startedAt,
    completedAt,
    findings,
    filesScanned: records.length,
    byAgent,
  });

  console.log("Done. Report re-rendered with the new live results.");
}

export function registerLiveValidateCommand(program: Command): void {
  program
    .command("live-validate")
    .description(
      "re-run only the live-validation reproduce phase against persisted findings in an --output directory",
    )
    .argument(
      "[output-dir]",
      "path to the scan's --output directory (defaults to ./scan-results)",
      "./scan-results",
    )
    .requiredOption(
      "--target-url <url>",
      "Root URL of the already-running application to validate against.",
    )
    .option(
      "--target-credentials <cred>",
      "Login for the target: `user:pass`, or `@path/to/creds.json` ({ username, password }). Redacted from any stored reasoning.",
    )
    .option(
      "--target-context <ctx>",
      "Free-form scope/context notes folded into the reproduce prompt (e.g. which flows are in scope).",
    )
    .option(
      "--target-image <ref>",
      `Sandbox image tag hosting Playwright + the MCP server. Defaults to the pinned ${DEFAULT_SANDBOX_IMAGE}.`,
    )
    .option(
      "--reproduce-timeout <s>",
      "Per-finding reproduction timeout in seconds (default 300).",
      (v) => parseInt(v, 10),
      300,
    )
    .option(
      "--reproduce-budget <s>",
      "Whole-phase reproduction budget in seconds; the phase stops cleanly once exceeded (default 1800).",
      (v) => parseInt(v, 10),
      1800,
    )
    .option(
      "--reproduce-max <n>",
      "Max findings to reproduce in one run (default 50).",
      (v) => parseInt(v, 10),
      50,
    )
    .option(
      "--reproduce-max-turns <n>",
      "Max browser steps per finding (default 50). Raise it for a target with multi-step flows.",
      (v) => parseInt(v, 10),
      50,
    )
    .option(
      "--force",
      "Re-reproduce web-reachable findings that already have a live-validation verdict.",
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
    .option("--region <name>", REGION_FLAG_HELP)
    .option("--model <name>", "One-shot model override for the selected provider (not persisted)")
    .option("-v, --verbose", "verbose output")
    .action(async (outputDir: string, opts: LiveValidateOpts) => {
      try {
        await runLiveValidate(outputDir, opts);
      } catch (err) {
        logError(`live-validate failed: ${err instanceof Error ? err.message : String(err)}`);
        process.exitCode = 1;
      }
    });
}
