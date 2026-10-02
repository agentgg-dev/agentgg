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
import { loadAllAgents } from "../agent-catalog.js";
import { loadOrSynthesizeConfig, resolveDetector } from "../llm.js";
import { logError } from "../log.js";
import {
  buildCredentialsFromOpts,
  REGION_FLAG_HELP,
  validateProviderFlags,
} from "../providers/index.js";
import { writeMarkdownReport } from "../reporters/md.js";
import { notLiveReproducible, proofRuleMap } from "../validation/proof-rules.js";
import { runReproducePhase } from "../validation/reproduce.js";
import { attachFromOpts, DEFAULT_SANDBOX_IMAGE } from "../validation/sandbox.js";
import { readTargetContext } from "../validation/target-context.js";
import { buildInvocation } from "./invocation.js";

interface LiveValidateOpts {
  targetUrl: string;
  targetContext?: string;
  targetImage?: string;
  sandboxEndpoint?: string;
  sandboxControl?: string;
  reproduceTimeout?: number;
  reproduceMaxTurns?: number;
  force?: boolean;
  provider?: string;
  apiKey?: string;
  oauthToken?: string;
  baseUrl?: string;
  region?: string;
  project?: string;
  model?: string;
  /** `--openrouter-routing`: see the twin option on `scan`. */
  openrouterRouting?: string;
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
  // Fail fast on a missing $AGENTGG_SANDBOX_TOKEN or bad --sandbox-endpoint
  // before any LLM/catalog work runs below, not only once the reproduce
  // phase itself starts.
  const attach = attachFromOpts(opts, env);

  const config = loadOrSynthesizeConfig(env, opts.provider);
  const activeProvider = (opts.provider ?? config.provider) as Provider;
  validateProviderFlags(activeProvider, opts);
  const credentials = buildCredentialsFromOpts(opts);
  const detector = resolveDetector(config, {
    provider: opts.provider,
    model: opts.model,
    credentials,
    verbose: opts.verbose,
    openrouterRouting: opts.openrouterRouting,
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

  // A finding carries only `agentSlug`, so resolve its reporting agent from
  // the catalog to pick up an agent-authored `liveProofRule`, exactly as
  // `scan --live-validate` does. A catalog that fails to load leaves the map
  // empty and every finding runs on the proof principle alone.
  let agentProofRules = new Map<string, string>();
  let skipLive = new Set<string>();
  try {
    const catalogAgents = loadAllAgents().agents;
    agentProofRules = proofRuleMap(catalogAgents);
    skipLive = notLiveReproducible(catalogAgents);
  } catch (err) {
    logError(`Could not load agents, using the proof principle alone: ${(err as Error).message}`);
  }

  const startedAt = new Date();
  const abortController = new AbortController();
  await runReproducePhase({
    findings,
    detector,
    outDir: outputDir,
    runId: runMeta.runId,
    targetUrl: opts.targetUrl,
    context: readTargetContext(opts.targetContext),
    image: opts.targetImage ?? DEFAULT_SANDBOX_IMAGE,
    timeoutMs: Number(opts.reproduceTimeout ?? 600) * 1000,
    reproduceMaxTurns: Number(opts.reproduceMaxTurns ?? 50),
    agentProofRules,
    notLiveReproducible: skipLive,
    force: opts.force ?? false,
    attach,
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
      "--target-context <ctx>",
      "Free-form notes for the reproduce prompt, or @path/to/file. Put the target login here, for example the account to sign in with.",
    )
    .option(
      "--target-image <ref>",
      `Sandbox image tag hosting Playwright + the MCP server. Defaults to the pinned ${DEFAULT_SANDBOX_IMAGE}.`,
    )
    .option(
      "--sandbox-endpoint <url>",
      "Attach to an already-running sandbox's MCP server (e.g. http://127.0.0.1:8931) instead of starting Docker. Reads the control token from $AGENTGG_SANDBOX_TOKEN.",
    )
    .option(
      "--sandbox-control <url>",
      "Control server of the attached sandbox (default: same host, port 8932).",
    )
    .option(
      "--reproduce-timeout <s>",
      "Per-finding reproduction timeout in seconds (default 600). A backstop only: the turn cap (--reproduce-max-turns) is meant to end a run first, because it stops cleanly with a verdict, while a timeout aborts and keeps no evidence.",
      (v) => parseInt(v, 10),
      600,
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
      "LLM provider for this run: anthropic | openai | ollama | bedrock | openrouter (overrides saved default)",
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
