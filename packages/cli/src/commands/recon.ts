import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import type { Agent, Provider } from "@agentgg/core";
import {
  completeRun,
  createRunMeta,
  fingerprint,
  getOfficialAgentsDir,
  upsertScanMeta,
  writeRunMeta,
  writeScanPlan,
} from "@agentgg/core";
import type { Command } from "commander";
import { loadAllAgents } from "../agent-catalog.js";
import { installOfficialAgents } from "../agents-install.js";
import { loadOrSynthesizeConfig, resolveDetector } from "../llm.js";
import { selectAgents } from "../precondition.js";
import { buildCredentialsFromOpts, validateProviderFlags } from "../providers/index.js";
import { runRecon } from "../recon.js";
import { resolveTemplates } from "../template.js";
import { DEFAULT_EXCLUDES, type WalkConfig } from "../walker.js";
import { buildInvocation } from "./invocation.js";

interface ReconOpts {
  output?: string;
  provider?: string;
  apiKey?: string;
  oauthToken?: string;
  baseUrl?: string;
  region?: string;
  project?: string;
  model?: string;
  concurrency?: number;
  template?: string[];
  exclude?: string[];
  only?: string[];
  maxFileSize?: number; // KB
  defaultExcludes?: boolean;
  maxTurns?: number;
  /** Re-run recon even when a cached brief exists for this output dir. */
  reRecon?: boolean;
  verbose?: boolean;
}

/**
 * Stand-alone recon command — runs only the first two phases of a scan:
 *
 *   1. recon  — the high-level project brief (`state/recon.json`)
 *   2. plan   — evaluate every selected agent's precondition and record
 *               which are queued vs skipped (`state/plan.json`)
 *
 * No detection runs. This is the durable plan→run hand-off: a distributed
 * runner can compute the plan here, then dispatch the queued agents
 * elsewhere. Locally it's a cheap dry-run that shows what a `scan` with the
 * same flags would actually execute — and because the recon brief is cached
 * by `reconHash`, a follow-up `scan` against the same `--output` reuses this
 * brief instead of paying for the survey twice.
 */
export async function runReconCommand(
  rootArg: string,
  opts: ReconOpts,
  env: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  const root = resolve(rootArg);
  const outDir = resolve(opts.output ?? "./scan-results/");

  // Record the scanned root so a later `scan` / `revalidate` / `summary`
  // against this output dir can resolve relative paths without retyping it.
  upsertScanMeta(outDir, root);
  const runMeta = createRunMeta({
    type: "scan",
    invocation: buildInvocation({ command: "recon" }),
  });
  writeRunMeta(outDir, runMeta);

  const reconAbortController = new AbortController();
  let runFinalized = false;

  // SIGINT (Ctrl+C) / SIGTERM handler: stamp the run as errored on disk.
  // SIGTERM matters when this CLI runs inside a Cloud Run Job — cancel
  // sends SIGTERM, and without this Node's default would exit silently,
  // leaving the run sidecar stuck at `phase: "running"`.
  const shutdownHandler = (signal: NodeJS.Signals) => {
    if (!runFinalized) {
      runFinalized = true;
      try {
        completeRun(outDir, runMeta.runId, "error", {});
      } catch {
        // best-effort
      }
      console.error(`\nInterrupted (${signal}). Partial state persisted; re-run to resume.`);
    }
    process.exit(signal === "SIGTERM" ? 143 : 130);
  };
  process.on("SIGINT", shutdownHandler);
  process.on("SIGTERM", shutdownHandler);

  try {
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

    // Mirror `scan`: auto-install the official agent library on first use.
    if (!existsSync(getOfficialAgentsDir(env))) {
      process.stdout.write("[INF] agentgg-agents are not installed, installing...\n");
      try {
        const { version, count } = await installOfficialAgents(env);
        process.stdout.write(
          `[INF] Successfully installed agentgg-agents at ~/.agentgg/agentgg-agents (${count} agents, ${version})\n`,
        );
      } catch (err) {
        process.stderr.write(`[WRN] Could not auto-install agents: ${(err as Error).message}\n`);
      }
    }

    const catalog = loadAllAgents(env);
    for (const e of catalog.errors) console.warn(`warning: ${e}`);

    const officialAgentsDir = getOfficialAgentsDir(env);
    const templateInputs = opts.template ?? [];
    const baseDir = join(officialAgentsDir, "base");
    const selectedAgents: Agent[] =
      templateInputs.length > 0
        ? resolveTemplates(templateInputs, catalog.agents, officialAgentsDir)
        : existsSync(baseDir)
          ? resolveTemplates([baseDir], catalog.agents, officialAgentsDir)
          : catalog.agents;
    if (selectedAgents.length === 0) {
      throw new Error("No agents selected — nothing to plan.");
    }

    const project = fingerprint(root);

    const excludePatterns = [...(opts.exclude ?? [])];
    const includePatterns = opts.only ?? [];
    const maxFileSizeBytes = (opts.maxFileSize ?? 500) * 1024;
    const walkExcludes =
      opts.defaultExcludes === false
        ? [...excludePatterns]
        : [...DEFAULT_EXCLUDES, ...excludePatterns];
    const walkCfg: WalkConfig = {
      excludePatterns: walkExcludes,
      includePatterns,
      maxFileSizeBytes,
    };

    console.log(`Recon + plan for ${root}`);
    console.log(`Agents selected: ${selectedAgents.length}`);
    console.log(`Provider: ${detector.name}`);
    if (templateInputs.length > 0) {
      console.log(`Template filter: ${templateInputs.join(", ")}`);
    }
    console.log("");

    // -------- PHASE 1 — recon --------
    console.log("[1/2] Recon — surveying the project…");
    const recon = await runRecon({
      rootDir: root,
      outDir,
      detector,
      fingerprintTags: project.tags,
      excludePatterns: walkExcludes,
      includePatterns,
      maxFileSizeKb: opts.maxFileSize ?? 500,
      maxTurns: opts.maxTurns ?? 50,
      force: opts.reRecon,
      signal: reconAbortController.signal,
      verbose: opts.verbose,
    });
    console.log(
      `Recon: ${recon.languages.length > 0 ? recon.languages.join(", ") : "(languages unknown)"}${
        recon.frameworks.length > 0 ? ` | ${recon.frameworks.join(", ")}` : ""
      }`,
    );
    if (recon.summary) {
      console.log("");
      console.log(recon.summary);
    }

    // -------- PHASE 2 — precondition plan --------
    console.log("\n[2/2] Preconditions — deciding which agents would run…");
    const selection = await selectAgents(selectedAgents, {
      rootDir: root,
      walkCfg,
      detector,
      recon,
      concurrency: opts.concurrency,
      signal: reconAbortController.signal,
      verbose: opts.verbose,
    });
    const queuedAgents = selection.queued;
    const skippedCount = selection.decisions.length - queuedAgents.length;
    try {
      writeScanPlan(outDir, {
        runId: runMeta.runId,
        generatedAt: new Date().toISOString(),
        reconHash: recon.reconHash,
        rootPath: root,
        decisions: selection.decisions,
      });
    } catch (err) {
      if (opts.verbose) console.error(`  plan: failed to write: ${(err as Error).message}`);
    }
    console.log(
      `Preconditions: ${queuedAgents.length} queued, ${skippedCount} skipped → ${outDir}\\state\\plan.json`,
    );
    // The plan is the product of this command — always print the per-agent
    // decisions, not just under --verbose (unlike scan, where they're noise
    // ahead of the detection output).
    for (const d of selection.decisions) {
      console.log(`  ${d.queued ? "[queued] " : "[skipped]"} ${d.slug}: ${d.reason}`);
    }

    completeRun(outDir, runMeta.runId, "done", {});
    runFinalized = true;
    process.off("SIGINT", shutdownHandler);
    process.off("SIGTERM", shutdownHandler);

    console.log(
      `\nDone. ${queuedAgents.length} agent(s) queued. Run \`agentgg scan ${rootArg} -o ${
        opts.output ?? "./scan-results/"
      }\` to execute them (the recon brief is cached and will be reused).`,
    );
  } catch (err) {
    if (!runFinalized) {
      runFinalized = true;
      try {
        completeRun(outDir, runMeta.runId, "error", {});
      } catch {
        // best-effort
      }
    }
    process.off("SIGINT", shutdownHandler);
    process.off("SIGTERM", shutdownHandler);
    throw err;
  }
}

export function registerReconCommand(program: Command): void {
  program
    .command("recon")
    .description(
      "run only the recon survey + precondition planning for a codebase (writes recon.json + plan.json; no detection)",
    )
    .argument("<path>", "path to the codebase to survey")
    .option("-o, --output <path>", "output directory for recon + plan state", "./scan-results/")
    .option(
      "--provider <name>",
      "LLM provider for this run: anthropic | openai | ollama | bedrock | vertex (overrides saved default)",
    )
    .option(
      "--api-key <key>",
      "One-shot API key (not persisted). Valid for: anthropic, openai. For Anthropic, also accepts an sk-ant-oat… OAuth token.",
    )
    .option(
      "--oauth-token <token>",
      "One-shot Anthropic OAuth token (sk-ant-oat…). Not persisted. Anthropic only.",
    )
    .option("--base-url <url>", "One-shot Ollama base URL (not persisted). Ollama only.")
    .option(
      "--region <name>",
      "AWS region for Bedrock (e.g. us-east-1). Falls back to $AWS_REGION / $AWS_DEFAULT_REGION. Bedrock only.",
    )
    .option(
      "--project <id>",
      "GCP project ID for Vertex AI. Falls back to $GOOGLE_CLOUD_PROJECT / $GCLOUD_PROJECT. Vertex only.",
    )
    .option("--model <name>", "One-shot model override for the selected provider (not persisted)")
    .option(
      "-t, --template <value>",
      "Restrict planning to specific agents (slug, path to a .md file/dir, or a .txt list). Repeatable; comma/whitespace-separated values allowed within one -t. Defaults to the official base/ library.",
      collect,
      [] as string[],
    )
    .option("--concurrency <n>", "parallel precondition prompt gates", (v) => parseInt(v, 10), 5)
    .option("--max-turns <n>", "Max tool-use turns for the recon survey (default 50).", (v) =>
      parseInt(v, 10),
    )
    .option(
      "--re-recon",
      "Re-run the recon pass even if a cached brief exists for this output dir (default: reuse it when the project root + stack fingerprint are unchanged).",
    )
    .option(
      "--exclude <pattern>",
      "extra glob to exclude (repeatable; additive to walker defaults)",
      collect,
      [] as string[],
    )
    .option(
      "--only <pattern>",
      "restrict the file census to files matching at least one of these globs (repeatable)",
      collect,
      [] as string[],
    )
    .option(
      "--max-file-size <kb>",
      "skip files larger than this in KB (default 500)",
      (v) => parseInt(v, 10),
      500,
    )
    .option(
      "--no-default-excludes",
      "Don't apply the shared default exclude set (node_modules, .git, build dirs, lockfiles, binaries).",
    )
    .option("-v, --verbose", "verbose output")
    .action(async (path: string, opts: ReconOpts) => {
      try {
        await runReconCommand(path, opts);
      } catch (err) {
        console.error(`recon failed: ${err instanceof Error ? err.message : String(err)}`);
        process.exitCode = 1;
      }
    });
}

function collect(value: string, prev: string[]): string[] {
  return prev.concat([value]);
}
