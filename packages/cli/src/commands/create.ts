import { resolve } from "node:path";
import type { Provider } from "@agentgg/core";
import type { Command } from "commander";
import { runCreate } from "../create.js";
import { loadOrSynthesizeConfig, resolveDetector } from "../llm.js";
import { buildCredentialsFromOpts, validateProviderFlags } from "../providers/index.js";
import { loadReports } from "../report-loader.js";

interface CreateOpts {
  code: string;
  report: string;
  output: string;
  provider?: string;
  apiKey?: string;
  oauthToken?: string;
  baseUrl?: string;
  region?: string;
  project?: string;
  model?: string;
  maxTurns?: number;
  maxFileSize?: number;
  exclude?: string[];
  only?: string[];
  verbose?: boolean;
}

/**
 * `agentgg create` — distill a past security report (or several) into
 * reusable agent `.md` files that future `agentgg scan` runs can use to
 * catch the same anti-pattern if it recurs in this codebase. Standalone
 * command, no shared state with `scan` — no `state/` dir, no resume, no
 * recon brief. One LLM session per report, output is one agent `.md` per
 * report into `--output`.
 */
export async function runCreateCommand(opts: CreateOpts): Promise<void> {
  const codeDir = resolve(opts.code);
  const outputDir = resolve(opts.output);

  const reports = loadReports(opts.report);
  console.log(`Found ${reports.length} report${reports.length === 1 ? "" : "s"} to distill.`);

  const env = process.env;
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

  console.log(`Code root: ${codeDir}`);
  console.log(`Output:    ${outputDir}`);
  console.log(`Provider:  ${detector.name}`);
  console.log("");

  const outcomes = await runCreate({
    rootDir: codeDir,
    outputDir,
    reports,
    detector,
    excludePatterns: opts.exclude ?? [],
    includePatterns: opts.only ?? [],
    maxFileSizeKb: opts.maxFileSize ?? 500,
    maxTurns: opts.maxTurns ?? 50,
    verbose: opts.verbose,
  });

  const created = outcomes.filter((o) => o.status === "created").length;
  const failed = outcomes.filter((o) => o.status === "failed").length;
  console.log("");
  console.log(`Done. ${created} agent${created === 1 ? "" : "s"} created, ${failed} failed.`);
  if (created > 0) {
    console.log(
      `Inspect them in ${outputDir}, then \`agentgg agents add ${outputDir}\` to install.`,
    );
  }
  if (failed > 0) {
    process.exitCode = 1;
  }
}

export function registerCreateCommand(program: Command): void {
  program
    .command("create")
    .description(
      "distill a past security report (md/txt) into a reusable agent that catches the same anti-pattern if it recurs in this codebase",
    )
    .requiredOption("-c, --code <path>", "path to the codebase the report came from")
    .requiredOption(
      "-r, --report <path>",
      "path to the past report (.md/.txt file, a directory of them, or a .txt list of paths)",
    )
    .requiredOption(
      "-o, --output <path>",
      "directory to write the generated <slug>-<hash>.md agent file(s) into",
    )
    .option(
      "--provider <name>",
      "LLM provider for this run: anthropic | openai | ollama | bedrock | vertex (overrides saved default)",
    )
    .option(
      "--api-key <key>",
      "One-shot API key (not persisted). Valid for: anthropic, openai. For Anthropic, also accepts an sk-ant-oat... OAuth token.",
    )
    .option(
      "--oauth-token <token>",
      "One-shot Anthropic OAuth token (sk-ant-oat...). Not persisted. Anthropic only.",
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
    .option("--max-turns <n>", "tool-use turn cap per distillation session (default 50)", (v) =>
      parseInt(v, 10),
    )
    .option(
      "--max-file-size <kb>",
      "skip files larger than this when exploring the code (default 500)",
      (v) => parseInt(v, 10),
      500,
    )
    .option(
      "--exclude <pattern>",
      "extra glob to exclude while exploring the code (repeatable)",
      collect,
      [] as string[],
    )
    .option(
      "--only <pattern>",
      "restrict code exploration to matching globs (repeatable)",
      collect,
      [] as string[],
    )
    .option("-v, --verbose", "verbose output")
    .action(async (opts: CreateOpts) => {
      try {
        await runCreateCommand(opts);
      } catch (err) {
        console.error(`create failed: ${err instanceof Error ? err.message : String(err)}`);
        process.exitCode = 1;
      }
    });
}

function collect(value: string, prev: string[]): string[] {
  return prev.concat([value]);
}
