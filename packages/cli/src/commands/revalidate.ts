import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { FileRecord, Finding } from "@agentgg/core";
import {
  completeRun,
  createRunMeta,
  loadAllFileRecords,
  loadUserConfig,
  readScanMeta,
  writeFileRecord,
  writeRunMeta,
} from "@agentgg/core";
import type { Command } from "commander";
import { runConcurrent } from "../concurrent.js";
import { type CredentialOverrides, resolveDetector } from "../llm.js";

interface RevalidateOpts {
  scope?: string;
  provider?: string;
  apiKey?: string;
  oauthToken?: string;
  baseUrl?: string;
  concurrency?: number;
  force?: boolean;
  verbose?: boolean;
  /** Override the scanned root recorded in scan.json — rare. */
  root?: string;
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

  const config = loadUserConfig(env);
  if (!config) {
    throw new Error(
      "No agentgg config found. Run `agentgg init` first to choose a provider and store an API key.",
    );
  }
  const credentials: CredentialOverrides = {
    ...(opts.apiKey ? { anthropicApiKey: opts.apiKey, openaiApiKey: opts.apiKey } : {}),
    ...(opts.oauthToken ? { anthropicOauthToken: opts.oauthToken } : {}),
    ...(opts.baseUrl ? { ollamaBaseUrl: opts.baseUrl } : {}),
  };
  const detector = resolveDetector(config, {
    provider: opts.provider,
    credentials,
  });

  // Re-read --scope at revalidate time. Treat a missing path as fatal
  // (same fail-fast contract scan uses).
  let scopeContent: string | undefined;
  if (opts.scope) {
    const scopePath = resolve(opts.scope);
    try {
      scopeContent = readFileSync(scopePath, "utf8");
    } catch (err) {
      throw new Error(
        `--scope: cannot read ${scopePath}: ${(err as Error).message}`,
      );
    }
  }

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

  const concurrency = Math.max(1, opts.concurrency ?? 5);
  console.log(`Revalidating ${tasks.length} finding(s) in ${outputDir}`);
  console.log(`  Root:        ${rootPath}`);
  console.log(`  Provider:    ${detector.name}`);
  if (scopeContent) console.log(`  Scope:       ${opts.scope}`);
  if (opts.force) console.log(`  Force:       re-classifying everything`);
  console.log(`  Concurrency: ${concurrency}`);
  console.log("");

  const runMeta = createRunMeta({ type: "validate" });
  writeRunMeta(outputDir, runMeta);

  const startedAt = new Date();
  const verdicts: Record<string, number> = {};
  const fileCache = new Map<string, string | null>();
  // Track which records actually changed so we don't rewrite every
  // FileRecord on disk for no reason.
  const dirtyRecords = new Set<FileRecord>();

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
      const result = await detector.validateFinding({
        finding,
        fileContent: content,
        scope: scopeContent,
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
      console.error(
        `  validate:${finding.id} failed — ${err instanceof Error ? err.message : String(err)}`,
      );
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
      console.error(
        `  persist failed for ${record.filePath}: ${(err as Error).message}`,
      );
    }
  }

  const completedAt = new Date();
  completeRun(outputDir, runMeta.runId, "done", {
    findingsCount: tasks.length,
    totalDurationMs: completedAt.getTime() - startedAt.getTime(),
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
    .description(
      "re-run the validation phase against persisted findings in an --output directory",
    )
    .argument(
      "[output-dir]",
      "path to the scan's --output directory (defaults to ./scan-results)",
      "./scan-results",
    )
    .option(
      "--scope <path>",
      "path to a SECURITY.md-style scope file. When set, the validator can return `out-of-scope`.",
    )
    .option(
      "--root <path>",
      "override the scanned root recorded in scan.json (only needed if the working copy moved)",
    )
    .option(
      "--provider <name>",
      "LLM provider for this run: anthropic | openai | ollama (overrides saved default)",
    )
    .option(
      "--api-key <key>",
      "One-shot API key for the selected provider (not persisted).",
    )
    .option(
      "--oauth-token <token>",
      "One-shot Anthropic OAuth token (sk-ant-oat…). Not persisted.",
    )
    .option("--base-url <url>", "One-shot Ollama base URL (not persisted)")
    .option("--concurrency <n>", "parallel validation calls", (v) => parseInt(v, 10), 5)
    .option(
      "--force",
      "re-validate findings that already have a verdict (default: skip them)",
    )
    .option("-v, --verbose", "verbose output")
    .action(async (outputDir: string, opts: RevalidateOpts) => {
      try {
        await runRevalidate(outputDir, opts);
      } catch (err) {
        console.error(
          `revalidate failed: ${err instanceof Error ? err.message : String(err)}`,
        );
        process.exit(1);
      }
    });
}
