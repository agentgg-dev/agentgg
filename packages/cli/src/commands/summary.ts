import { resolve } from "node:path";
import {
  completeRun,
  createRunMeta,
  loadAllFileRecords,
  readScanMeta,
  writeRunMeta,
} from "@agentgg/core";
import type { Command } from "commander";
import { writeMarkdownReport } from "../reporters/md.js";
import { buildInvocation } from "./invocation.js";

interface SummaryOpts {
  /** Override the scanned root recorded in scan.json — rare. */
  root?: string;
  /** Drop false-positive findings from the markdown report (kept by default). */
  excludeFalsePositives?: boolean;
  verbose?: boolean;
}

/**
 * Stand-alone report command — render `summary.md` and the per-finding
 * `findings/*.md` from the findings already persisted in an `--output`
 * directory. No LLM, no walker, no detection: it is the final
 * report-writing phase of `scan` lifted out so it can run on its own.
 *
 * Pairs with `scan --no-summary`: run the scan without rendering, inspect
 * or post-process the raw state, then `agentgg summary` to produce the
 * markdown. Also re-renders after a `revalidate` / `score` if you want a
 * fresh report without re-running those passes (both already re-render on
 * their own, so this is mainly for the `--no-summary` workflow).
 */
export async function runSummary(
  outputArg: string,
  opts: SummaryOpts,
  _env: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  const outputDir = resolve(outputArg);
  const scanMeta = readScanMeta(outputDir);
  if (!scanMeta) {
    throw new Error(
      `No scan state at ${outputDir}. Run \`agentgg scan <path> -o ${outputArg}\` first.`,
    );
  }
  const rootPath = opts.root ? resolve(opts.root) : scanMeta.root;

  const records = loadAllFileRecords(outputDir);
  if (records.length === 0) {
    console.log(`No FileRecords in ${outputDir}/state/files/.`);
    console.log("  Run `agentgg scan` first to populate findings.");
    return;
  }

  const allFindings = records.flatMap((r) => r.findings);
  const byAgent: Record<string, number> = {};
  for (const f of allFindings) {
    byAgent[f.agentSlug] = (byAgent[f.agentSlug] ?? 0) + 1;
  }

  const runMeta = createRunMeta({
    type: "scan",
    invocation: buildInvocation({ command: "summary" }),
  });
  writeRunMeta(outputDir, runMeta);

  // No detection happened here, so there's no meaningful run duration.
  // Use the scan-meta timestamps for the report header so it reflects the
  // underlying scan rather than the instant this render ran.
  const startedAt = new Date(scanMeta.createdAt);
  const completedAt = new Date(scanMeta.updatedAt);

  const report = writeMarkdownReport({
    outDir: outputDir,
    root: rootPath,
    startedAt,
    completedAt,
    findings: allFindings,
    filesScanned: new Set(records.map((r) => r.filePath)).size,
    byAgent,
    excludeFalsePositives: opts.excludeFalsePositives,
  });

  completeRun(outputDir, runMeta.runId, "done", {
    findingsCount: allFindings.length,
  });

  console.log(
    `Wrote report for ${allFindings.length} finding(s) across ${records.length} record(s).`,
  );
  console.log(`  Summary: ${report.summaryPath}`);
  console.log(`  Findings dir: ${outputDir}\\findings`);
}

export function registerSummaryCommand(program: Command): void {
  program
    .command("summary")
    .description(
      "render summary.md + findings/*.md from persisted findings in an --output directory (no detection; pairs with `scan --no-summary`)",
    )
    .argument(
      "[output-dir]",
      "path to the scan's --output directory (defaults to ./scan-results)",
      "./scan-results",
    )
    .option(
      "--root <path>",
      "override the scanned root recorded in scan.json (only affects the report header)",
    )
    .option(
      "--exclude-false-positives",
      "Drop false-positive findings from the markdown report (default: keep them). FP findings always stay in state/files/* regardless.",
    )
    .option("-v, --verbose", "verbose output")
    .action(async (outputDir: string, opts: SummaryOpts) => {
      try {
        await runSummary(outputDir, opts);
      } catch (err) {
        console.error(`summary failed: ${err instanceof Error ? err.message : String(err)}`);
        process.exitCode = 1;
      }
    });
}
