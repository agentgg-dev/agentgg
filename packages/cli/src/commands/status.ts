import { resolve } from "node:path";
import { listRuns, loadAllFileRecords, readScanMeta } from "@agentgg/core";
import type { Command } from "commander";

interface StatusOpts {
  json?: boolean;
}

/**
 * Read-only view of one scan's on-disk state. Operates on the same
 * `--output` dir `scan` wrote to. No project abstraction — nuclei-style.
 *
 *   agentgg scan <path> -o ./scan-results
 *   agentgg status ./scan-results
 *
 * The default path is `./scan-results/` to match `scan`'s default.
 */
export async function runStatus(outputArg: string, opts: StatusOpts): Promise<void> {
  const outputDir = resolve(outputArg);
  const scanMeta = readScanMeta(outputDir);

  if (!scanMeta) {
    if (opts.json) {
      console.log(JSON.stringify({ outputDir, exists: false }, null, 2));
      return;
    }
    console.log(`No scan state at ${outputDir}`);
    console.log(`  Run \`agentgg scan <path> -o ${outputArg}\` first.`);
    return;
  }

  const records = loadAllFileRecords(outputDir);
  const runs = listRuns(outputDir);

  const statusCounts = { pending: 0, analyzed: 0, validated: 0 };
  for (const r of records) statusCounts[r.status]++;

  // Records are sharded per (agent, file), so the same source file shows
  // up once per agent that analyzed it. Report distinct source paths.
  const distinctFiles = new Set(records.map((r) => r.filePath)).size;

  const allFindings = records.flatMap((r) => r.findings);
  const validated = allFindings.filter((f) => f.validation);
  const verdictCounts: Record<string, number> = {};
  for (const f of validated) {
    if (!f.validation) continue;
    verdictCounts[f.validation.verdict] = (verdictCounts[f.validation.verdict] ?? 0) + 1;
  }

  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          outputDir,
          root: scanMeta.root,
          createdAt: scanMeta.createdAt,
          updatedAt: scanMeta.updatedAt,
          filesTracked: distinctFiles,
          recordsTracked: records.length,
          statusCounts,
          findings: {
            total: allFindings.length,
            validated: validated.length,
            byVerdict: verdictCounts,
          },
          recentRuns: runs.slice(0, 10).map((r) => ({
            runId: r.runId,
            type: r.type,
            phase: r.phase,
            startedAt: r.startedAt,
            completedAt: r.completedAt,
            stats: r.stats,
          })),
        },
        null,
        2,
      ),
    );
    return;
  }

  console.log(`Scan state: ${outputDir}`);
  console.log(`  Root:           ${scanMeta.root}`);
  console.log(`  Created:        ${scanMeta.createdAt}`);
  console.log(`  Last updated:   ${scanMeta.updatedAt}`);
  console.log(`  Files tracked:  ${distinctFiles} (${records.length} agent-file records)`);
  console.log("");

  console.log("Status");
  console.log(`  analyzed:   ${statusCounts.analyzed}`);
  console.log(`  validated:  ${statusCounts.validated}`);
  console.log(`  pending:    ${statusCounts.pending}`);
  console.log("");

  if (allFindings.length > 0) {
    console.log("Findings");
    console.log(`  total:      ${allFindings.length}`);
    console.log(`  validated:  ${validated.length}/${allFindings.length}`);
    const verdictKeys = Object.keys(verdictCounts).sort();
    if (verdictKeys.length > 0) {
      const line = verdictKeys.map((k) => `${k}=${verdictCounts[k]}`).join(", ");
      console.log(`  verdicts:   ${line}`);
    }
    console.log("");
  }

  if (runs.length > 0) {
    console.log(`Recent runs (${runs.length} total)`);
    for (const run of runs.slice(0, 5)) {
      const duration =
        run.completedAt && run.startedAt
          ? `${(
              (new Date(run.completedAt).getTime() - new Date(run.startedAt).getTime()) / 1000
            ).toFixed(1)}s`
          : "running";
      const findingsPart =
        run.stats.findingsCount !== undefined ? ` findings: ${run.stats.findingsCount}` : "";
      const filesPart =
        run.stats.filesScanned !== undefined ? ` files: ${run.stats.filesScanned}` : "";
      console.log(
        `  ${run.runId}  ${run.type}  ${run.phase}  ${duration}${filesPart}${findingsPart}`,
      );
    }
  }
}

export function registerStatusCommand(program: Command): void {
  program
    .command("status")
    .description("show scan state for an --output directory (files tracked, findings, recent runs)")
    .argument(
      "[output-dir]",
      "path to the scan's --output directory (defaults to ./scan-results)",
      "./scan-results",
    )
    .option("--json", "emit raw JSON")
    .action(async (outputDir: string, opts: StatusOpts) => {
      try {
        await runStatus(outputDir, opts);
      } catch (err) {
        console.error(`status failed: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      }
    });
}
