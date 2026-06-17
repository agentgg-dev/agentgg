import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseAgentMarkdown } from "@agentgg/core";
import { renderAgentSpecMd } from "./agent-spec.js";
import { loadCreateInstructions } from "./create-agent.js";
import type { Detector } from "./detect.js";
import type { LoadedReport } from "./report-loader.js";

/**
 * Orchestration for `agentgg create`. One distillation session per report
 * file: the detector reads the report + explores the code root with its
 * tools, then emits an `AgentSpec` constrained by the schema. We render
 * the spec to an agent `.md`, validate the round-trip through the loader,
 * and write to `<outputDir>/<slug>-<hash>.md`.
 *
 * The filename hash is derived from the report path + content + code
 * root, so a re-run on the same inputs overwrites the same file
 * (idempotent), and runs against different reports never collide. Same
 * naming shape as findings (`{slug}-{title}-{id}.md`).
 */

export interface CreateOptions {
  rootDir: string;
  outputDir: string;
  reports: LoadedReport[];
  detector: Detector;
  excludePatterns: string[];
  includePatterns: string[];
  maxFileSizeKb: number;
  maxTurns: number;
  signal?: AbortSignal;
  verbose?: boolean;
}

export interface CreateOutcome {
  reportPath: string;
  status: "created" | "failed";
  agentPath?: string;
  slug?: string;
  error?: string;
}

export async function runCreate(opts: CreateOptions): Promise<CreateOutcome[]> {
  if (!opts.detector.createAgent) {
    throw new Error(
      `The active provider (${opts.detector.name}) does not support \`agentgg create\` yet.`,
    );
  }
  mkdirSync(opts.outputDir, { recursive: true });

  const instructions = loadCreateInstructions();
  const outcomes: CreateOutcome[] = [];

  // Sequential rather than parallel: a future user is most likely passing
  // a handful of reports interactively, and a tool-enabled session against
  // the same code root benefits from cache warmth on consecutive calls
  // (and avoids fighting for the LLM rate limit).
  for (let i = 0; i < opts.reports.length; i++) {
    const report = opts.reports[i] as LoadedReport;
    console.log(`[${i + 1}/${opts.reports.length}] Distilling ${report.name} into an agent...`);
    try {
      const spec = await opts.detector.createAgent({
        rootDir: opts.rootDir,
        instructions,
        reportName: report.name,
        reportContent: report.content,
        excludePatterns: opts.excludePatterns,
        includePatterns: opts.includePatterns,
        maxFileSizeKb: opts.maxFileSizeKb,
        maxTurns: opts.maxTurns,
        signal: opts.signal,
      });

      const md = renderAgentSpecMd(spec);

      // Round-trip the rendered markdown through the same loader scan.ts
      // uses. Catches regex compile failures, slug shape violations, and
      // any other schema mismatch before the file lands on disk.
      try {
        parseAgentMarkdown(md);
      } catch (err) {
        throw new Error(
          `Generated agent failed lint: ${(err as Error).message}. The model produced an invalid spec; raise --max-turns or retry.`,
        );
      }

      const hash = shortHash(opts.rootDir, report.path, report.content);
      const filename = `${spec.slug}-${hash}.md`;
      const outPath = join(opts.outputDir, filename);
      writeFileSync(outPath, md, "utf8");

      console.log(`  -> ${outPath}`);
      outcomes.push({
        reportPath: report.path,
        status: "created",
        agentPath: outPath,
        slug: spec.slug,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`  FAILED: ${msg}`);
      outcomes.push({
        reportPath: report.path,
        status: "failed",
        error: msg,
      });
    }
  }

  return outcomes;
}

/**
 * Stable 8-char hash for the agent filename suffix. Derived from
 * (code root, report path, report content) so:
 *   - Same inputs → same hash → idempotent re-runs overwrite in place.
 *   - Different reports → different hash → no collisions in the output dir.
 *   - Editing the report content → new hash → fresh file (the model's
 *     read of the report changed, so the previous agent is stale).
 */
function shortHash(rootDir: string, reportPath: string, reportContent: string): string {
  return createHash("sha256")
    .update(`${resolve(rootDir)}|${resolve(reportPath)}|${reportContent}`)
    .digest("hex")
    .slice(0, 8);
}
