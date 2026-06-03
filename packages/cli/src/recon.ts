import { resolve } from "node:path";
import type { ReconReport } from "@agentgg/core";
import { hashContent, readReconReport, writeReconReport } from "@agentgg/core";
import type { Detector, ReconResult } from "./detect.js";
import { loadReconInstructions } from "./recon-agent.js";

/**
 * Recon orchestration. Runs once at the start of a scan, before
 * precondition evaluation and agent dispatch. The resulting brief is
 * (a) injected into precondition `prompt` checks and (b) prepended to
 * every queued agent's first detection prompt so the model starts
 * oriented.
 *
 * Cached/resumed by `reconHash`: a re-scan with the same root + stack
 * fingerprint reuses the prior brief instead of paying for another
 * survey. `--re-recon` (force) bypasses the cache. The hash also feeds
 * each agent's `AgentRun` resume scope, so a changed brief invalidates
 * prompt-gated agents.
 */

export interface RunReconOptions {
  rootDir: string;
  outDir: string;
  detector: Detector;
  /** Static fingerprint tags, handed to the recon agent as a head start. */
  fingerprintTags: string[];
  excludePatterns: string[];
  includePatterns: string[];
  maxFileSizeKb: number;
  maxTurns: number;
  /** `--re-recon`: ignore any cached brief and survey again. */
  force?: boolean;
  signal?: AbortSignal;
  verbose?: boolean;
}

/**
 * A cheap, stable hash of the inputs the brief is derived from. We hash
 * the absolute root + the sorted fingerprint tags rather than the whole
 * tree — recon is a high-level pass, and the stack fingerprint is the
 * signal that matters for "is the prior brief still valid." A code-only
 * change won't invalidate it; a stack change (new manifest dep) will.
 */
export function computeReconHash(rootDir: string, fingerprintTags: string[]): string {
  return hashContent(
    JSON.stringify({ root: resolve(rootDir), tags: [...fingerprintTags].sort() }),
  ).slice(0, 16);
}

export async function runRecon(opts: RunReconOptions): Promise<ReconReport> {
  const reconHash = computeReconHash(opts.rootDir, opts.fingerprintTags);

  if (!opts.force) {
    const cached = readReconReport(opts.outDir);
    if (cached && cached.reconHash === reconHash) {
      if (opts.verbose) {
        console.log("  recon: cached (project unchanged; pass --re-recon to refresh)");
      }
      return cached;
    }
  }

  let result: ReconResult;
  try {
    result = await opts.detector.recon({
      rootDir: opts.rootDir,
      instructions: loadReconInstructions(),
      fingerprintTags: opts.fingerprintTags,
      excludePatterns: opts.excludePatterns,
      includePatterns: opts.includePatterns,
      maxFileSizeKb: opts.maxFileSizeKb,
      maxTurns: opts.maxTurns,
      signal: opts.signal,
    });
  } catch (err) {
    // Recon is advisory: its brief orients the agents but the scan can run
    // without it. A turn-cap stop (or any survey failure) must not abort the
    // whole scan — degrade to a minimal brief and continue. We intentionally
    // do NOT persist this stand-in, so the next run re-attempts a full survey
    // instead of caching a truncated one. Raise --max-turns or pass --re-recon
    // to refresh.
    console.warn(
      `  recon: survey did not complete (${(err as Error).message}); ` +
        `continuing with a minimal brief. Raise --max-turns or re-run with --re-recon to refresh.`,
    );
    return {
      purpose: "",
      languages: [],
      frameworks: [],
      authModel: undefined,
      integrations: [],
      notableDirs: [],
      summary:
        "Recon did not complete within the turn budget; the scan proceeded without a full project brief.",
      reconHash,
      generatedAt: new Date().toISOString(),
    };
  }

  const report: ReconReport = {
    purpose: result.purpose,
    languages: result.languages,
    frameworks: result.frameworks,
    // ReconResult.authModel is nullable; ReconReport.authModel is optional.
    authModel: result.authModel ?? undefined,
    integrations: result.integrations,
    notableDirs: result.notableDirs,
    summary: result.summary,
    reconHash,
    generatedAt: new Date().toISOString(),
  };
  writeReconReport(opts.outDir, report);
  return report;
}

/**
 * Render the recon brief as a compact prompt block for injection into
 * precondition checks and agent detection prompts. `summary` carries
 * the prose; the structured bullets give the model quick anchors.
 */
export function renderReconForPrompt(recon: ReconReport): string {
  const bits: string[] = [];
  if (recon.languages.length > 0) bits.push(`- Languages: ${recon.languages.join(", ")}`);
  if (recon.frameworks.length > 0) bits.push(`- Frameworks: ${recon.frameworks.join(", ")}`);
  if (recon.authModel) bits.push(`- Auth: ${recon.authModel}`);
  if (recon.integrations.length > 0) bits.push(`- Integrations: ${capList(recon.integrations)}`);
  if (recon.notableDirs.length > 0) bits.push(`- Notable dirs: ${capList(recon.notableDirs)}`);

  return `## Project recon (high-level context)

${recon.summary}${bits.length > 0 ? `\n\n${bits.join("\n")}` : ""}`;
}

/**
 * Backstop so the injected brief can't grow with repo size: render at most
 * `cap` list entries, summarizing the overflow. The recon agent is also
 * instructed to keep these lists short, but a model can over-produce — this
 * guarantees the prompt stays bounded regardless.
 */
function capList(items: string[], cap = 8): string {
  if (items.length <= cap) return items.join(", ");
  return `${items.slice(0, cap).join(", ")} (+${items.length - cap} more)`;
}
