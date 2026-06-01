import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Agent, PreconditionRegex, ReconReport } from "@agentgg/core";
import { minimatch } from "minimatch";
import { runConcurrent } from "./concurrent.js";
import type { Detector } from "./detect.js";
import { renderReconForPrompt } from "./recon.js";
import { collectAllFiles, type WalkConfig } from "./walker.js";

/**
 * Precondition engine — decides which selected agents are queued for
 * this repo and which are skipped, BEFORE any detection runs.
 *
 * Four cases per agent (`Precondition` docstring in core/types.ts):
 *   - no prompt, no regex → always queued
 *   - regex only          → queued iff the regex existence check matches
 *   - prompt only         → queued iff the LLM relevance gate says yes
 *   - both                → queued iff regex matches AND the LLM says yes
 *
 * The regex checks (file extensions / path globs / directories / content
 * patterns) are pure filesystem work — no LLM. They run first and
 * short-circuit: when an agent declares both and the regex fails, we
 * skip without paying for an LLM call. The prompt gate is the only part
 * that hits the model, so only prompt-declaring agents that survive the
 * regex pass incur LLM cost.
 */

export interface PreconditionDecision {
  slug: string;
  queued: boolean;
  reason: string;
}

export interface SelectAgentsOptions {
  rootDir: string;
  /** Same walk filters the executor will use, so the file census matches. */
  walkCfg: WalkConfig;
  detector: Detector;
  /** Recon brief injected into prompt gates. */
  recon?: ReconReport;
  /** Parallelism for the LLM prompt gates. Defaults to 5. */
  concurrency?: number;
  signal?: AbortSignal;
  verbose?: boolean;
}

export interface SelectAgentsResult {
  queued: Agent[];
  decisions: PreconditionDecision[];
}

/**
 * Evaluate every agent's precondition and partition into queued/skipped.
 * Decisions preserve input order; `queued` lists the agents to run.
 */
export async function selectAgents(
  agents: ReadonlyArray<Agent>,
  opts: SelectAgentsOptions,
): Promise<SelectAgentsResult> {
  // One file census for the whole precondition pass — reused by every
  // agent's regex check so we walk the tree once.
  const files = collectAllFiles(opts.rootDir, opts.walkCfg);
  const reconBlock = opts.recon ? renderReconForPrompt(opts.recon) : undefined;

  const decisionBySlug = new Map<string, PreconditionDecision>();

  await runConcurrent(agents, Math.max(1, opts.concurrency ?? 5), async (agent) => {
    const decision = await evaluateAgent(agent, files, opts.rootDir, opts.detector, reconBlock, opts.signal);
    decisionBySlug.set(agent.slug, decision);
  });

  // Re-derive in input order for stable output.
  const decisions = agents.map(
    (a) => decisionBySlug.get(a.slug) ?? { slug: a.slug, queued: true, reason: "no precondition" },
  );
  const queued = agents.filter((a) => decisionBySlug.get(a.slug)?.queued ?? true);
  return { queued, decisions };
}

async function evaluateAgent(
  agent: Agent,
  files: string[],
  rootDir: string,
  detector: Detector,
  reconBlock: string | undefined,
  signal: AbortSignal | undefined,
): Promise<PreconditionDecision> {
  const pre = agent.precondition;
  const hasRegex = !!pre?.regex && regexHasConstraint(pre.regex);
  const hasPrompt = !!pre?.prompt && pre.prompt.trim().length > 0;

  if (!hasRegex && !hasPrompt) {
    return { slug: agent.slug, queued: true, reason: "no precondition — always run" };
  }

  // Cheap regex pass first. A declared-but-failing regex short-circuits
  // to "skip" without an LLM call (regex AND prompt).
  if (hasRegex) {
    // biome-ignore lint/style/noNonNullAssertion: hasRegex implies pre.regex
    const r = evaluateRegex(pre!.regex!, files, rootDir);
    if (!r.matched) {
      return { slug: agent.slug, queued: false, reason: `regex precondition not met` };
    }
    if (!hasPrompt) {
      return { slug: agent.slug, queued: true, reason: r.reason ?? "regex matched" };
    }
  }

  // Prompt gate (regex already passed or was absent).
  // biome-ignore lint/style/noNonNullAssertion: hasPrompt implies pre.prompt
  const conditionPrompt = pre!.prompt!;
  const check = await detector.checkPrecondition({
    agentName: agent.name,
    agentDescription: agent.description,
    conditionPrompt,
    recon: reconBlock,
    signal,
  });
  return {
    slug: agent.slug,
    queued: check.relevant,
    reason: check.reason || (check.relevant ? "prompt gate: relevant" : "prompt gate: not relevant"),
  };
}

// ---------------------------------------------------------------------------
// Regex existence checks (no LLM)
// ---------------------------------------------------------------------------

function regexHasConstraint(r: PreconditionRegex): boolean {
  return (
    r.extensions.length > 0 ||
    r.files.length > 0 ||
    r.directories.length > 0 ||
    r.patterns.length > 0
  );
}

interface RegexMatch {
  matched: boolean;
  reason?: string;
}

/**
 * Evaluate a `PreconditionRegex` against the file census. ANY sub-check
 * matching is enough (logical OR). Ordered cheap → costly: extensions,
 * path globs, and directories are pure path tests; content `patterns`
 * read files and so run last, only when the path checks didn't already
 * satisfy the gate.
 */
export function evaluateRegex(
  regex: PreconditionRegex,
  files: string[],
  rootDir: string,
): RegexMatch {
  // 1. extensions — does a file of this type exist?
  for (const ext of regex.extensions) {
    const norm = ext.startsWith(".") ? ext.toLowerCase() : `.${ext.toLowerCase()}`;
    if (files.some((f) => f.toLowerCase().endsWith(norm))) {
      return { matched: true, reason: `file *${norm} exists` };
    }
  }

  // 2. files — does a file at this path glob exist?
  for (const g of regex.files) {
    if (files.some((f) => matchGlob(f, g))) {
      return { matched: true, reason: `file matching "${g}" exists` };
    }
  }

  // 3. directories — does a directory glob hold any file?
  for (const d of regex.directories) {
    if (dirHasContent(files, d)) {
      return { matched: true, reason: `directory "${d}" exists` };
    }
  }

  // 4. content patterns — read files in scope and test the regex.
  for (const p of regex.patterns) {
    let re: RegExp;
    try {
      re = new RegExp(p.regex);
    } catch {
      continue; // bad regex in the template — skip rather than crash
    }
    const inScope = p.in.length > 0 ? files.filter((f) => p.in.some((g) => matchGlob(f, g))) : files;
    const scoped =
      p.notIn.length > 0 ? inScope.filter((f) => !p.notIn.some((g) => matchGlob(f, g))) : inScope;
    for (const f of scoped) {
      let content: string;
      try {
        content = readFileSync(resolve(rootDir, f), "utf8");
      } catch {
        continue;
      }
      if (re.test(content)) {
        return { matched: true, reason: p.label ?? `content matches /${p.regex}/` };
      }
    }
  }

  return { matched: false };
}

/** minimatch with sane defaults; `matchBase` lets a bare name like
 *  "artisan" match anywhere in the tree. */
function matchGlob(filePath: string, glob: string): boolean {
  return minimatch(filePath, glob, { dot: true, matchBase: !glob.includes("/") });
}

/** A directory "exists" (for gating) when at least one file lives under
 *  it. Accepts "app", "app/", "app/**", or "src/api". */
function dirHasContent(files: string[], dirGlob: string): boolean {
  const base = dirGlob.replace(/\/+$/, "").replace(/\/\*\*?$/, "");
  return files.some(
    (f) => minimatch(f, `${base}/**`, { dot: true }) || minimatch(f, dirGlob, { dot: true }),
  );
}
