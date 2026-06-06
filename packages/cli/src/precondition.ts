import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
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
  /** Scan output dir. When set, each agent's decision is persisted as
   *  `<outputDir>/state/preconditions/<slug>.json` immediately after the
   *  LLM gate resolves, and existing sidecars are read at the top of the
   *  pass to skip already-evaluated agents. Without this, the function
   *  still runs (in-memory only) — used by tests that don't need resume. */
  outputDir?: string;
  /** When true, ignore existing sidecars and re-evaluate every agent.
   *  Set by --re-recon: the user explicitly asked to re-run the gating.
   *  New decisions still get written to sidecars, so the next normal run
   *  picks them up via the cache. */
  force?: boolean;
}

// ---------------------------------------------------------------------------
// Precondition sidecars — per-agent persistence so a SIGTERM mid-pass
// (Cloud Run Job cancel, OOM) doesn't throw away evaluated decisions.
// Sidecar shape mirrors `PreconditionDecision`. Failed JSON.parse on read
// treats the sidecar as missing — the agent gets re-evaluated. That's the
// safe default for any partial-write scenario.
// ---------------------------------------------------------------------------

const PRECONDITIONS_SUBDIR = "state/preconditions";

function preconditionsDir(outputDir: string): string {
  return join(outputDir, PRECONDITIONS_SUBDIR);
}

function preconditionSidecarPath(outputDir: string, slug: string): string {
  // Slug safety: agent catalog loader already rejects path-traversal characters
  // (see agents-fs.ts). Trust the loader rather than re-validating here.
  return join(preconditionsDir(outputDir), `${slug}.json`);
}

function writePreconditionSidecar(outputDir: string, decision: PreconditionDecision): void {
  const path = preconditionSidecarPath(outputDir, decision.slug);
  mkdirSync(preconditionsDir(outputDir), { recursive: true });
  // Direct write — file is tiny and idempotent; a torn write fails JSON.parse
  // on the next read and the agent is re-evaluated. No tmp/rename needed.
  writeFileSync(path, `${JSON.stringify(decision, null, 2)}\n`);
}

function readPreconditionSidecar(outputDir: string, slug: string): PreconditionDecision | null {
  const path = preconditionSidecarPath(outputDir, slug);
  if (!existsSync(path)) return null;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as Partial<PreconditionDecision>;
    if (
      typeof parsed.slug === "string" &&
      typeof parsed.queued === "boolean" &&
      typeof parsed.reason === "string"
    ) {
      return { slug: parsed.slug, queued: parsed.queued, reason: parsed.reason };
    }
    return null;
  } catch {
    return null;
  }
}

function readAllPreconditionSidecars(outputDir: string): Map<string, PreconditionDecision> {
  const dir = preconditionsDir(outputDir);
  const out = new Map<string, PreconditionDecision>();
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
    const slug = entry.name.slice(0, -".json".length);
    const decision = readPreconditionSidecar(outputDir, slug);
    if (decision) out.set(slug, decision);
  }
  return out;
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

  // Resume: read any existing sidecars before kicking off the pool, so
  // agents already evaluated in a prior (killed) run skip straight to
  // their cached decision. `force` (set by --re-recon) bypasses the cache
  // so the user can deliberately re-evaluate every gate.
  const decisionBySlug = new Map<string, PreconditionDecision>();
  if (opts.outputDir && !opts.force) {
    const cached = readAllPreconditionSidecars(opts.outputDir);
    for (const [slug, decision] of cached) decisionBySlug.set(slug, decision);
  }

  // Only evaluate agents that don't already have a cached decision.
  const toEvaluate = agents.filter((a) => !decisionBySlug.has(a.slug));

  await runConcurrent(toEvaluate, Math.max(1, opts.concurrency ?? 5), async (agent) => {
    const decision = await evaluateAgent(
      agent,
      files,
      opts.rootDir,
      opts.detector,
      reconBlock,
      opts.signal,
    );
    // Write sidecar BEFORE updating the in-memory map. If we crash between
    // the write and the map update, the next run reads the sidecar and
    // picks up the decision; vice versa would lose it.
    if (opts.outputDir) {
      try {
        writePreconditionSidecar(opts.outputDir, decision);
      } catch (err) {
        if (opts.verbose) {
          console.error(
            `  precondition sidecar write failed for ${agent.slug}: ${(err as Error).message}`,
          );
        }
      }
    }
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
    reason:
      check.reason || (check.relevant ? "prompt gate: relevant" : "prompt gate: not relevant"),
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
    const inScope =
      p.in.length > 0 ? files.filter((f) => p.in.some((g) => matchGlob(f, g))) : files;
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
