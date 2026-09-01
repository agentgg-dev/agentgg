import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import type {
  Agent,
  AgentRun,
  FileRecord,
  Finding,
  PreconditionDecisionRecord,
  Provider,
  ReconReport,
} from "@agentgg/core";
import {
  completeRun,
  createRunMeta,
  fingerprint,
  getOfficialAgentsDir,
  hasFileScope,
  hashContent,
  isSemgrepPreFilter,
  loadAllFileRecords,
  readAgentRun,
  readFileRecord,
  readScanPlan,
  upsertScanMeta,
  writeAgentRun,
  writeFileRecord,
  writeRunMeta,
  writeScanPlan,
} from "@agentgg/core";
import type { Command } from "commander";
import { defaultAgentDirs, loadAllAgents } from "../agent-catalog.js";
import { installOfficialAgents } from "../agents-install.js";
import { anchorLoad, packBatches, shardCandidate, shardKeyOf } from "../anchors.js";
import { runConcurrent } from "../concurrent.js";
import { resolveDedup } from "../deduper.js";
import { loadDefaultScope } from "../default-scope.js";
import type { AgentCandidate } from "../detect.js";
import { FatalScanError, handleDetectorError } from "../diagnostics.js";
import { listChangedFiles, loadCommitPatch } from "../diff.js";
import { loadOrSynthesizeConfig, resolveDetector } from "../llm.js";
import { logError, logInfo, logWarn } from "../log.js";
import { evaluatePreFilter } from "../pre-filter.js";
import { selectAgents } from "../precondition.js";
import {
  buildCredentialsFromOpts,
  REGION_FLAG_HELP,
  validateProviderFlags,
} from "../providers/index.js";
import { renderReconForPrompt, runRecon } from "../recon.js";
import { findingFilenameSlug, writeMarkdownReport } from "../reporters/md.js";
import { getSemgrepRulesDir, isSemgrepSuppressed, runSemgrepProject } from "../semgrep.js";
import { runSmartExclude } from "../smart-exclude.js";
import { resolveTemplates } from "../template.js";
import { createUsageMeter, type UsageMeter } from "../usage-meter.js";
import { DEFAULT_VIEWER_PORT, openBrowser, startViewer } from "../viewer-server.js";
import { DEFAULT_EXCLUDES, type WalkConfig, walkForAgents } from "../walker.js";
import { buildInvocation } from "./invocation.js";
import { printReady } from "./view.js";

interface ScanOpts {
  /**
   * Scope document control. Commander gives three shapes:
   *   - a string: path to a SECURITY.md-style scope doc (`--scope <path>`).
   *   - `undefined`: flag omitted → the bundled default scope is used
   *     (see `loadDefaultScope`), so validation always has trust-boundary
   *     rules to reason about `out-of-scope`.
   *   - `false`: `--no-scope` → opt out of scope entirely (no default).
   *
   * A resolved scope doc has two meanings downstream:
   *   - with --validate: scope context is threaded into full validation
   *     so the model can return `out-of-scope` alongside the usual
   *     confirmed / false-positive / uncertain verdicts.
   *   - WITHOUT --validate: an EXPLICIT `--scope <path>` triggers cheap
   *     scope-only validation (the model never sees the source, only the
   *     finding metadata + scope doc, and only `out-of-scope` persists).
   *     The bundled default never triggers this on its own — a plain
   *     detection-only scan stays detection-only.
   */
  scope?: string | boolean;
  output?: string;
  /** `--source-id`: resume identity, replacing the absolute root. Defaults to
   *  the root, which is what stops two projects sharing one `-o` dir from
   *  serving each other's findings. */
  sourceId?: string;
  validate?: boolean;
  provider?: string;
  apiKey?: string;
  oauthToken?: string;
  baseUrl?: string;
  region?: string;
  project?: string;
  model?: string;
  openrouterRouting?: string;
  concurrency?: number;
  diff?: string;
  template?: string[];
  /** `--semgrep-rules <dir>`: extra rule dirs searched BEFORE the catalog's
   *  own `semgrep-rules/`, so a local file shadows a catalog rule of the same
   *  name. Repeatable. Only `semgrepRule` preFilters read it. */
  semgrepRules?: string[];
  verbose?: boolean;
  exclude?: string[];
  only?: string[];
  /**
   * Max file size in KB; the walker skips anything larger. Defaults to 500.
   * `--no-max-file-size` sets this to `false`, which lifts the size cap
   * entirely (scan files of any size).
   */
  maxFileSize?: number | false; // KB, or false (--no-max-file-size) to disable the cap
  /**
   * Apply the shared `DEFAULT_EXCLUDES` set (node_modules, .git, build
   * dirs, lockfiles, binaries). Defaults to true. Commander stores
   * `--no-default-excludes` as `defaultExcludes: false` — pass it to scan
   * everything (only the CLI `--exclude` deletes still apply). Per-agent
   * opt-out is `where.useDefaultExcludes`.
   */
  defaultExcludes?: boolean;
  /**
   * `--auto-exclude`: before recon, ask the model which folders are not
   * worth security-scanning (tests, fixtures, generated code, vendored
   * deps, docs, sample data) and fold them in as if they were CLI
   * `--exclude` paths. On by default (Commander default `true`); pass
   * `--no-auto-exclude` to scan the whole tree. The chosen folders are
   * always logged (with reasons in `--verbose`). When a prior `recon` or
   * `scan` against the same `--output` dir already chose auto-excludes,
   * they're reused (no second LLM pass); `--re-recon` forces a fresh pass.
   */
  autoExclude?: boolean;
  /** Re-analyze files even when a prior FileRecord covers them with the same contentHash. */
  rescan?: boolean;
  /** Re-validate findings even when they already have a verdict on disk. */
  revalidateAll?: boolean;
  /**
   * Max tool-use turns per LLM session. When set, applies uniformly to every
   * agent batch, recon, and the validator. When unset, agent runs use the
   * agent's `where.maxTurnsPerBatch` (default 50, or 150 when the agent
   * declares no file scope), recon uses 50, validator 50.
   */
  maxTurns?: number;
  /** Candidate files per agent batch. Overrides the agent's `where.maxFilesPerBatch`. */
  maxFilesPerBatch?: number;
  /**
   * Cap the anchor locations packed into one batch. Sibling of
   * `maxFilesPerBatch`: same container, different unit. Both are ceilings,
   * and whichever binds first closes the batch. A single file carrying more
   * anchors than this is split into shards of at most this many, and each
   * prompt anchors on a contiguous line range — the guard against one rule
   * matching 500 places in one file and all of them landing in one prompt.
   * Each shard still carries the whole file as context, so an N-shard file
   * sends its content N times. Source-agnostic: a regex anchor and a semgrep
   * anchor count the same, and anchors sharing a line count once.
   * Defaults to 150 when unset (both CLI and programmatic callers).
   * `--no-max-anchors-per-batch` sets this to `false`, disabling the cap.
   */
  maxAnchorsPerBatch?: number | false;
  /**
   * Cap the candidate files reviewed per agent: when an agent's `where`
   * resolves to more than this many candidates (after prefilter), keep the
   * first N in the walker's deterministic order and drop the rest. A
   * guardrail against an over-broad agent blowing up cost/time on a large
   * repo. Defaults to 300 when unset (both CLI and programmatic callers).
   * `--no-max-files-per-agent` sets this to `false`, disabling the cap.
   * Independent of resume state, so the same N files are chosen across runs.
   */
  maxFilesPerAgent?: number | false;
  /**
   * Cap the TOTAL agent batches run across the whole scan (all agents). Once
   * Phase 1 has enqueued every (agent, batch) pair, the pool is truncated to
   * this many in enqueue order and the rest are dropped. A whole-scan cost/
   * time guardrail — siblings (`maxFilesPerAgent`) cap per-agent instead. An
   * agent whose batches are dropped writes no completion sidecar, so it
   * re-runs next time (per-file resume lifts the batches that did run).
   * Defaults to 250 when unset (both CLI and programmatic callers).
   * `--no-max-batches` sets this to `false`, disabling the cap.
   */
  maxBatches?: number | false;
  /** SDK reasoning effort. Maps to `effort` option. */
  effort?: "low" | "medium" | "high" | "max";
  /** SDK thinking mode. `adaptive` lets the model decide per call; `off` skips entirely. */
  thinking?: "off" | "adaptive" | "enabled";
  /** Drop false-positive findings from the markdown report instead of keeping them (kept by default). */
  excludeFalsePositives?: boolean;
  /**
   * Re-run recon even when a cached brief exists for this output dir.
   * Recon is otherwise reused when the root + stack fingerprint are
   * unchanged. Maps to `--re-recon`.
   */
  reRecon?: boolean;
  /**
   * `--no-recon` → `recon: false`. Skip the recon survey AND precondition
   * gating: no project brief is generated or injected into prompts, and
   * every agent selected via `-t` runs unconditionally (the regex/prompt
   * gates that would otherwise skip irrelevant agents are bypassed). For
   * a focused run where you already know exactly which agents you want.
   * Commander defaults this to `true`; the bare flag sets it `false`.
   */
  recon?: boolean;
  /**
   * `--no-summary` → `summary: false`. Skip the final report-writing step
   * (`summary.md` + per-finding `findings/*.md`). Findings still persist to
   * `state/files/*`; render the report later with `agentgg summary`.
   * Commander defaults this to `true`; the bare flag sets it `false`.
   */
  summary?: boolean;
  /**
   * Run the CVSS 3.1 scoring phase after detection (and after validation).
   * On by default (Commander default `true`); pass `--no-score` to skip it.
   * The scoring agent picks the 8 base metrics per finding; the score and
   * severity bucket are computed deterministically in Node from those
   * choices. Findings the validator marked false-positive or out-of-scope
   * are skipped to avoid paying for findings that won't ship.
   */
  score?: boolean;
  /** Re-score findings even when they already carry a `cvss` on disk. */
  rescore?: boolean;
  /**
   * Run the de-duplication phase at the very end (after detect/validate/
   * score). On by default (Commander default `true`); pass `--no-dedup` to
   * skip it. Groups shippable findings by source file across agents, folds
   * same-root-cause findings under one primary, and marks the rest with a
   * `dedup` field so the report collapses them. The final gather step —
   * it needs every finding for a file co-located, so it cannot be
   * distributed like the earlier phases.
   */
  dedup?: boolean;
  /**
   * With --dedup, physically remove duplicate findings from their
   * FileRecords instead of just marking them. Off by default.
   */
  deleteDuplicates?: boolean;
  /**
   * Boot the local viewer (Next.js) after the scan finishes and keep
   * it running until Ctrl+C. Accepts an optional port; without one,
   * uses the default 3737 (auto-incrementing if busy).
   *   `--serve`           → default port
   *   `--serve 8080`      → port 8080
   *
   * Commander resolves the value to a string when supplied, boolean
   * `true` when the bare flag is passed.
   */
  serve?: boolean | string;
}

/**
 * Orchestrate a scan: recon → preconditions → run queued agents → validate
 * → score → report.
 *
 * Every agent is one unified, tool-enabled shape. An agent with a file
 * scope (`extensions` / `filePatterns`) resolves to a concrete file set,
 * narrowed by `preFilter`, which is reviewed in batches of
 * `maxFilesPerBatch`. An agent with neither has no file scope: the whole
 * repository is its scope, the orchestrator seeds it with no candidates,
 * and it finds its own targets with its tools. See `hasFileScope`. Either
 * way the agent always has Read/Glob/Grep to read beyond what it was
 * seeded. Under `--diff <commit>`, each agent's candidate list is
 * intersected with the files touched in that commit (its own patch,
 * parent → commit, independent of the working tree).
 */
/**
 * Slugs whose batches were dropped by the `--max-batches` cap. An agent is
 * "capped" if ANY of its batches fall beyond `maxBatches` in enqueue order — a
 * partially-dropped agent never completes (remaining > 0), so it counts.
 * Returns [] when the queue fits or the cap is disabled (non-finite).
 */
export function cappedSlugsFromQueue(
  queue: ReadonlyArray<{ agent: { slug: string } }>,
  maxBatches: number,
): string[] {
  if (!Number.isFinite(maxBatches) || queue.length <= maxBatches) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (let i = maxBatches; i < queue.length; i++) {
    const slug = queue[i].agent.slug;
    if (!seen.has(slug)) {
      seen.add(slug);
      out.push(slug);
    }
  }
  return out;
}

export async function runScan(
  rootArg: string,
  opts: ScanOpts,
  env: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  const root = resolve(rootArg);
  const outDir = resolve(opts.output ?? "./scan-results/");
  // Resume identity: compared by the sidecar scope, reconHash, and the plan's
  // auto-exclude replay. `root` stays the real path for reading files.
  const sourceId = opts.sourceId ?? root;

  // -------- per-scan persistence setup --------
  // Nuclei-style: state lives inside the --output dir. The scan-meta
  // sidecar records the absolute root so `revalidate` can resolve
  // relative filePaths back to source files later.
  upsertScanMeta(outDir, root);
  const runMeta = createRunMeta({
    type: "scan",
    invocation: buildInvocation({ command: "scan" }),
  });
  writeRunMeta(outDir, runMeta);
  if (opts.verbose) {
    console.log(`State: ${outDir}\\state  (run ${runMeta.runId})`);
  }

  // SIGINT (Ctrl+C) / SIGTERM handler: mark the run as errored on disk
  // so it doesn't sit in `phase: "running"` forever, then exit with the
  // conventional 128+signal code. Files already persisted stay on disk
  // and a re-run with the same --output resumes past them (see
  // contentHash skip in the per-file loop below). SIGTERM matters when
  // the CLI runs inside a Cloud Run Job — `gcloud run jobs executions
  // cancel` sends SIGTERM, and without this handler Node's default would
  // kill the process immediately, leaving no audit trail of why.
  let runFinalized = false;
  // Assigned once the detector is resolved below. The shutdown handler closes
  // over it so a SIGTERM (Cloud Run Job cancel) flushes the partial token
  // ledger before exit — the basis for billing a cancelled scan.
  let usageMeter: UsageMeter | undefined;
  const shutdownHandler = (signal: NodeJS.Signals) => {
    if (!runFinalized) {
      runFinalized = true;
      // Flush usage first so the tokens spent before the cancel land on disk.
      try {
        usageMeter?.flush();
      } catch {
        // metering must never block shutdown
      }
      try {
        completeRun(outDir, runMeta.runId, "error", {});
      } catch {
        // best-effort; the run file just stays "running"
      }
      console.error("");
      logError(`Interrupted (${signal}). Partial state persisted; re-run to resume.`);
    }
    process.exit(signal === "SIGTERM" ? 143 : 130);
  };
  process.on("SIGINT", shutdownHandler);
  process.on("SIGTERM", shutdownHandler);

  // Scan-wide abort controller. Fired by `handleDetectorError` when a
  // fatal diagnostic (quota exhausted, bad credentials) classifies an
  // error: cancels every in-flight detector HTTP request so sibling
  // workers exit immediately instead of waiting for their (doomed)
  // requests to settle. Each detector call below threads `signal` from
  // here down to the SDK's abortSignal/abortController option.
  //
  // Resume safety: this controller only cancels in-flight requests; it
  // does NOT write any state. `persistDetection` / `writeAgentRun` only
  // run on the happy path of each per-task try block, so a cancelled
  // (file, agent) pair stays "pending" on disk and the next run re-runs
  // it — including under quota cancellation, where rerunning after the
  // user tops up Just Works™.
  const scanAbortController = new AbortController();

  try {
    const config = loadOrSynthesizeConfig(env, opts.provider);

    // Hard-error on any credential flag that isn't meaningful for the
    // active provider, before we touch the LLM. Silent ignore here would
    // mask user-intent mistakes (e.g. `--oauth-token` against Bedrock).
    const activeProvider = (opts.provider ?? config.provider) as Provider;
    validateProviderFlags(activeProvider, opts);

    const credentials = buildCredentialsFromOpts(opts);

    const detector = resolveDetector(config, {
      provider: opts.provider,
      model: opts.model,
      credentials,
      verbose: opts.verbose,
      validateMaxTurns: opts.maxTurns ?? 50,
      effort: opts.effort,
      thinking: opts.thinking,
      openrouterRouting: opts.openrouterRouting,
    });

    // LLM token-usage metering (observability, not billing — you run your own
    // model). The detector records `usage` from every LLM response into this
    // meter, which checkpoints to state/usage.json incrementally (debounced)
    // and is force-flushed on shutdown + finalize. Seeded from any existing
    // usage.json so a retried invocation in the same output dir continues the
    // total instead of resetting. Every provider's detector meters.
    usageMeter = createUsageMeter(outDir, detector.name);
    detector.attachUsageMeter?.(usageMeter);

    // Auto-install official agents on first scan — mirrors how nuclei
    // auto-downloads templates when ~/nuclei-templates/ doesn't exist yet.
    if (!existsSync(getOfficialAgentsDir(env))) {
      logInfo("agentgg-agents are not installed, installing...");
      try {
        const { version, count } = await installOfficialAgents(env);
        logInfo(
          `Successfully installed agentgg-agents at ~/.agentgg/agentgg-agents (${count} agents, ${version})`,
        );
      } catch (err) {
        logWarn(`Could not auto-install agents: ${(err as Error).message}`);
        logWarn("Run `agentgg agents update` to install, or provide agents via -t flag.");
      }
    }

    // Load official + custom agents. Same catalog `agents list` shows.
    // Surface parse errors as warnings so a broken file doesn't block a scan.
    // Structural correctness of the official tree is guaranteed by the
    // agentgg-agents repo's pre-commit hook (`agentgg agents lint`), not
    // re-checked here.
    const catalog = loadAllAgents(env);
    for (const e of catalog.errors) logWarn(e);

    const officialAgentsDir = getOfficialAgentsDir(env);

    // Rule dirs for `semgrepRule` preFilters. `--semgrep-rules` dirs come
    // first, so a local rule shadows the catalog rule of the same name, and
    // `agentgg agents update` (which clears the catalog dir) cannot delete it.
    // A bad path fails here, before any LLM call.
    const semgrepRuleDirs = [
      ...(opts.semgrepRules ?? []).map((d) => {
        const abs = resolve(d);
        if (!existsSync(abs) || !statSync(abs).isDirectory()) {
          throw new Error(`--semgrep-rules: not a directory: ${abs}`);
        }
        return abs;
      }),
      getSemgrepRulesDir(officialAgentsDir),
    ];
    if (semgrepRuleDirs.length > 1) {
      console.log(
        `Semgrep rules: ${semgrepRuleDirs.slice(0, -1).join(", ")} (searched before the catalog)`,
      );
    }

    // `--template` / `-t` filters the catalog. Each value is a slug,
    // a path to a .md file/dir, or a subdirectory name relative to the
    // official agents dir (e.g. "agents/injection/" or "agents/deep/").
    // When no -t is given, default to every category under agents/
    // except the opt-in ones — see `defaultAgentDirs`.
    const templateInputs = opts.template ?? [];
    const defaultDirs = defaultAgentDirs(officialAgentsDir);
    const selectedAgents: Agent[] =
      templateInputs.length > 0
        ? resolveTemplates(templateInputs, catalog.agents, officialAgentsDir)
        : defaultDirs.length > 0
          ? resolveTemplates(defaultDirs, catalog.agents, officialAgentsDir)
          : catalog.agents;
    if (selectedAgents.length === 0) {
      throw new Error("No agents selected — nothing to scan.");
    }

    // Fingerprint the project once — its tags seed the recon agent (a
    // head start on the stack) and are otherwise informational. There is
    // no tech gate anymore: per-agent `precondition` checks decide what
    // runs, so a Go-only repo simply fails the regex/prompt gates of
    // PHP/Python agents instead of being filtered here.
    const project = fingerprint(root);

    // `--diff <commit>` scopes the scan to a single commit's own changes
    // (parent → commit), independent of working tree state. Each agent's
    // candidate list is intersected with the files touched in the commit
    // (`git diff-tree --name-only`), and the commit patch (`git show`) is
    // injected into the agent's prompt as a focus hint; tools stay
    // unrestricted so the agent can chase context outward.
    const diffFiles: Set<string> | undefined = opts.diff
      ? new Set(listChangedFiles(opts.diff, root))
      : undefined;
    const diffPatch: string | undefined = opts.diff ? loadCommitPatch(opts.diff, root) : undefined;

    // CLI `--exclude` paths are treated as DELETED: invisible to recon,
    // the precondition census, and every agent's file selection. They're
    // applied everywhere and can't be opted out of by a template.
    const cliExcludes = [...(opts.exclude ?? [])];
    const includePatterns = opts.only ?? [];
    // `--no-max-file-size` (opts.maxFileSize === false) lifts the size cap.
    // Infinity flows cleanly through the byte comparison and the KB-typed
    // recon/detector configs; the resume scope stores a JSON-safe sentinel.
    const maxFileSizeKb =
      opts.maxFileSize === false ? Number.POSITIVE_INFINITY : (opts.maxFileSize ?? 500);
    const maxFileSizeBytes = maxFileSizeKb * 1024; // Infinity * 1024 === Infinity

    // `--auto-exclude`: before anything else reads the tree, let the model
    // pick folders not worth scanning and fold them in as if the user had
    // typed them as `--exclude`. This runs FIRST (ahead of recon) so recon,
    // the precondition census, and every agent all inherit the excludes.
    // Advisory: a pass failure degrades to "no auto-excludes" rather than
    // aborting the scan. Off by default, and always logged.
    const smartExcludes: string[] = [];
    if (opts.autoExclude) {
      // Reuse the auto-exclude globs a prior `recon` (or `scan`) already chose
      // for this output dir when they exist — the same plan→run hand-off that
      // reuses the recon brief and precondition plan below. This pass runs
      // BEFORE recon, so it can't be keyed on reconHash (not computed yet); the
      // scanned root is the guard, and `--re-recon` forces a fresh pass to
      // mirror how it re-runs the survey + plan. `autoExcludes` is present on
      // the plan only when the pass previously ran, so `undefined` (pass never
      // ran / plan absent) correctly falls through to deriving it now.
      const priorPlan = readScanPlan(outDir);
      const cachedExcludes =
        !opts.reRecon && priorPlan?.rootPath === sourceId ? priorPlan.autoExcludes : undefined;
      if (cachedExcludes !== undefined) {
        for (const g of cachedExcludes) smartExcludes.push(g);
        if (cachedExcludes.length > 0) {
          console.log(
            `Auto-exclude: reusing ${cachedExcludes.length} folder(s) from ${outDir}\\state\\plan.json: ${cachedExcludes.join(", ")} (pass --re-recon to re-derive).`,
          );
        } else {
          console.log(
            `Auto-exclude: reusing prior result from ${outDir}\\state\\plan.json (nothing to drop; pass --re-recon to re-derive).`,
          );
        }
      } else {
        const baselineWalk =
          opts.defaultExcludes === false ? [...cliExcludes] : [...DEFAULT_EXCLUDES, ...cliExcludes];
        try {
          const suggestions = await runSmartExclude({
            rootDir: root,
            detector,
            excludePatterns: baselineWalk,
            includePatterns,
            maxFileSizeBytes,
            signal: scanAbortController.signal,
          });
          for (const s of suggestions) smartExcludes.push(s.glob);
          if (suggestions.length > 0) {
            console.log(
              `Auto-excluded ${suggestions.length} folder(s): ${smartExcludes.join(", ")}`,
            );
            if (opts.verbose) {
              for (const s of suggestions) console.log(`    ${s.glob}: ${s.reason}`);
            }
          } else {
            console.log("Auto-exclude: nothing to drop; scanning the whole tree.");
          }
        } catch (err) {
          logWarn(
            `auto-exclude: pass did not complete (${(err as Error).message}); continuing without it.`,
          );
        }
      }
    }

    // The full deleted set: CLI `--exclude` plus any smart excludes.
    const excludePatterns = [...cliExcludes, ...smartExcludes];

    // The baseline walk excludes = the shared default set + the deleted
    // CLI paths. Recon and the precondition census use this. Per-agent
    // walks below rebuild it so an agent can opt out of the defaults
    // (`where.useDefaultExcludes: false`) while still honoring CLI deletes.
    // `--no-default-excludes` drops the shared set globally for this run.
    const walkExcludes =
      opts.defaultExcludes === false
        ? [...excludePatterns]
        : [...DEFAULT_EXCLUDES, ...excludePatterns];

    // Resolve the scope document. An explicit `--scope <path>` is read
    // verbatim (missing file is fatal — the user asked for it). With the
    // flag omitted we fall back to the bundled default scope so the
    // validator always has trust-boundary rules to reason about
    // `out-of-scope`. `--no-scope` (opts.scope === false) opts out.
    // Passed verbatim into the validator prompt.
    let scopeContent: string | undefined;
    if (typeof opts.scope === "string") {
      const scopePath = resolve(opts.scope);
      try {
        scopeContent = readFileSync(scopePath, "utf8");
      } catch (err) {
        throw new Error(`--scope: cannot read ${scopePath}: ${(err as Error).message}`);
      }
    } else if (opts.scope !== false) {
      scopeContent = loadDefaultScope();
    }

    // Scope-only validation (a cheap, file-read-free pre-filter that
    // classifies each finding against the scope doc alone) is triggered
    // ONLY by an explicit `--scope <path>` without `--validate`. The
    // bundled default must never silently turn a detection-only scan into
    // a validation run, so it does not count here. `--validate` (with or
    // without `--scope`) runs the full source-reading classifier.
    const scopeOnlyValidate = !opts.validate && typeof opts.scope === "string";

    const walkCfg: WalkConfig = {
      excludePatterns: walkExcludes,
      includePatterns,
      maxFileSizeBytes,
    };

    const startedAt = new Date();

    console.log(`Scanning ${root}`);
    console.log(`Agents selected: ${selectedAgents.length}`);
    console.log(`Provider: ${detector.name}`);
    if (templateInputs.length > 0) {
      console.log(`Template filter: ${templateInputs.join(", ")}`);
    }
    if (opts.diff) {
      console.log(
        `Diff mode: reviewing commit ${opts.diff} (${diffFiles?.size ?? 0} file(s) changed)`,
      );
    }
    if (opts.validate) {
      const scopeLabel = typeof opts.scope === "string" ? opts.scope : "default";
      console.log(`Validation: full${scopeContent ? ` (scope: ${scopeLabel})` : ""}`);
    } else if (scopeOnlyValidate) {
      console.log(
        `Validation: scope-only (scope: ${opts.scope}; only out-of-scope verdicts persisted)`,
      );
    }
    if (excludePatterns.length > 0) {
      console.log(`Excluding: ${excludePatterns.join(", ")}`);
    }
    if (includePatterns.length > 0) {
      console.log(`Only: ${includePatterns.join(", ")}`);
    }
    console.log("");

    // `let` (not const): the de-duplication phase may drop deleted
    // duplicates from this list before the report render.
    let findings: Finding[] = [];
    const byAgent: Record<string, number> = {};
    const touchedFiles = new Set<string>();
    // Files that have a FileRecord once this scan ends: written by this run,
    // or reused from a prior one. `touchedFiles` counts
    // CANDIDATES, fixed before any LLM call, so on its own it overstates the
    // work done the moment a batch fails: the batch stamps no records, yet its
    // files still count as scanned. That gap did not exist while a text-less
    // batch was laundered into `{findings: []}` (every candidate got a record
    // either way); it appeared once an empty batch started failing honestly.
    const analyzedFiles = new Set<string>();
    let failedBatchCount = 0;

    // Detection-phase accumulator, keyed by finding id. A file split across
    // shards can have one shard resumed from disk and another re-run, and the
    // re-run may re-report what the lift already added — same inputs, same id.
    // Adding by id keeps that one finding, so the counts, the validator, and
    // the scorer each see it once. Returns how many were actually new.
    // Detection only: the dedupe phase reassigns `findings` afterwards.
    const seenFindingIds = new Set<string>();
    function addFindings(incoming: readonly Finding[]): number {
      let added = 0;
      for (const f of incoming) {
        if (seenFindingIds.has(f.id)) continue;
        seenFindingIds.add(f.id);
        findings.push(f);
        added++;
      }
      return added;
    }

    // Persist findings for one (file, agent) pair into the per-project
    // FileRecord. Merges by finding id so re-runs of the same agent on the
    // same file replace (not duplicate) prior findings.
    // `shardKey` identifies the slice of the file this pass actually
    // analyzed (see anchors.ts). Every candidate persist supplies one, even
    // for a file small enough to run whole. It is omitted only when the model
    // reported a finding in a file that was not a candidate at all, where
    // there is no shard to record.
    function persistDetection(
      relPath: string,
      agent: Agent,
      fileContent: string,
      newFindings: Finding[],
      shardKey?: string,
    ): void {
      const normalized = relPath.replace(/\\/g, "/");
      analyzedFiles.add(normalized);
      let record: FileRecord | null;
      try {
        record = readFileRecord(outDir, agent.slug, normalized);
      } catch {
        record = null;
      }
      if (!record) {
        record = {
          agentSlug: agent.slug,
          filePath: normalized,
          contentHash: hashContent(fileContent),
          candidates: [],
          findings: [],
          analysisHistory: [],
          scope: { outOfScope: false },
          status: "pending",
        };
      }
      const byId = new Map(record.findings.map((f) => [f.id, f]));
      for (const f of newFindings) byId.set(f.id, f);
      record.findings = [...byId.values()];
      // Refresh the content + recon stamps to the inputs actually
      // analyzed this pass — both are the keys per-file resume checks,
      // and refreshing keeps a re-analyzed (changed) file from looking
      // stale on the next resume.
      const nextContentHash = hashContent(fileContent);
      // Either stamp changing means every shard re-runs against new inputs,
      // so the keys recorded under the old ones are dead. Drop them here
      // rather than let a stale key coincide with a new cut and skip a shard.
      //
      // Empty, never `undefined`: absent means "analyzed whole" to resume, and
      // this branch also covers the write for a file the model reached on its
      // own. That file was never reviewed as a candidate, so it must not come
      // out of here looking complete. Only a record written before the cap
      // existed is allowed to have no `shards` field at all.
      if (record.contentHash !== nextContentHash || record.reconHash !== recon.reconHash) {
        record.shards = [];
      }
      if (shardKey !== undefined) {
        const done = record.shards ?? [];
        if (!done.includes(shardKey)) done.push(shardKey);
        record.shards = done;
      }
      record.contentHash = nextContentHash;
      record.reconHash = recon.reconHash;
      record.analysisHistory.push({
        runId: runMeta.runId,
        phase: "detect",
        ranAt: new Date().toISOString(),
        durationMs: 0,
        provider: detector.name,
        agentSlugs: [agent.slug],
        findingCount: newFindings.length,
      });
      record.status = "analyzed";
      try {
        writeFileRecord(outDir, record);
      } catch (err) {
        if (opts.verbose) {
          logError(`persist failed for ${normalized}: ${(err as Error).message}`);
        }
      }
    }

    // -------- PHASE 1 — recon: high-level project brief --------
    // One tool-enabled survey of the repo, cached/resumed by reconHash.
    // The brief is injected into precondition prompt gates and into every
    // queued agent's detection prompt so the model starts oriented.
    //
    // `--no-recon` short-circuits this entirely: no survey runs, no brief
    // is injected (reconBlock is empty), and a synthetic brief with a
    // sentinel reconHash stands in so the rest of the pipeline — resume
    // stamps, plan.json — stays well-formed.
    const skipRecon = opts.recon === false;
    let recon: ReconReport;
    let reconBlock: string;
    if (skipRecon) {
      console.log(
        "\n[1/3] Recon — skipped (--no-recon); every selected agent runs unconditionally.",
      );
      recon = synthesizeSkippedRecon();
      reconBlock = "";
    } else {
      console.log("\n[1/3] Recon — surveying the project…");
      recon = await runRecon({
        rootDir: root,
        outDir,
        sourceId,
        detector,
        fingerprintTags: project.tags,
        excludePatterns: walkExcludes,
        includePatterns,
        maxFileSizeKb,
        maxTurns: opts.maxTurns ?? 50,
        force: opts.reRecon,
        signal: scanAbortController.signal,
        verbose: opts.verbose,
      });
      reconBlock = renderReconForPrompt(recon);
      console.log(
        `Recon: ${recon.languages.length > 0 ? recon.languages.join(", ") : "(languages unknown)"}${
          recon.frameworks.length > 0 ? ` | ${recon.frameworks.join(", ")}` : ""
        }`,
      );
    }

    // Scope signature stamped on each agent's resume sidecar. A change to
    // --diff, --exclude, --only, --max-file-size, root, OR the recon brief
    // invalidates resume and re-runs the agent.
    const currentScope: AgentRun["scope"] = {
      diff: opts.diff,
      excludePatterns: [...excludePatterns],
      includePatterns: [...includePatterns],
      // JSON-safe: Infinity would serialize to null and break resume compares,
      // so store -1 as the "no cap" sentinel. Consistent on both write and read.
      maxFileSizeKb: Number.isFinite(maxFileSizeKb) ? maxFileSizeKb : -1,
      rootPath: sourceId,
      reconHash: recon.reconHash,
    };

    // -------- PHASE 2 — precondition: decide which agents run --------
    // Every selected agent's `precondition` (regex existence checks and/or an
    // LLM prompt gate that sees the recon brief) is evaluated up front, before
    // ANY agent runs. No precondition = always queued. Regex checks are pure
    // filesystem work; only prompt-gated agents incur an LLM call. The result
    // is persisted to state/plan.json as the durable plan→run hand-off.
    // Under `--no-recon` the gate is bypassed: every selected agent is
    // queued unconditionally (prompt gates need the brief that wasn't
    // generated, and the user explicitly asked to run exactly their -t set).
    let queuedAgents: Agent[];
    let decisions: PreconditionDecisionRecord[];
    if (skipRecon) {
      console.log("\n[2/3] Preconditions — skipped (--no-recon); queuing every selected agent.");
      queuedAgents = [...selectedAgents];
      decisions = selectedAgents.map((a) => ({
        slug: a.slug,
        queued: true,
        reason: "recon skipped (--no-recon) — queued unconditionally",
      }));
    } else {
      // Reuse a cached precondition plan when one already exists for this
      // exact recon brief and covers the current agent selection — the
      // plan→run hand-off written by `agentgg recon` (or a prior scan).
      // This is the counterpart to recon caching: just as a matching
      // recon brief is reused instead of re-surveying, a matching plan is
      // reused instead of re-running the precondition for-loop (and, in
      // particular, the per-agent LLM prompt gates). Invalidated by
      // `--re-recon` (which forces a re-survey + re-plan) or by selecting
      // agents the plan never evaluated.
      const cachedPlan = readScanPlan(outDir);
      const planUsable =
        !!cachedPlan &&
        !opts.reRecon &&
        cachedPlan.reconHash === recon.reconHash &&
        selectedAgents.every((a) => cachedPlan.decisions.some((d) => d.slug === a.slug));
      if (planUsable && cachedPlan) {
        const queuedSlugs = new Set(
          cachedPlan.decisions.filter((d) => d.queued).map((d) => d.slug),
        );
        queuedAgents = selectedAgents.filter((a) => queuedSlugs.has(a.slug));
        // Re-derive decisions in selection order from the cached plan so
        // the rewritten plan.json + verbose log reflect exactly this run's
        // selection (a subset of the plan is a valid, narrower plan).
        decisions = selectedAgents.map(
          (a) =>
            cachedPlan.decisions.find((d) => d.slug === a.slug) ?? {
              slug: a.slug,
              queued: true,
              reason: "no precondition",
            },
        );
        console.log(
          `\n[2/3] Preconditions — reusing cached plan from ${outDir}\\state\\plan.json (${queuedAgents.length} queued; pass --re-recon to re-evaluate).`,
        );
      } else {
        console.log("\n[2/3] Preconditions — deciding which agents run…");
        const selection = await selectAgents(selectedAgents, {
          rootDir: root,
          walkCfg,
          detector,
          recon,
          concurrency: opts.concurrency,
          signal: scanAbortController.signal,
          verbose: opts.verbose,
        });
        queuedAgents = selection.queued;
        decisions = selection.decisions;
      }
    }
    const skippedCount = decisions.length - queuedAgents.length;
    // Persist the plan BEFORE any agent runs — this is the artifact a
    // distributed runner consumes to dispatch the queued agents.
    try {
      writeScanPlan(outDir, {
        runId: runMeta.runId,
        generatedAt: new Date().toISOString(),
        reconHash: recon.reconHash,
        rootPath: sourceId,
        decisions,
        // Persist the auto-excludes in effect this run so a later scan against
        // the same output dir reuses them instead of re-deriving (mirrors how
        // `recon` records them). Present only when the pass ran or was reused;
        // `--no-auto-exclude` writes `undefined`, matching recon's producer.
        autoExcludes: opts.autoExclude ? smartExcludes : undefined,
      });
    } catch (err) {
      if (opts.verbose) logError(`plan: failed to write: ${(err as Error).message}`);
    }
    console.log(
      `Preconditions: ${queuedAgents.length} queued, ${skippedCount} skipped → ${outDir}\\state\\plan.json`,
    );
    if (opts.verbose) {
      for (const d of decisions) {
        console.log(`  ${d.queued ? "[queued] " : "[skipped]"} ${d.slug}: ${d.reason}`);
      }
    }

    // Cached FileRecords used by agent-level resume to lift prior findings
    // on skip. Loaded lazily so a first scan (empty state) doesn't pay.
    let allRecordsCache: FileRecord[] | null = null;
    const getAllRecords = (): FileRecord[] => {
      if (allRecordsCache === null) {
        allRecordsCache = loadAllFileRecords(outDir);
      }
      return allRecordsCache;
    };
    // -------- run queued agents --------
    // One unified path: every agent is a tool-enabled investigation. An
    // agent with a file scope resolves `where` to seeded candidate files
    // (extensions/filePatterns + preFilter, intersected with --diff),
    // reviewed in batches, with tools to read beyond its seeds. An agent
    // with no file scope gets no candidates: the whole repository is its
    // scope and it finds its own targets with those same tools. Findings
    // are stamped with the agent's slug.
    //
    // Resume is per-agent: a completed agent with a matching scope
    // (including reconHash) is skipped and its findings lifted from disk.
    // An interrupted agent (no sidecar) re-runs in full.
    //
    // Concurrency model: every (agent, batch) pair across ALL queued agents
    // is fed through ONE bounded worker pool, so batches from different
    // agents overlap instead of agents running one-at-a-time. `--concurrency`
    // caps TOTAL in-flight batches across the whole scan (it used to cap
    // batches within a single agent). Safe because every disk write is
    // namespaced by agent.slug, so disjoint agents never collide. Phase 1
    // (the loop below) resolves each agent to its batches sequentially —
    // cheap: walk + prefilter + resume, no LLM — and enqueues them; Phase 2
    // drains the pool.
    const concurrency = Math.max(1, opts.concurrency ?? 5);
    // Cost/time guardrails. Default 300 files/agent and 250 batches/scan;
    // an unset opt (programmatic caller) gets the same defaults as the CLI.
    // `--no-max-files-per-agent` / `--no-max-batches` set the opt to `false`,
    // which resolves to Infinity here so the `> 0` cap checks never fire.
    const maxFilesPerAgent =
      opts.maxFilesPerAgent === false ? Number.POSITIVE_INFINITY : (opts.maxFilesPerAgent ?? 300);
    const maxBatches =
      opts.maxBatches === false ? Number.POSITIVE_INFINITY : (opts.maxBatches ?? 250);
    // Anchor ceiling per batch. Deliberately well above a normal batch's load
    // so it fires on the pathological file (one rule matching hundreds of
    // places) instead of quietly reshaping every scan's batching — smaller
    // batches mean more of them, and more batches run into `maxBatches`.
    // 0, a negative, and a non-numeric value all resolve to "no cap", matching
    // the `> 0` sentinel the sibling caps use. Normalizing here rather than at
    // each use keeps the splitter and the packer from reading one value two
    // ways — 0 would otherwise disable the split but close a batch per file.
    const rawMaxAnchors =
      opts.maxAnchorsPerBatch === false
        ? Number.POSITIVE_INFINITY
        : (opts.maxAnchorsPerBatch ?? 150);
    const maxAnchorsPerBatch =
      Number.isFinite(rawMaxAnchors) && rawMaxAnchors > 0
        ? rawMaxAnchors
        : Number.POSITIVE_INFINITY;
    let cachedAgentCount = 0;
    // Agents whose candidate list was truncated by `--max-files-per-agent`.
    let cappedAgentCount = 0;
    const diffArg =
      opts.diff && diffPatch !== undefined ? { commit: opts.diff, patch: diffPatch } : undefined;
    /** The turn budget for one session. The default depends on scope: an agent
     *  that must find its own targets spends turns on the search before it
     *  spends any on judgement, so 50 (right for a pre-seeded batch) starves it. */
    const resolveMaxTurns = (agent: Agent): number =>
      opts.maxTurns ?? agent.where.maxTurnsPerBatch ?? (hasFileScope(agent) ? 50 : 150);
    type AgentRuntime = {
      // Batches not yet settled; the resume sidecar is written when it hits 0.
      remaining: number;
      // Sticky: any failed batch suppresses the sidecar so the agent re-runs.
      failed: boolean;
      agentExcludes: string[];
      maxTurns: number;
      // True when the orchestrator handed this agent a candidate file set.
      // False for an agent with no file scope, which searched the whole
      // repository itself: `filesReviewed` then counts `reportedFiles`
      // instead of the (nonexistent) candidate count.
      seeded: boolean;
      filesReviewed: number;
      // Distinct files this agent's findings named. The only honest
      // "files reviewed" count for an unseeded agent, which has no
      // candidate set to measure against.
      reportedFiles: Set<string>;
      hitCount: number;
      degraded: { kind: "semgrep"; reason: string }[];
      preFilterHits: { regex: number; semgrep: number };
    };
    const runtimeBySlug = new Map<string, AgentRuntime>();
    const batchQueue: { agent: Agent; batch: AgentCandidate[] }[] = [];
    if (queuedAgents.length > 0) {
      console.log(
        `\n[3/3] Agents — ${queuedAgents.length} queued (completed agents are reused from prior runs; only new/changed work calls the LLM)…`,
      );
    }
    // Pass 1: resolve each agent to the file set it will review. Cheap —
    // resume check + walk, no LLM and no engine — and it has to finish before
    // semgrep runs, because the project pass needs every agent's files at once.
    const prepared: { agent: Agent; agentExcludes: string[]; scopedFiles: string[] }[] = [];
    // Agents that declare no extensions and no filePatterns. Held apart from
    // `prepared` because they skip the walk, the prefilter, and the project
    // semgrep pass entirely — there is nothing to seed them with.
    const unseeded: { agent: Agent; agentExcludes: string[] }[] = [];
    for (const agent of queuedAgents) {
      if (!opts.rescan) {
        const prior = readAgentRun(outDir, agent.slug);
        if (prior && scopeMatches(prior.scope, currentScope)) {
          const cached = getAllRecords()
            .flatMap((r) => r.findings)
            .filter((f) => f.agentSlug === agent.slug);
          byAgent[agent.slug] = (byAgent[agent.slug] ?? 0) + addFindings(cached);
          for (const f of cached) {
            if (f.filePath && f.filePath !== "(unknown)") touchedFiles.add(f.filePath);
          }
          cachedAgentCount++;
          console.log(
            `  ${agent.slug}: cached (${cached.length} finding(s) from prior run; pass --rescan to force)`,
          );
          continue;
        }
        if (opts.verbose && prior) {
          console.log(
            `  ${agent.slug}: sidecar ignored (${scopeMismatchReason(prior.scope, currentScope)}) — re-running`,
          );
        }
      }

      // Effective excludes for this agent: the default set (unless the
      // agent opted out) + the deleted CLI paths + the agent's own
      // declared excludes. CLI deletes always apply; defaults are
      // overridable per template via `where.useDefaultExcludes`.
      const agentBaseExcludes =
        agent.where.useDefaultExcludes === false ? excludePatterns : walkExcludes;
      const agentExcludes = Array.from(
        new Set([...agentBaseExcludes, ...agent.where.excludePatterns]),
      );

      // No file scope declared: the whole repository is this agent's scope,
      // so it gets no seeded candidates and the walk, the prefilter, the
      // project semgrep pass and the per-agent file cap have nothing to do.
      // Keeping it out of `prepared` is what excludes it from all four —
      // above all from the zero-candidate early exit below, which would
      // otherwise write a clean completion sidecar without ever running it.
      if (!hasFileScope(agent)) {
        unseeded.push({ agent, agentExcludes });
        continue;
      }

      const agentWalkCfg: WalkConfig = {
        excludePatterns: agentBaseExcludes,
        includePatterns,
        maxFileSizeBytes,
      };
      // Resolve `where` → seeded candidate files. The walker enumerates every
      // file the `where` includes (`extensions` / `filePatterns`), then
      // `preFilter` narrows to anchor-carrying files (empty preFilter = every
      // included file is a candidate). Under --diff, the list is intersected
      // with the changed-file set. Only agents that declare a file scope reach
      // here; the branch above already took the rest.
      const [work] = walkForAgents(root, [agent], agentWalkCfg);
      const files = work ? work.files : [];
      const scopedFiles = diffFiles ? files.filter((f) => diffFiles.has(f)) : files;
      prepared.push({ agent, agentExcludes, scopedFiles });
    }

    // `semgrepRule` preFilters run ONCE for the whole scan, over the union of
    // every agent's files. The engine then parses each file a single time and
    // matches every rule against that one tree, instead of re-parsing it per
    // rule and per agent. Per-line regex entries stay in the loop below.
    const semgrepProject = await runSemgrepProject(
      root,
      prepared.map(({ agent, scopedFiles }) => ({ agent, files: scopedFiles })),
      semgrepRuleDirs,
      concurrency,
      (m) => logWarn(m),
      env,
      { onInfo: opts.verbose ? (m) => console.log(`  ${m}`) : undefined },
    );

    // One batch, no candidates. The prompt swaps its candidate block for a
    // scope block (see buildAgentPrompt), and the agent finds its own targets
    // with its Read/Glob/Grep tools. This counts as one pair toward
    // --max-batches like any other batch.
    //
    // Enqueued BEFORE every seeded batch, and the position is deliberate.
    // `--max-batches` truncates the queue from the end, so enqueue order
    // decides what gets dropped. One of these costs exactly one pair while an
    // agent with a file scope can cost hundreds, so going last would mean that
    // on any repository whose seeded queue alone exceeds the cap, an agent with
    // no file scope never runs, on any number of repeated scans.
    for (const { agent, agentExcludes } of unseeded) {
      const maxTurns = resolveMaxTurns(agent);
      console.log(
        `  ${agent.slug}: no file scope, whole repository → 1 session of up to ${maxTurns} turns`,
      );
      runtimeBySlug.set(agent.slug, {
        remaining: 1,
        failed: false,
        agentExcludes,
        maxTurns,
        seeded: false,
        filesReviewed: 0,
        reportedFiles: new Set(),
        hitCount: 0,
        degraded: [],
        preFilterHits: { regex: 0, semgrep: 0 },
      });
      batchQueue.push({ agent, batch: [] });
    }

    // Pass 2: build each agent's candidates and enqueue its batches.
    for (const { agent, agentExcludes, scopedFiles } of prepared) {
      const candidates: AgentCandidate[] = [];
      const semgrepHits = semgrepProject.byAgent.get(agent.slug) ?? new Map();
      const semgrepDegraded = semgrepProject.degradedByAgent.get(agent.slug) ?? null;
      // Recorded on the sidecar so the report cannot imply coverage this
      // agent did not have.
      const degraded = semgrepDegraded
        ? [{ kind: "semgrep" as const, reason: semgrepDegraded }]
        : [];
      // Anchors split by source. An agent with no regex entries must not have
      // the synthetic "(no preFilter)" hit counted as one.
      const hasRegexEntry = agent.where.preFilter.some((p) => !isSemgrepPreFilter(p));
      const declaresSemgrep = agent.where.preFilter.some(isSemgrepPreFilter);
      const preFilterHits = { regex: 0, semgrep: 0 };
      for (const relPath of scopedFiles) {
        let content: string;
        try {
          content = readFileSync(resolve(root, relPath), "utf8");
        } catch {
          continue;
        }
        const hits = evaluatePreFilter(content, agent.where.preFilter);
        if (hasRegexEntry) preFilterHits.regex += hits.length;
        const fileSemgrepHits = semgrepHits.get(relPath);
        if (fileSemgrepHits && fileSemgrepHits.length > 0) {
          const lines = content.split("\n");
          for (const h of fileSemgrepHits) {
            if (isSemgrepSuppressed(lines, h.line)) continue;
            // Spread, so message/metadata/taint ride along without this
            // call site having to know every enrichment field.
            hits.push({
              ...h,
              snippet: (lines[h.line - 1] ?? "").trim().slice(0, 200),
            });
            preFilterHits.semgrep++;
          }
        }
        if (hits.length === 0) continue;
        candidates.push({ filePath: relPath, content, hits });
      }

      // `--max-files-per-agent` cap: review at most N candidate files per
      // agent — keep the first N in the walker's deterministic order and
      // drop the rest. A guardrail so an over-broad agent (e.g. one matching
      // every .ts file) can't blow up cost/time on a large repo. Stable walk
      // order means the same N files are chosen across runs, so per-file
      // resume stays consistent. Default 300; --no-max-files-per-agent (→
      // Infinity) disables it.
      if (maxFilesPerAgent > 0 && candidates.length > maxFilesPerAgent) {
        const dropped = candidates.length - maxFilesPerAgent;
        cappedAgentCount++;
        candidates.length = maxFilesPerAgent;
        console.log(
          `  ${agent.slug}: capped to ${maxFilesPerAgent} candidate file(s) (--max-files-per-agent; ${dropped} dropped)`,
        );
      }
      // Only the candidates the agent will actually review count as scanned.
      for (const c of candidates) touchedFiles.add(c.filePath);

      // Deterministic "how much work" signals for this agent, fixed before
      // any LLM call: files it reviews and total pre-filter anchor matches.
      const filesReviewed = candidates.length;
      const hitCount = candidates.reduce((sum, c) => sum + c.hits.length, 0);

      if (candidates.length === 0) {
        if (opts.verbose) console.log(`  ${agent.slug}: no candidate files`);
        try {
          writeAgentRun(outDir, {
            agentSlug: agent.slug,
            lastCompletedRunId: runMeta.runId,
            lastCompletedAt: new Date().toISOString(),
            scope: currentScope,
            precondition: { queued: true },
            findingCount: 0,
            seeded: true,
            filesReviewed,
            hitCount,
            degraded,
            preFilterHits,
          });
          allRecordsCache = null;
        } catch {
          // best-effort
        }
        continue;
      }

      // `--max-anchors-per-batch`: split a file carrying more anchor
      // locations than the cap into shards, one prompt each, anchored on a
      // contiguous line range. Deliberately placed AFTER the per-agent
      // file cap (so that cap still counts files, not shards) and AFTER
      // filesReviewed/hitCount (so both stay file-level), but BEFORE resume,
      // so each shard is resumed on its own key.
      const shardedCandidates = candidates.flatMap((c) => shardCandidate(c, maxAnchorsPerBatch));
      if (shardedCandidates.length > candidates.length) {
        const splitFiles = candidates.filter((c) => anchorLoad(c) > maxAnchorsPerBatch).length;
        console.log(
          `  ${agent.slug}: ${splitFiles} anchor-dense file(s) split into ${shardedCandidates.length - candidates.length + splitFiles} prompt(s) (--max-anchors-per-batch ${maxAnchorsPerBatch})`,
        );
      }

      // Per-file resume: within an agent interrupted before its
      // completion sidecar was written, skip candidate files already
      // analyzed under the SAME content AND recon brief, lifting their
      // saved findings from disk. A changed file (contentHash) or changed
      // brief (reconHash) re-runs that file; --rescan re-runs everything.
      //
      // Shards make this per-shard, not per-file: the content and recon
      // stamps are refreshed by whichever shard finishes first, so a file
      // also has to show this shard's key in `record.shards` to count as
      // done. A record with no `shards` field predates the anchor cap and
      // was analyzed whole, so it counts as done for every shard.
      let pending = shardedCandidates;
      if (!opts.rescan) {
        const todo: AgentCandidate[] = [];
        // A file's findings are stored per file, not per shard, so they are
        // lifted at most once even when several of its shards resume.
        const lifted = new Set<string>();
        let resumedFiles = 0;
        let resumedShards = 0;
        let resumedFindings = 0;
        for (const c of shardedCandidates) {
          const normalized = c.filePath.replace(/\\/g, "/");
          let rec: FileRecord | null = null;
          try {
            rec = readFileRecord(outDir, agent.slug, normalized);
          } catch {
            rec = null;
          }
          const reusable =
            rec !== null &&
            rec.contentHash === hashContent(c.content) &&
            rec.reconHash === recon.reconHash &&
            (rec.shards === undefined || rec.shards.includes(shardKeyOf(c)));
          if (reusable && rec) {
            resumedShards++;
            if (!lifted.has(normalized)) {
              lifted.add(normalized);
              // Reused from a prior run, so persistDetection is never called
              // for it here. It still has a record on disk, which is what
              // `analyzedFiles` counts.
              analyzedFiles.add(normalized);
              byAgent[agent.slug] = (byAgent[agent.slug] ?? 0) + addFindings(rec.findings);
              for (const f of rec.findings) {
                if (f.filePath && f.filePath !== "(unknown)") touchedFiles.add(f.filePath);
              }
              resumedFiles++;
              resumedFindings += rec.findings.length;
            }
            continue;
          }
          todo.push(c);
        }
        if (resumedShards > 0) {
          const shardNote =
            shardedCandidates.length > candidates.length
              ? ` (${resumedShards}/${shardedCandidates.length} prompt(s))`
              : "";
          console.log(
            `  ${agent.slug}: resuming — ${resumedFiles}/${candidates.length} file(s) already analyzed${shardNote} (${resumedFindings} finding(s)) reused`,
          );
        }
        pending = todo;
      }
      // Everything already analyzed (e.g. the agent finished its batches
      // but crashed before the completion sidecar landed) → mark the
      // agent complete and move on.
      if (pending.length === 0) {
        try {
          writeAgentRun(outDir, {
            agentSlug: agent.slug,
            lastCompletedRunId: runMeta.runId,
            lastCompletedAt: new Date().toISOString(),
            scope: currentScope,
            precondition: { queued: true },
            findingCount: byAgent[agent.slug] ?? 0,
            seeded: true,
            filesReviewed,
            hitCount,
            degraded,
            preFilterHits,
          });
          allRecordsCache = null;
        } catch {
          // best-effort
        }
        continue;
      }

      const maxTurns = resolveMaxTurns(agent);
      const batchSize = Math.max(1, opts.maxFilesPerBatch ?? agent.where.maxFilesPerBatch);

      // Candidates are packed into batches under two ceilings: `batchSize`
      // entries and `maxAnchorsPerBatch` anchor locations. The batches are
      // not run here — they're enqueued into the shared pool drained in
      // Phase 2, so they interleave with every other agent's batches.
      const batches = packBatches(pending, batchSize, maxAnchorsPerBatch);

      // Only agents that declare a semgrep rule get the attribution suffix, so
      // every other agent's output is unchanged.
      const anchorNote = declaresSemgrep
        ? `, ${preFilterHits.regex + preFilterHits.semgrep} anchor(s) (semgrep ${preFilterHits.semgrep}, regex ${preFilterHits.regex})`
        : "";
      const pendingFiles = new Set(pending.map((c) => c.filePath)).size;
      console.log(
        `  ${agent.slug}: ${pendingFiles} candidate file(s)${anchorNote} → ${batches.length} batch(es) of up to ${batchSize}`,
      );

      runtimeBySlug.set(agent.slug, {
        remaining: batches.length,
        failed: false,
        agentExcludes,
        maxTurns,
        seeded: true,
        filesReviewed,
        reportedFiles: new Set(),
        hitCount,
        degraded,
        preFilterHits,
      });
      for (const batch of batches) batchQueue.push({ agent, batch });
    }

    // `--max-batches` cap: keep at most N (agent, batch) pairs across the
    // whole scan in enqueue order, drop the rest. A truncated/dropped agent
    // keeps `rt.remaining > 0`, so it writes no completion sidecar and re-runs
    // next time (per-file resume lifts what ran). Do NOT lower `remaining` to
    // the kept count — that would wrongly mark a truncated agent complete.
    // Default 250; --no-max-batches (→ Infinity) disables it.
    if (maxBatches > 0 && batchQueue.length > maxBatches) {
      const cappedSlugs = cappedSlugsFromQueue(batchQueue, maxBatches);
      const dropped = batchQueue.length - maxBatches;
      batchQueue.length = maxBatches;
      console.log(
        `  Capping to ${maxBatches} batch(es) across all agents (--max-batches; ${dropped} dropped → ${cappedSlugs.length} agent(s) capped)`,
      );
      // Durable, machine-readable record of capped agents. A platform runner
      // reads state/capped.json to mark them `capped` (not failed) rather than
      // solo-retrying them, which would defeat the whole-scan cap.
      try {
        writeFileSync(
          join(outDir, "state", "capped.json"),
          JSON.stringify({ slugs: cappedSlugs }, null, 2),
        );
      } catch (err) {
        logError(`failed to write capped.json: ${(err as Error).message}`);
      }
    }

    // -------- Phase 2: drain the batch pool --------
    // One bounded worker pool over every enqueued (agent, batch) pair.
    // Batches from different agents run concurrently up to `concurrency`.
    if (batchQueue.length > 0) {
      console.log(
        `  Running ${batchQueue.length} batch(es) across ${runtimeBySlug.size} agent(s) at concurrency ${concurrency}…`,
      );
    }
    await runConcurrent(batchQueue, concurrency, async ({ agent, batch }) => {
      const rt = runtimeBySlug.get(agent.slug);
      if (!rt) return;
      try {
        const batchFindings = await detector.runAgent({
          agent,
          rootDir: root,
          recon: reconBlock,
          candidates: batch,
          excludePatterns: rt.agentExcludes,
          maxFileSizeKb,
          maxTurns: rt.maxTurns,
          diff: diffArg,
          signal: scanAbortController.signal,
        });
        // Last-resort guard against a model inventing a file. The detector
        // has already mapped a mis-spelled path onto its batch candidate (see
        // repairFindingPath), so anything still unresolvable names no file the
        // agent was given and no file on disk.
        //
        // Warns rather than logging under --verbose: this DISCARDS a finding
        // the model actually reported, and the file record it leaves behind is
        // indistinguishable from clean code. Losing analysis silently is the
        // failure this scan path exists to avoid, so it is never quiet.
        const valid = batchFindings.filter((f) => {
          if (!f.filePath || f.filePath === "(unknown)") {
            // A seeded batch never reaches here in practice: the detector
            // anchors an anchorless finding onto its first candidate. Keep
            // that path exactly as it was.
            if (batch.length > 0) return true;
            // A batch with no candidates has no such fallback, so this is the
            // only case that produces a finding naming no file. Findings with
            // no file anchor are not supported, and keeping one is worse than
            // dropping it: it counts into the agent total and the report, but
            // writes no file record, so the next scan resumes the agent as
            // cleanly cached with nothing to show for it.
            logWarn(
              `${agent.slug}: discarded a finding that names no file. This agent has no file ` +
                `scope, so there is no candidate file to anchor it to`,
            );
            return false;
          }
          if (existsSync(resolve(root, f.filePath))) return true;
          logWarn(
            `${agent.slug}: discarded a finding naming "${f.filePath}", which is neither a file ` +
              `on disk nor one of this batch's files`,
          );
          return false;
        });
        byAgent[agent.slug] = (byAgent[agent.slug] ?? 0) + addFindings(valid);
        for (const f of valid) {
          if (f.filePath && f.filePath !== "(unknown)") {
            touchedFiles.add(f.filePath);
            rt.reportedFiles.add(f.filePath);
          }
        }
        if (opts.verbose || valid.length > 0) {
          // A batch with no candidate files has no paths to name, so it says
          // what it covered instead of rendering an empty bracket.
          const label =
            batch.length > 0 ? batch.map((c) => c.filePath).join(", ") : "whole repository";
          console.log(`    ${agent.slug} [${label}]: ${valid.length} finding(s)`);
        }
        // Persist findings grouped by file.
        const byFile = new Map<string, Finding[]>();
        for (const f of valid) {
          if (!f.filePath || f.filePath === "(unknown)") continue;
          const list = byFile.get(f.filePath) ?? [];
          list.push(f);
          byFile.set(f.filePath, list);
        }
        for (const [relPath, group] of byFile) {
          const inBatch = batch.find((c) => c.filePath === relPath);
          let content: string;
          if (inBatch) {
            content = inBatch.content;
          } else {
            try {
              content = readFileSync(resolve(root, relPath), "utf8");
            } catch {
              continue;
            }
          }
          // A file the model reached on its own (not in this batch) has no
          // shard to record, so it passes no key.
          persistDetection(
            relPath,
            agent,
            content,
            group,
            inBatch ? shardKeyOf(inBatch) : undefined,
          );
        }
        // Stamp an empty record for candidate files with no findings so
        // `status` reports candidate files with no findings as analyzed.
        for (const c of batch) {
          if (byFile.has(c.filePath)) continue;
          persistDetection(c.filePath, agent, c.content, [], shardKeyOf(c));
        }
      } catch (err) {
        rt.failed = true;
        failedBatchCount++;
        // Fatal errors (bad creds, quota) throw out of here → runConcurrent
        // stops dispatching, drains in-flight, and rethrows. Recoverable
        // ones are logged and the pool continues.
        handleDetectorError(opts, `agent:${agent.slug}`, err, scanAbortController);
      } finally {
        // Write the agent's resume sidecar exactly once, when its LAST batch
        // settles, and only if no batch failed — a failed agent leaves no
        // sidecar and re-runs next time. No per-agent timing: under the
        // shared pool an agent isn't a contiguous runtime unit (its batches
        // interleave with other agents'), so filesReviewed/hitCount are the
        // meaningful per-agent signals; whole-scan time lives in RunMeta.
        rt.remaining--;
        if (rt.remaining === 0 && !rt.failed) {
          try {
            writeAgentRun(outDir, {
              agentSlug: agent.slug,
              lastCompletedRunId: runMeta.runId,
              lastCompletedAt: new Date().toISOString(),
              scope: currentScope,
              precondition: { queued: true },
              findingCount: byAgent[agent.slug] ?? 0,
              seeded: rt.seeded,
              // A seeded agent's count is its candidate set, fixed before any LLM
              // call. An agent that searched for itself has no such denominator, so
              // the only honest count is the files it actually reported on.
              filesReviewed: rt.seeded ? rt.filesReviewed : rt.reportedFiles.size,
              hitCount: rt.hitCount,
              degraded: rt.degraded,
              preFilterHits: rt.preFilterHits,
            });
            allRecordsCache = null;
          } catch (err) {
            if (opts.verbose) {
              logError(`${agent.slug}: failed to write resume sidecar: ${(err as Error).message}`);
            }
          }
        }
      }
    });
    if (queuedAgents.length > 0) {
      const ranCount = queuedAgents.length - cachedAgentCount;
      console.log(
        `  Agents: ${ranCount} ran, ${cachedAgentCount} reused from prior run${
          cachedAgentCount > 0 ? " (pass --rescan to force a full re-run)" : ""
        }${cappedAgentCount > 0 ? `; ${cappedAgentCount} capped by --max-files-per-agent` : ""}`,
      );
    }

    // -------- validation phase --------
    // Two opt-in modes:
    //   - `--validate`: full classifier — re-reads source, with --scope
    //     context if provided. Doubles LLM cost.
    //   - `--scope` alone (no --validate): scope-only classifier — never
    //     re-reads source, only emits `out-of-scope` verdicts. Cheap
    //     pre-filter; in-scope/uncertain leave the finding's validation
    //     field untouched so a follow-up `revalidate` can do full
    //     classification.
    if ((opts.validate || scopeOnlyValidate) && findings.length > 0) {
      const candidates = findings.filter((f) => f.filePath && f.filePath !== "(unknown)");
      // Resume path: skip findings that already carry a verdict on disk.
      // `--revalidate-all` bypasses the skip and forces re-classification.
      const validatable = opts.revalidateAll ? candidates : candidates.filter((f) => !f.validation);
      const carriedOver = candidates.length - validatable.length;
      if (validatable.length > 0 || carriedOver > 0) {
        const scopeNote = scopeContent ? " with scope" : "";
        const carryNote = carriedOver > 0 ? ` (${carriedOver} cached)` : "";
        const modeNote = scopeOnlyValidate ? " — scope-only mode" : "";
        console.log(
          `\nValidating ${validatable.length} finding(s)${scopeNote}${carryNote}${modeNote} at concurrency ${concurrency}`,
        );
        const fileCache = new Map<string, string | null>();
        // A finding only carries `agentSlug`, so resolve its reporting agent
        // here to pick up an agent-authored `validationPrompt`. Built from the
        // whole catalog, not the selection: a finding restored from a prior
        // run can come from an agent this run's `-t` filter left out.
        const agentBySlug = new Map(catalog.agents.map((a) => [a.slug, a]));
        if (!scopeOnlyValidate) {
          const withCustomPrompt = validatable.filter(
            (f) => agentBySlug.get(f.agentSlug)?.validationPrompt,
          ).length;
          if (withCustomPrompt > 0) {
            console.log(`  ${withCustomPrompt} use their agent's own validation prompt`);
          }
        }
        // One bounded pool over findings. Each finding is a distinct object
        // and fileCache is only touched in await-free regions, so workers
        // don't race; verdicts are persisted below once the pool drains.
        await runConcurrent(validatable, concurrency, async (finding) => {
          // Scope-only branch: never read the file, only ask the LLM to
          // classify against --scope, and only persist `out-of-scope`.
          // Findings the scope doesn't disqualify are left untouched so a
          // follow-up `revalidate` (full mode) can still assess them.
          if (scopeOnlyValidate && scopeContent !== undefined) {
            try {
              const result = await detector.validateFindingByScope({
                finding,
                scope: scopeContent,
                signal: scanAbortController.signal,
              });
              if (result.verdict === "out-of-scope") {
                finding.validation = {
                  verdict: result.verdict,
                  reasoning: result.reasoning,
                };
              }
              if (opts.verbose) {
                const note =
                  result.verdict === "out-of-scope"
                    ? "marked out-of-scope"
                    : "kept (scope did not disqualify)";
                console.log(`    ${finding.filePath}: ${result.verdict} — ${note}`);
              }
            } catch (err) {
              handleDetectorError(opts, `scope-validate:${finding.id}`, err, scanAbortController);
            }
            return;
          }

          let content = fileCache.get(finding.filePath);
          if (content === undefined) {
            try {
              content = readFileSync(resolve(root, finding.filePath), "utf8");
            } catch {
              content = null;
            }
            fileCache.set(finding.filePath, content);
          }
          if (content === null) {
            console.log(`    skip ${finding.id}: file not readable (${finding.filePath})`);
            return;
          }
          try {
            const result = await detector.validateFinding({
              finding,
              fileContent: content,
              scope: scopeContent,
              root,
              // Cross-file tracing honors the same walk excludes + size cap
              // as detection, so the validator can't read past --exclude.
              excludePatterns: walkExcludes,
              maxFileSizeKb,
              // Undefined when the agent declares none, or when its slug is no
              // longer in the catalog: the validator falls back to its defaults.
              validationPrompt: agentBySlug.get(finding.agentSlug)?.validationPrompt,
              signal: scanAbortController.signal,
            });
            finding.validation = {
              verdict: result.verdict,
              reasoning: result.reasoning,
              ...(result.refused ? { refused: true } : {}),
            };
            if (result.refused) {
              console.log(`    ${finding.filePath}: validation refused, recorded as uncertain`);
            } else if (opts.verbose) {
              console.log(`    ${finding.filePath}: ${result.verdict}`);
            }
          } catch (err) {
            handleDetectorError(opts, `validate:${finding.id}`, err, scanAbortController);
          }
        });
        // Persist validation verdicts back into the per-(agent, file)
        // shards. Group by (agentSlug, filePath) so each shard is
        // rewritten once.
        const byShard = new Map<
          string,
          { agentSlug: string; filePath: string; findings: Finding[] }
        >();
        for (const f of validatable) {
          if (!f.validation) continue;
          const normalized = f.filePath.replace(/\\/g, "/");
          if (isAbsolute(normalized)) continue;
          const key = `${f.agentSlug} ${normalized}`;
          const entry = byShard.get(key) ?? {
            agentSlug: f.agentSlug,
            filePath: normalized,
            findings: [],
          };
          entry.findings.push(f);
          byShard.set(key, entry);
        }
        for (const { agentSlug, filePath, findings: group } of byShard.values()) {
          const record = readFileRecord(outDir, agentSlug, filePath);
          if (!record) continue;
          const inMemory = new Map(group.map((f) => [f.id, f]));
          record.findings = record.findings.map((rec) => {
            const live = inMemory.get(rec.id);
            return live?.validation ? { ...rec, validation: live.validation } : rec;
          });
          record.analysisHistory.push({
            runId: runMeta.runId,
            phase: "validate",
            ranAt: new Date().toISOString(),
            durationMs: 0,
            provider: detector.name,
            agentSlugs: [agentSlug],
            findingCount: group.length,
          });
          record.status = "validated";
          try {
            writeFileRecord(outDir, record);
          } catch (err) {
            if (opts.verbose) {
              logError(`persist failed for ${agentSlug}/${filePath}: ${(err as Error).message}`);
            }
          }
        }
        // Final tally combines this-run verdicts and carried-over ones so
        // the summary reflects every classified finding, not just freshly
        // validated ones.
        const finalVerdicts: Record<string, number> = {};
        for (const f of candidates) {
          if (!f.validation) continue;
          finalVerdicts[f.validation.verdict] = (finalVerdicts[f.validation.verdict] ?? 0) + 1;
        }
        const summary = Object.entries(finalVerdicts)
          .sort()
          .map(([v, n]) => `${v}=${n}`)
          .join(", ");
        console.log(`  Verdicts: ${summary || "(none)"}`);
      }
    }

    // -------- scoring phase --------
    // Pick CVSS 3.1 metrics per finding; assemble the full CvssScore in
    // Node from those choices. Runs after validation so the scorer skips
    // findings the validator already disqualified (false-positive /
    // out-of-scope) — no point spending tokens on findings that won't
    // ship. Without --validate, every detected finding is scored.
    if (opts.score && findings.length > 0) {
      const isDisqualified = (f: Finding): boolean => {
        const v = f.validation?.verdict;
        return v === "false-positive" || v === "out-of-scope";
      };
      const scorable = findings.filter(
        (f) =>
          f.filePath &&
          f.filePath !== "(unknown)" &&
          !isDisqualified(f) &&
          (opts.rescore || !f.cvss),
      );
      const skippedHasScore = findings.filter((f) => f.cvss).length;
      const skippedDisq = findings.filter(isDisqualified).length;
      if (scorable.length > 0) {
        console.log(
          `\nScoring ${scorable.length} finding(s)` +
            (skippedHasScore > 0 ? ` (${skippedHasScore} already scored)` : "") +
            (skippedDisq > 0 ? ` (${skippedDisq} skipped: FP/out-of-scope)` : ""),
        );
        const scoreFileCache = new Map<string, string | null>();
        const scoredByShard = new Map<
          string,
          { agentSlug: string; filePath: string; findings: Finding[] }
        >();
        // One bounded pool over findings, same as validation. scoredByShard
        // is mutated only after the await (a synchronous get/push/set with no
        // yield), so concurrent workers can't lose an entry.
        await runConcurrent(scorable, concurrency, async (finding) => {
          let content = scoreFileCache.get(finding.filePath);
          if (content === undefined) {
            try {
              content = readFileSync(resolve(root, finding.filePath), "utf8");
            } catch {
              content = null;
            }
            scoreFileCache.set(finding.filePath, content);
          }
          if (content === null) {
            if (opts.verbose) {
              console.log(`    skip score ${finding.id}: file not readable`);
            }
            return;
          }
          try {
            const cvss = await detector.scoreFinding({
              finding,
              fileContent: content,
              recon,
              signal: scanAbortController.signal,
            });
            finding.cvss = cvss;
            finding.severity = cvss.severity;
            const normalized = finding.filePath.replace(/\\/g, "/");
            const key = `${finding.agentSlug} ${normalized}`;
            const entry = scoredByShard.get(key) ?? {
              agentSlug: finding.agentSlug,
              filePath: normalized,
              findings: [],
            };
            entry.findings.push(finding);
            scoredByShard.set(key, entry);
            if (opts.verbose) {
              const loc = finding.lineRange ? `:${finding.lineRange[0]}` : "";
              console.log(
                `    ${cvss.severity.padEnd(8)} ${cvss.baseScore.toFixed(1).padStart(4)}  ${findingFilenameSlug(finding)}  ${finding.filePath}${loc}`,
              );
            }
          } catch (err) {
            handleDetectorError(opts, `score:${finding.id}`, err, scanAbortController);
          }
        });
        // Persist scored findings back into the per-(agent, file) shards.
        // Grouped by (agentSlug, filePath) so each shard is rewritten
        // once per scoring run.
        for (const { agentSlug, filePath, findings: group } of scoredByShard.values()) {
          if (isAbsolute(filePath)) continue;
          const record = readFileRecord(outDir, agentSlug, filePath);
          if (!record) continue;
          const inMemory = new Map(group.map((f) => [f.id, f]));
          record.findings = record.findings.map((rec) => {
            const live = inMemory.get(rec.id);
            if (!live?.cvss) return rec;
            return { ...rec, cvss: live.cvss, severity: live.severity };
          });
          record.analysisHistory.push({
            runId: runMeta.runId,
            phase: "detect",
            ranAt: new Date().toISOString(),
            durationMs: 0,
            provider: detector.name,
            agentSlugs: [agentSlug],
            findingCount: group.length,
          });
          try {
            writeFileRecord(outDir, record);
          } catch (err) {
            if (opts.verbose) {
              logError(`persist failed for ${agentSlug}/${filePath}: ${(err as Error).message}`);
            }
          }
        }
        const buckets: Record<string, number> = {};
        for (const f of scorable) {
          if (!f.severity) continue;
          buckets[f.severity] = (buckets[f.severity] ?? 0) + 1;
        }
        const summary = Object.entries(buckets)
          .sort()
          .map(([s, n]) => `${s}=${n}`)
          .join(", ");
        console.log(`  Severity: ${summary || "(none)"}`);
      } else if (skippedHasScore + skippedDisq > 0) {
        console.log(
          `\nScoring: nothing to do (${skippedHasScore} already scored, ${skippedDisq} FP/out-of-scope). Pass --rescore to redo.`,
        );
      }
    }

    // -------- de-duplication phase (final gather) --------
    // Group shippable findings by source filePath ACROSS agents and fold
    // same-root-cause duplicates under one primary. Runs LAST — after
    // detect/validate/score — because, unlike those per-finding phases, it
    // needs every finding for a file co-located, so it cannot be
    // distributed. Marks the non-primary findings with a `dedup` field
    // (orthogonal to the validation verdict); `--delete-duplicates` strips
    // them instead. The report render below then collapses them.
    if (opts.dedup && findings.length > 0) {
      const shippable = findings.filter(
        (f) =>
          f.filePath &&
          f.filePath !== "(unknown)" &&
          f.validation?.verdict !== "false-positive" &&
          f.validation?.verdict !== "out-of-scope",
      );
      const byFile = new Map<string, Finding[]>();
      for (const f of shippable) {
        const bucket = byFile.get(f.filePath);
        if (bucket) bucket.push(f);
        else byFile.set(f.filePath, [f]);
      }
      const dedupeTasks = [...byFile.entries()]
        .filter(([, fs]) => fs.length >= 2)
        .map(([filePath, fs]) => ({ filePath, findings: fs }));

      if (dedupeTasks.length > 0) {
        console.log(`\nDe-duplicating across ${dedupeTasks.length} file(s)`);
        const dedupeFileCache = new Map<string, string | null>();
        const dupedByShard = new Map<
          string,
          { agentSlug: string; filePath: string; findings: Finding[] }
        >();
        let totalDuplicates = 0;
        await runConcurrent(dedupeTasks, concurrency, async ({ filePath, findings: bucket }) => {
          let content = dedupeFileCache.get(filePath);
          if (content === undefined) {
            try {
              content = readFileSync(resolve(root, filePath), "utf8");
            } catch {
              content = null;
            }
            dedupeFileCache.set(filePath, content);
          }
          try {
            const clusters = await detector.dedupeFindings({
              filePath,
              findings: bucket,
              fileContent: content ?? undefined,
              signal: scanAbortController.signal,
            });
            const byId = new Map(bucket.map((f) => [f.id, f]));
            for (const a of resolveDedup(bucket, clusters)) {
              const dupe = byId.get(a.id);
              if (!dupe) continue;
              dupe.dedup = {
                duplicateOf: a.duplicateOf,
                reasoning: a.reasoning,
                runId: runMeta.runId,
              };
              const normalized = dupe.filePath.replace(/\\/g, "/");
              const key = `${dupe.agentSlug} ${normalized}`;
              const entry = dupedByShard.get(key) ?? {
                agentSlug: dupe.agentSlug,
                filePath: normalized,
                findings: [],
              };
              entry.findings.push(dupe);
              dupedByShard.set(key, entry);
              totalDuplicates++;
            }
          } catch (err) {
            handleDetectorError(opts, `dedup:${filePath}`, err, scanAbortController);
          }
        });
        // Persist dedup markers back into the per-(agent, file) shards.
        for (const { agentSlug, filePath, findings: group } of dupedByShard.values()) {
          if (isAbsolute(filePath)) continue;
          const record = readFileRecord(outDir, agentSlug, filePath);
          if (!record) continue;
          const inMemory = new Map(group.map((f) => [f.id, f]));
          if (opts.deleteDuplicates) {
            record.findings = record.findings.filter((rec) => !inMemory.has(rec.id));
          } else {
            record.findings = record.findings.map((rec) => {
              const live = inMemory.get(rec.id);
              return live?.dedup ? { ...rec, dedup: live.dedup } : rec;
            });
          }
          record.analysisHistory.push({
            runId: runMeta.runId,
            phase: "dedup",
            ranAt: new Date().toISOString(),
            durationMs: 0,
            provider: detector.name,
            agentSlugs: [agentSlug],
            findingCount: record.findings.length,
          });
          try {
            writeFileRecord(outDir, record);
          } catch (err) {
            if (opts.verbose) {
              logError(`persist failed for ${agentSlug}/${filePath}: ${(err as Error).message}`);
            }
          }
        }
        const verb = opts.deleteDuplicates ? "deleted" : "marked";
        console.log(`  ${verb} ${totalDuplicates} duplicate(s)`);
        // When deleting, drop them from the in-memory list too so the
        // report render below doesn't re-include them.
        if (opts.deleteDuplicates && totalDuplicates > 0) {
          findings = findings.filter((f) => !f.dedup);
        }
      } else {
        console.log("\nDe-duplication: nothing to compare (no file has 2+ shippable findings).");
      }
    }

    const completedAt = new Date();

    // `--no-summary` skips the report render entirely. Findings are already
    // persisted to state/files/*, so `agentgg summary <outDir>` can produce
    // the markdown later without re-running detection.
    const report =
      opts.summary === false
        ? null
        : writeMarkdownReport({
            outDir,
            root,
            startedAt,
            completedAt,
            findings,
            filesScanned: analyzedFiles.size,
            byAgent,
            excludeFalsePositives: opts.excludeFalsePositives,
          });

    completeRun(outDir, runMeta.runId, "done", {
      filesScanned: analyzedFiles.size,
      findingsCount: findings.length,
      totalDurationMs: completedAt.getTime() - startedAt.getTime(),
    });
    // Final token-ledger checkpoint — drains any debounced records.
    usageMeter?.flush();
    runFinalized = true;
    process.off("SIGINT", shutdownHandler);
    process.off("SIGTERM", shutdownHandler);

    console.log(`\nDone. ${findings.length} finding(s) across ${analyzedFiles.size} file(s).`);
    // A failed batch leaves its agent without a sidecar, so the agent re-runs.
    // Say so: without this the closing line reads like a complete scan.
    if (failedBatchCount > 0) {
      const notAnalyzed = touchedFiles.size - analyzedFiles.size;
      console.log(
        `  ${failedBatchCount} batch(es) failed; ${notAnalyzed} candidate file(s) were not analyzed ` +
          `and re-run on the next scan.`,
      );
    }
    if (report) {
      console.log(`  Summary: ${report.summaryPath}`);
      console.log(`  Findings dir: ${outDir}\\findings`);
    } else {
      console.log(
        `  Summary: skipped (--no-summary). Run \`agentgg summary ${opts.output ?? "./scan-results/"}\` to render it.`,
      );
    }

    if (opts.serve) {
      const port = parsePortOpt(opts.serve);
      console.log("\nBooting local viewer…");
      const handle = await startViewer({
        outputDir: outDir,
        port,
        verbose: opts.verbose,
      });
      printReady(handle.url, outDir);
      openBrowser(handle.url);
      // Block until Ctrl+C — same pattern as `agentgg view`.
      await new Promise<void>((res) => {
        const shutdown = async () => {
          process.stdout.write("\nStopping viewer…\n");
          await handle.stop();
          res();
        };
        process.once("SIGINT", shutdown);
        process.once("SIGTERM", shutdown);
        handle.child.once("exit", () => res());
      });
    }
  } catch (err) {
    // Stamp the on-disk run sidecar as `error` so the next scan run
    // doesn't see a stale `phase: "running"`. Same finalize the SIGINT
    // handler does — guard with runFinalized so we don't double-write.
    if (!runFinalized) {
      runFinalized = true;
      try {
        usageMeter?.flush();
      } catch {
        // metering must never mask the original error
      }
      try {
        completeRun(outDir, runMeta.runId, "error", {});
      } catch {
        // best-effort
      }
    }
    process.off("SIGINT", shutdownHandler);
    process.off("SIGTERM", shutdownHandler);
    if (err instanceof FatalScanError) {
      // Single clean line. The action handler also prints "scan failed:"
      // around it, so the user sees the diagnostic message once.
      throw new Error(err.message);
    }
    throw err;
  }
}

/**
 * The stand-in recon brief used under `--no-recon`. Empty content (nothing
 * is injected into prompts) with a stable sentinel `reconHash` so resume
 * stamps and plan.json stay consistent across `--no-recon` runs, and a
 * normal (recon-bearing) run is correctly treated as a different scope.
 */
function synthesizeSkippedRecon(): ReconReport {
  return {
    purpose: "",
    languages: [],
    frameworks: [],
    integrations: [],
    notableDirs: [],
    summary: "",
    reconHash: "no-recon",
    generatedAt: new Date().toISOString(),
  };
}

/**
 * True when two scope signatures describe the same effective scan. List
 * fields compare order-insensitively (`--exclude a --exclude b` and
 * `--exclude b --exclude a` are the same scope). Mismatch on any field
 * invalidates a sidecar and forces the agent to re-run.
 */
function scopeMatches(prior: AgentRun["scope"], current: AgentRun["scope"]): boolean {
  if (prior.diff !== current.diff) return false;
  if (prior.rootPath !== current.rootPath) return false;
  if (prior.maxFileSizeKb !== current.maxFileSizeKb) return false;
  if (prior.reconHash !== current.reconHash) return false;
  if (!sameSet(prior.excludePatterns, current.excludePatterns)) return false;
  if (!sameSet(prior.includePatterns, current.includePatterns)) return false;
  return true;
}

function sameSet(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const sa = [...a].sort();
  const sb = [...b].sort();
  for (let i = 0; i < sa.length; i++) {
    if (sa[i] !== sb[i]) return false;
  }
  return true;
}

/**
 * Human-readable explanation of which scope field caused a mismatch.
 * Only called from the verbose-mode diagnostic log so the user can see
 * *why* an agent's sidecar got ignored on resume.
 */
function scopeMismatchReason(prior: AgentRun["scope"], current: AgentRun["scope"]): string {
  if (prior.diff !== current.diff) {
    return `diff: ${prior.diff ?? "(none)"} → ${current.diff ?? "(none)"}`;
  }
  if (prior.rootPath !== current.rootPath) {
    return `root: ${prior.rootPath} → ${current.rootPath}`;
  }
  if (prior.maxFileSizeKb !== current.maxFileSizeKb) {
    return `maxFileSizeKb: ${prior.maxFileSizeKb} → ${current.maxFileSizeKb}`;
  }
  if (prior.reconHash !== current.reconHash) {
    return `reconHash: ${prior.reconHash ?? "(none)"} → ${current.reconHash ?? "(none)"}`;
  }
  if (!sameSet(prior.excludePatterns, current.excludePatterns)) {
    return `excludePatterns: [${prior.excludePatterns.join(",")}] → [${current.excludePatterns.join(",")}]`;
  }
  if (!sameSet(prior.includePatterns, current.includePatterns)) {
    return `includePatterns: [${prior.includePatterns.join(",")}] → [${current.includePatterns.join(",")}]`;
  }
  return "scope differs";
}

export function registerScanCommand(program: Command): void {
  program
    .command("scan")
    .description("run a security scan against a codebase")
    .argument("<path>", "path to the codebase to scan")
    .option(
      "--scope <path>",
      "path to a SECURITY.md-style scope file. With --validate, scope rules are threaded into the full classifier (verdicts include `out-of-scope`). WITHOUT --validate, triggers scope-only validation: the model never re-reads the source and only persists `out-of-scope` verdicts (cheap pre-filter). When omitted, a bundled default scope (trust-boundary rules) is used with --validate; pass --no-scope to disable it.",
    )
    .option(
      "--no-scope",
      "disable the bundled default scope (skip trust-boundary filtering during validation)",
    )
    .option("-o, --output <path>", "output directory for findings", "./scan-results/")
    .option(
      "--source-id <id>",
      "stable identifier for the scanned source. Resume state in --output is reused only when it matches the prior run. Defaults to the absolute path of the scan root; set it when the same codebase is scanned from a different path each run (CI checkouts, container mounts). Reusing one id across genuinely different codebases will serve the wrong cached findings.",
    )
    .option(
      "--validate",
      "run a full second-pass LLM validation phase per finding (slower; reduces false positives). Combine with --scope to thread scope rules into the classifier. On by default; disable with --no-validate.",
      true,
    )
    .option(
      "--no-validate",
      "skip the full second-pass validation phase (it runs by default). Detection findings ship unvalidated.",
    )
    .option(
      "--rescan",
      "re-analyze files even if a prior run already covered them with the same content (default: resume)",
    )
    .option(
      "--revalidate-all",
      "re-validate findings even if they already have a verdict on disk (default: skip them)",
    )
    .option(
      "--provider <name>",
      "LLM provider for this run: anthropic | openai | ollama | bedrock | vertex | openrouter (overrides saved default)",
    )
    .option(
      "--api-key <key>",
      "One-shot API key (not persisted). Valid for: anthropic, openai, openrouter. For Anthropic, also accepts an sk-ant-oat… OAuth token.",
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
      "OpenRouter provider-routing block, overriding OPENROUTER_* env for this run: inline JSON (must start with {) or a path to a .json file (avoids shell-quoting JSON on Windows). Invalid JSON aborts the scan before any LLM call. OpenRouter only.",
    )
    .option(
      "-t, --template <value>",
      "Restrict the scan to specific agents. A value can be: a slug (`sql-injection`), a path to a `.md` agent file, a directory of `.md` files, or a `.txt` file listing slugs/paths one per line (# for comments). Multiple values can be comma- or whitespace-separated within one `-t`, or `-t` may be repeated.",
      collect,
      [] as string[],
    )
    .option(
      "--semgrep-rules <dir>",
      "Directory of local semgrep rule files (.yml/.yaml) that an agent's `where.preFilter` can name via `semgrepRule`. Searched BEFORE the downloaded catalog's own rules dir, so a local file shadows a catalog rule of the same name, and `agentgg agents update` cannot delete it. Repeat the flag for several dirs. The value is a directory; the rule is still referenced by bare name (no path, no extension).",
      collect,
      [] as string[],
    )
    .option(
      "--diff <commit>",
      "Restrict the scan to what a commit or range touched, independent of the working tree. A bare ref reviews that commit's own changes (parent → commit). `a..b` is the tip-to-tip diff; `a...b` is merge-base(a,b) → b, which matches a PR review. Each agent's candidate files are intersected with the touched files, and the patch is injected into the agent's prompt as a focus hint (tools stay unrestricted so it can chase context outward).",
    )
    .option(
      "--concurrency <n>",
      "max batches run in parallel across ALL agents (total in-flight LLM sessions for the whole scan)",
      (v) => parseInt(v, 10),
      5,
    )
    .option(
      "--max-turns <n>",
      "Max tool-use turns per LLM session. When set, applies uniformly to every agent batch, recon, and the validator. When unset: agent batches use the agent's `where.maxTurnsPerBatch` (default 50, or 150 when the agent declares no extensions and no filePatterns), recon 50, validator 50.",
      (v) => parseInt(v, 10),
    )
    .option(
      "--max-files-per-batch <n>",
      "How many candidate files an agent with a file scope packs into one investigation batch (no effect on an agent with no file scope, which runs a single session with no candidates). Overrides the agent's `maxFilesPerBatch`. Default 5. Different from --concurrency: batch size = files per LLM session; --concurrency = sessions in parallel.",
      (v) => parseInt(v, 10),
    )
    .option(
      "--max-anchors-per-batch <n>",
      "Cap the scanner anchor lines packed into one investigation batch. Sibling of --max-files-per-batch: same batch, different unit. Both are ceilings and whichever binds first closes the batch. A single file with more anchors than <n> is split into shards of at most <n>, and each prompt anchors on a contiguous line range — so one rule matching 500 places in one file no longer arrives in a single prompt. Each shard still carries the whole file as context, so an N-shard file sends its content N times. Anchors sharing a line count once, and regex and semgrep anchors count the same. Default 150; pass --no-max-anchors-per-batch to disable the cap. A low value makes many more batches, so raise --max-batches with it.",
      (v) => parseInt(v, 10),
      150,
    )
    .option("--no-max-anchors-per-batch", "disable the per-batch anchor cap (never split a file)")
    .option(
      "--max-files-per-agent <n>",
      "Cap the candidate files each agent reviews: if an agent's scope resolves to more than <n> files (after prefilter), keep the first <n> in scan order and drop the rest. A guardrail against an over-broad agent blowing up cost/time on a large repo. Default 300; pass --no-max-files-per-agent to disable the cap. Different from --max-files-per-batch, which only sets how many files pack into one LLM session.",
      (v) => parseInt(v, 10),
      300,
    )
    .option(
      "--no-max-files-per-agent",
      "disable the per-agent candidate-file cap (review every file)",
    )
    .option(
      "--max-batches <n>",
      "Cap the TOTAL number of agent batches run across the whole scan (all agents combined). Once batches are enqueued, the pool is truncated to <n> in enqueue order and the rest are dropped, then the scan stops. A whole-scan cost/time guardrail — different from --max-files-per-agent (per-agent file cap) and --concurrency (parallel sessions). Agents whose batches are dropped re-run on the next scan. Default 250; pass --no-max-batches to disable the cap.",
      (v) => parseInt(v, 10),
      250,
    )
    .option("--no-max-batches", "disable the whole-scan agent-batch cap (run every batch)")
    .option(
      "--effort <level>",
      "Reasoning effort for tool-using calls (recon, agent runs, validate). One of: low, medium, high, max. Default: SDK default (no override). Anthropic maps it to the Claude SDK effort; OpenAI maps it to reasoning_effort, which ONLY reasoning models accept (a non-reasoning model rejects it with an HTTP 400). No effect on Bedrock, Vertex, or Ollama.",
    )
    .option(
      "--thinking <mode>",
      "Thinking mode for tool-using calls. One of: off, adaptive, enabled. `adaptive` matches Claude Code interactive — the model decides per call. Anthropic-only; other providers ignore it.",
    )
    .option(
      "--exclude-false-positives",
      "Skip per-finding markdown reports for findings the validator marked false-positive (default: write them). FP findings always stay in state/files/* regardless.",
    )
    .option(
      "--re-recon",
      "Re-run the recon pass even if a cached brief exists for this output dir (default: reuse it when the project root + stack fingerprint are unchanged).",
    )
    .option(
      "--no-recon",
      "Skip the recon survey AND precondition gating: no project brief is generated or injected into prompts, and every agent passed via -t runs unconditionally (the regex/prompt gates that would otherwise skip irrelevant agents are bypassed). Use for a focused run when you already know exactly which agents you want.",
    )
    .option(
      "--no-summary",
      "Skip writing the markdown report (summary.md + findings/*.md) at the end of the scan. Findings still persist to state/files/*; render the report later with `agentgg summary`.",
    )
    .option(
      "--score",
      "Run the CVSS 3.1 scoring phase after detection (and after validation). The agent picks the 8 base metrics; the score and severity bucket are computed deterministically. Findings the validator marked false-positive or out-of-scope are skipped. On by default; disable with --no-score.",
      true,
    )
    .option(
      "--no-score",
      "skip the CVSS 3.1 scoring phase (it runs by default). Findings ship without a severity score.",
    )
    .option(
      "--rescore",
      "Re-score findings even when they already carry a CVSS score on disk (default: skip them)",
    )
    .option(
      "--dedup",
      "Run the de-duplication phase at the very end (after detect/validate/score). Groups findings by source file across agents, folds same-root-cause findings under one primary, and marks the rest with a `dedup` field so the report collapses them. The final gather step — it sees all of a file's findings, so it can't be distributed like the earlier phases. On by default; disable with --no-dedup.",
      true,
    )
    .option(
      "--no-dedup",
      "skip the de-duplication phase (it runs by default). Duplicate findings across agents are all kept in the report.",
    )
    .option(
      "--delete-duplicates",
      "With --dedup, physically remove duplicate findings from their FileRecords instead of just marking them (default: keep + mark).",
    )
    .option(
      "--serve [port]",
      `After the scan completes, boot a local web UI for the findings and keep it running until Ctrl+C. Optional port (default ${DEFAULT_VIEWER_PORT}; auto-increments if busy). Same UI as \`agentgg view\`.`,
    )
    .option(
      "--exclude <pattern>",
      "extra glob to exclude (repeatable; additive to walker defaults)",
      collect,
      [] as string[],
    )
    .option(
      "--only <pattern>",
      "restrict scan to files matching at least one of these globs (repeatable)",
      collect,
      [] as string[],
    )
    .option(
      "--max-file-size <kb>",
      "skip files larger than this in KB (default 500; pass --no-max-file-size to scan files of any size)",
      (v) => parseInt(v, 10),
      500,
    )
    .option("--no-max-file-size", "don't skip large files (scan files of any size)")
    .option(
      "--no-default-excludes",
      "Don't apply the shared default exclude set (node_modules, .git, build dirs, lockfiles, binaries). Scans everything except your explicit --exclude paths. Per-agent opt-out is `where.useDefaultExcludes: false`.",
    )
    .option(
      "--auto-exclude",
      "Before scanning, let the model pick folders not worth reviewing (tests, fixtures, generated/vendored code, docs, sample data) and skip them like --exclude paths. On by default; chosen folders are always logged (reasons shown with --verbose). Reuses the folders a prior recon/scan chose for this --output dir when present (pass --re-recon to re-derive). Disable with --no-auto-exclude to scan the whole tree.",
      true,
    )
    .option(
      "--no-auto-exclude",
      "don't let the model pick folders to skip (auto-exclude runs by default). The whole tree is scanned except your explicit --exclude paths.",
    )
    .option("-v, --verbose", "verbose output")
    .action(async (path: string, opts: ScanOpts) => {
      try {
        await runScan(path, opts);
      } catch (err) {
        logError(`scan failed: ${err instanceof Error ? err.message : String(err)}`);
        // Set the code rather than calling process.exit so the event
        // loop drains naturally — pending claude-agent-sdk subprocesses
        // get a clean shutdown instead of the libuv double-close
        // assertion that fires on Windows when handles are still mid-close.
        process.exitCode = 1;
      }
    });
}

function collect(value: string, prev: string[]): string[] {
  return prev.concat([value]);
}

/**
 * Resolve the `--serve [port]` option. Commander passes the boolean
 * `true` when the bare flag was used and the string value otherwise.
 * Returns undefined for the default-port case so `startViewer` picks
 * 3737 (and auto-increments).
 */
function parsePortOpt(value: boolean | string | undefined): number | undefined {
  if (typeof value !== "string") return undefined;
  const n = parseInt(value, 10);
  if (!Number.isFinite(n) || n < 1 || n > 65535) {
    throw new Error(`--serve: invalid port "${value}" (expected an integer between 1 and 65535)`);
  }
  return n;
}
