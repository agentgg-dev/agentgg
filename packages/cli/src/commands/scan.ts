import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import type { Agent, AgentRun, FileRecord, Finding, Provider } from "@agentgg/core";
import {
  completeRun,
  createRunMeta,
  fingerprint,
  getOfficialAgentsDir,
  hashContent,
  loadAllFileRecords,
  readAgentRun,
  readFileRecord,
  upsertScanMeta,
  writeAgentRun,
  writeFileRecord,
  writeRunMeta,
  writeScanPlan,
} from "@agentgg/core";
import type { Command } from "commander";
import { loadAllAgents } from "../agent-catalog.js";
import { installOfficialAgents } from "../agents-install.js";
import { runConcurrent } from "../concurrent.js";
import type { AgentCandidate } from "../detect.js";
import { FatalScanError, handleDetectorError } from "../diagnostics.js";
import { listChangedFiles, loadCommitPatch } from "../diff.js";
import { loadOrSynthesizeConfig, resolveDetector } from "../llm.js";
import { evaluatePreFilter } from "../pre-filter.js";
import { selectAgents } from "../precondition.js";
import { buildCredentialsFromOpts, validateProviderFlags } from "../providers/index.js";
import { renderReconForPrompt, runRecon } from "../recon.js";
import { findingFilenameSlug, writeMarkdownReport } from "../reporters/md.js";
import { resolveTemplates } from "../template.js";
import { DEFAULT_VIEWER_PORT, openBrowser, startViewer } from "../viewer-server.js";
import { DEFAULT_EXCLUDES, type WalkConfig, walkForAgents } from "../walker.js";
import { printReady } from "./view.js";

interface ScanOpts {
  /**
   * Path to a SECURITY.md-style scope document. Two meanings:
   *   - with --validate: scope context is threaded into full validation
   *     so the model can return `out-of-scope` alongside the usual
   *     confirmed / false-positive / uncertain verdicts.
   *   - WITHOUT --validate: triggers scope-only validation. The model
   *     never sees the source, only the finding metadata + this scope
   *     doc, and only `out-of-scope` verdicts are persisted. Cheap.
   */
  scope?: string;
  output?: string;
  validate?: boolean;
  provider?: string;
  apiKey?: string;
  oauthToken?: string;
  baseUrl?: string;
  region?: string;
  project?: string;
  model?: string;
  concurrency?: number;
  diff?: string;
  template?: string[];
  verbose?: boolean;
  exclude?: string[];
  only?: string[];
  maxFileSize?: number; // KB
  /**
   * Apply the shared `DEFAULT_EXCLUDES` set (node_modules, .git, build
   * dirs, lockfiles, binaries). Defaults to true. Commander stores
   * `--no-default-excludes` as `defaultExcludes: false` — pass it to scan
   * everything (only the CLI `--exclude` deletes still apply). Per-agent
   * opt-out is `where.useDefaultExcludes`.
   */
  defaultExcludes?: boolean;
  /** Re-analyze files even when a prior FileRecord covers them with the same contentHash. */
  rescan?: boolean;
  /** Re-validate findings even when they already have a verdict on disk. */
  revalidateAll?: boolean;
  /**
   * Max tool-use turns per LLM session. When set, applies uniformly to every
   * agent batch, recon, and the validator. When unset, agent runs use the
   * agent's `where.maxTurnsPerBatch` (default 30), recon uses 30, validator 30.
   */
  maxTurns?: number;
  /** Candidate files per agent batch. Overrides the agent's `where.maxFilesPerBatch`. */
  maxFilesPerBatch?: number;
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
   * Run the CVSS 3.1 scoring phase after detection (and after validation
   * when --validate is set). The scoring agent picks the 8 base metrics
   * per finding; the score and severity bucket are computed
   * deterministically in Node from those choices. When `--validate` was
   * passed, findings the validator marked false-positive or out-of-scope
   * are skipped to avoid paying for findings that won't ship.
   */
  score?: boolean;
  /** Re-score findings even when they already carry a `cvss` on disk. */
  rescore?: boolean;
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
 * Every agent is one unified, tool-enabled shape. Its `where` resolves to a
 * concrete file set (`extensions` / `filePatterns` narrowed by `preFilter`;
 * an empty `where` = all files), which is reviewed in batches of
 * `maxFilesPerBatch`. The agent always has Read/Glob/Grep to read beyond its
 * seeded files. Under `--diff <commit>`, each agent's candidate list is
 * intersected with the files touched in that commit (its own patch,
 * parent → commit, independent of the working tree).
 */
export async function runScan(
  rootArg: string,
  opts: ScanOpts,
  env: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  const root = resolve(rootArg);
  const outDir = resolve(opts.output ?? "./scan-results/");

  // -------- per-scan persistence setup --------
  // Nuclei-style: state lives inside the --output dir. The scan-meta
  // sidecar records the absolute root so `revalidate` can resolve
  // relative filePaths back to source files later.
  upsertScanMeta(outDir, root);
  const runMeta = createRunMeta({ type: "scan" });
  writeRunMeta(outDir, runMeta);
  if (opts.verbose) {
    console.log(`State: ${outDir}\\state  (run ${runMeta.runId})`);
  }

  // SIGINT (Ctrl+C) handler: mark the run as errored on disk so it
  // doesn't sit in `phase: "running"` forever, then exit with the
  // conventional 128+SIGINT code. Files already persisted stay on
  // disk and a re-run with the same --output resumes past them
  // (see contentHash skip in the file-mode loop below).
  let runFinalized = false;
  const sigintHandler = () => {
    if (!runFinalized) {
      runFinalized = true;
      try {
        completeRun(outDir, runMeta.runId, "error", {});
      } catch {
        // best-effort; the run file just stays "running"
      }
      console.error("\nInterrupted. Partial state persisted; re-run the same command to resume.");
    }
    process.exit(130);
  };
  process.on("SIGINT", sigintHandler);

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
      validateMaxTurns: opts.maxTurns ?? 30,
      effort: opts.effort,
      thinking: opts.thinking,
    });

    // Auto-install official agents on first scan — mirrors how nuclei
    // auto-downloads templates when ~/nuclei-templates/ doesn't exist yet.
    if (!existsSync(getOfficialAgentsDir(env))) {
      process.stdout.write("[INF] agentgg-agents are not installed, installing...\n");
      try {
        const { version, count } = await installOfficialAgents(env);
        process.stdout.write(
          `[INF] Successfully installed agentgg-agents at ~/.agentgg/agentgg-agents (${count} agents, ${version})\n`,
        );
      } catch (err) {
        process.stderr.write(`[WRN] Could not auto-install agents: ${(err as Error).message}\n`);
        process.stderr.write(
          "[WRN] Run `agentgg agents update` to install, or provide agents via -t flag.\n",
        );
      }
    }

    // Load official + custom agents. Same catalog `agents list` shows.
    // Surface parse errors as warnings so a broken file doesn't block a scan.
    // Structural correctness of the official tree is guaranteed by the
    // agentgg-agents repo's pre-commit hook (`agentgg agents lint`), not
    // re-checked here.
    const catalog = loadAllAgents(env);
    for (const e of catalog.errors) console.warn(`warning: ${e}`);

    const officialAgentsDir = getOfficialAgentsDir(env);

    // `--template` / `-t` filters the catalog. Each value is a slug,
    // a path to a .md file/dir, or a subdirectory name relative to the
    // official agents dir (e.g. "base/injection/" or "demo-agents/").
    // When no -t is given, default to the official base/ folder — the
    // full vulnerability library.
    const templateInputs = opts.template ?? [];
    const baseDir = join(officialAgentsDir, "base");
    let selectedAgents: Agent[] =
      templateInputs.length > 0
        ? resolveTemplates(templateInputs, catalog.agents, officialAgentsDir)
        : existsSync(baseDir)
          ? resolveTemplates([baseDir], catalog.agents, officialAgentsDir)
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
    const excludePatterns = [...(opts.exclude ?? [])];
    const includePatterns = opts.only ?? [];
    const maxFileSizeBytes = (opts.maxFileSize ?? 500) * 1024;

    // The baseline walk excludes = the shared default set + the deleted
    // CLI paths. Recon and the precondition census use this. Per-agent
    // walks below rebuild it so an agent can opt out of the defaults
    // (`where.useDefaultExcludes: false`) while still honoring CLI deletes.
    // `--no-default-excludes` drops the shared set globally for this run.
    const walkExcludes =
      opts.defaultExcludes === false
        ? [...excludePatterns]
        : [...DEFAULT_EXCLUDES, ...excludePatterns];

    // Read scope file once if --scope is set. Passed verbatim into the
    // validator prompt so `out-of-scope` becomes a meaningful verdict.
    // Missing-file is fatal: the user explicitly asked for scope.
    let scopeContent: string | undefined;
    if (opts.scope) {
      const scopePath = resolve(opts.scope);
      try {
        scopeContent = readFileSync(scopePath, "utf8");
      } catch (err) {
        throw new Error(`--scope: cannot read ${scopePath}: ${(err as Error).message}`);
      }
    }

    // `--scope` without `--validate` triggers scope-only validation:
    // a cheap, file-read-free pre-filter that classifies each finding
    // against the scope document alone. `--validate` with or without
    // `--scope` runs the full source-reading classifier.
    const scopeOnlyValidate = !opts.validate && !!scopeContent;

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
      console.log(`Validation: full${scopeContent ? ` (scope: ${opts.scope})` : ""}`);
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

    const findings: Finding[] = [];
    const byAgent: Record<string, number> = {};
    const touchedFiles = new Set<string>();

    // Persist findings for one (file, agent) pair into the per-project
    // FileRecord. Called from both the file-mode loop and the hunt
    // post-processing step. Merges by finding id so re-runs of the same
    // agent on the same file replace (not duplicate) prior findings.
    function persistDetection(
      relPath: string,
      agent: Agent,
      fileContent: string,
      newFindings: Finding[],
    ): void {
      const normalized = relPath.replace(/\\/g, "/");
      let record: FileRecord | null;
      try {
        record = readFileRecord(outDir, normalized);
      } catch {
        record = null;
      }
      if (!record) {
        record = {
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
          console.error(`    persist failed for ${normalized}: ${(err as Error).message}`);
        }
      }
    }

    // -------- PHASE 1 — recon: high-level project brief --------
    // One tool-enabled survey of the repo, cached/resumed by reconHash.
    // The brief is injected into precondition prompt gates and into every
    // queued agent's detection prompt so the model starts oriented.
    console.log("\n[1/3] Recon — surveying the project…");
    const recon = await runRecon({
      rootDir: root,
      outDir,
      detector,
      fingerprintTags: project.tags,
      excludePatterns: walkExcludes,
      includePatterns,
      maxFileSizeKb: opts.maxFileSize ?? 500,
      maxTurns: opts.maxTurns ?? 30,
      force: opts.reRecon,
      signal: scanAbortController.signal,
      verbose: opts.verbose,
    });
    const reconBlock = renderReconForPrompt(recon);
    console.log(
      `Recon: ${recon.languages.length > 0 ? recon.languages.join(", ") : "(languages unknown)"}${
        recon.frameworks.length > 0 ? ` | ${recon.frameworks.join(", ")}` : ""
      }`,
    );

    // Scope signature stamped on each agent's resume sidecar. A change to
    // --diff, --exclude, --only, --max-file-size, root, OR the recon brief
    // invalidates resume and re-runs the agent.
    const currentScope: AgentRun["scope"] = {
      diff: opts.diff,
      excludePatterns: [...excludePatterns],
      includePatterns: [...includePatterns],
      maxFileSizeKb: opts.maxFileSize ?? 500,
      rootPath: root,
      reconHash: recon.reconHash,
    };

    // -------- PHASE 2 — precondition: decide which agents run --------
    // Every selected agent's `precondition` (regex existence checks and/or an
    // LLM prompt gate that sees the recon brief) is evaluated up front, before
    // ANY agent runs. No precondition = always queued. Regex checks are pure
    // filesystem work; only prompt-gated agents incur an LLM call. The result
    // is persisted to state/plan.json as the durable plan→run hand-off.
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
    const queuedAgents = selection.queued;
    const skippedCount = selection.decisions.length - queuedAgents.length;
    // Persist the plan BEFORE any agent runs — this is the artifact a
    // distributed runner consumes to dispatch the queued agents.
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
    if (opts.verbose) {
      for (const d of selection.decisions) {
        console.log(`  ${d.queued ? "[run] " : "[skip]"} ${d.slug}: ${d.reason}`);
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
    // One unified path: every agent is a tool-enabled investigation over a
    // concrete file set. Its `where` resolves to seeded candidate files
    // (extensions/filePatterns + preFilter, intersected with --diff; empty
    // `where` = all files), reviewed in batches. The agent has tools to read
    // beyond its seeds. Findings are stamped with the agent's slug.
    //
    // Resume is per-agent: a completed agent with a matching scope
    // (including reconHash) is skipped and its findings lifted from disk.
    // An interrupted agent (no sidecar) re-runs in full. Agents run one at
    // a time; their batches run concurrently.
    const concurrency = Math.max(1, opts.concurrency ?? 5);
    let cachedAgentCount = 0;
    if (queuedAgents.length > 0) {
      console.log(
        `\n[3/3] Agents — ${queuedAgents.length} queued (completed agents are reused from prior runs; only new/changed work calls the LLM)…`,
      );
    }
    for (const agent of queuedAgents) {
      if (!opts.rescan) {
        const prior = readAgentRun(outDir, agent.slug);
        if (prior && scopeMatches(prior.scope, currentScope)) {
          const cached = getAllRecords()
            .flatMap((r) => r.findings)
            .filter((f) => f.agentSlug === agent.slug);
          findings.push(...cached);
          byAgent[agent.slug] = (byAgent[agent.slug] ?? 0) + cached.length;
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
      const agentWalkCfg: WalkConfig = {
        excludePatterns: agentBaseExcludes,
        includePatterns,
        maxFileSizeBytes,
      };
      // Resolve `where` → seeded candidate files. The walker enumerates every
      // file the `where` includes (`extensions` / `filePatterns`; an empty
      // `where` includes ALL files), then `preFilter` narrows to anchor-
      // carrying files (empty preFilter = every included file is a candidate).
      // Under --diff, the list is intersected with the changed-file set.
      // There is no "roam" mode: an agent always reviews a concrete file set
      // in batches, and uses its tools to read beyond it when needed.
      const candidates: AgentCandidate[] = [];
      const [work] = walkForAgents(root, [agent], agentWalkCfg);
      const files = work ? work.files : [];
      const scopedFiles = diffFiles ? files.filter((f) => diffFiles.has(f)) : files;
      for (const relPath of scopedFiles) {
        let content: string;
        try {
          content = readFileSync(resolve(root, relPath), "utf8");
        } catch {
          continue;
        }
        const hits = evaluatePreFilter(content, agent.where.preFilter);
        if (hits.length === 0) continue;
        candidates.push({ filePath: relPath, content, hits });
        touchedFiles.add(relPath);
      }
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
          });
          allRecordsCache = null;
        } catch {
          // best-effort
        }
        continue;
      }

      const maxTurns = opts.maxTurns ?? agent.where.maxTurnsPerBatch;
      const batchSize = Math.max(1, opts.maxFilesPerBatch ?? agent.where.maxFilesPerBatch);
      const diffArg =
        opts.diff && diffPatch !== undefined ? { commit: opts.diff, patch: diffPatch } : undefined;

      // Candidates are reviewed in batches of `batchSize`, run concurrently.
      const batches: AgentCandidate[][] = [];
      for (let i = 0; i < candidates.length; i += batchSize) {
        batches.push(candidates.slice(i, i + batchSize));
      }

      console.log(
        `  ${agent.slug}: ${candidates.length} candidate file(s) → ${batches.length} batch(es) of up to ${batchSize} (concurrency ${concurrency})`,
      );

      let agentFailed = false;
      await runConcurrent(batches, concurrency, async (batch) => {
        try {
          const batchFindings = await detector.runAgent({
            agent,
            rootDir: root,
            recon: reconBlock,
            candidates: batch,
            excludePatterns: agentExcludes,
            maxFileSizeKb: opts.maxFileSize ?? 500,
            maxTurns,
            diff: diffArg,
            signal: scanAbortController.signal,
          });
          // Drop findings whose filePath doesn't exist on disk (model
          // invented a path — common with smaller models).
          const valid = batchFindings.filter((f) => {
            if (!f.filePath || f.filePath === "(unknown)") return true;
            if (existsSync(resolve(root, f.filePath))) return true;
            if (opts.verbose) {
              console.log(
                `    ${agent.slug}: dropping finding with non-existent path: ${f.filePath}`,
              );
            }
            return false;
          });
          findings.push(...valid);
          byAgent[agent.slug] = (byAgent[agent.slug] ?? 0) + valid.length;
          for (const f of valid) {
            if (f.filePath && f.filePath !== "(unknown)") touchedFiles.add(f.filePath);
          }
          if (opts.verbose || valid.length > 0) {
            const label = batch.map((c) => c.filePath).join(", ");
            console.log(`    [${label}]: ${valid.length} finding(s)`);
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
            persistDetection(relPath, agent, content, group);
          }
          // Stamp an empty record for candidate files with no findings so
          // `status` reports candidate files with no findings as analyzed.
          for (const c of batch) {
            if (byFile.has(c.filePath)) continue;
            persistDetection(c.filePath, agent, c.content, []);
          }
        } catch (err) {
          agentFailed = true;
          handleDetectorError(opts, `agent:${agent.slug}`, err, scanAbortController);
        }
      });

      // Write the resume sidecar only when every batch succeeded — a
      // failed agent leaves no sidecar and re-runs next time.
      if (!agentFailed) {
        try {
          writeAgentRun(outDir, {
            agentSlug: agent.slug,
            lastCompletedRunId: runMeta.runId,
            lastCompletedAt: new Date().toISOString(),
            scope: currentScope,
            precondition: { queued: true },
            findingCount: byAgent[agent.slug] ?? 0,
          });
          allRecordsCache = null;
        } catch (err) {
          if (opts.verbose) {
            console.error(
              `    ${agent.slug}: failed to write resume sidecar: ${(err as Error).message}`,
            );
          }
        }
      }
    }
    if (queuedAgents.length > 0) {
      const ranCount = queuedAgents.length - cachedAgentCount;
      console.log(
        `  Agents: ${ranCount} ran, ${cachedAgentCount} reused from prior run${
          cachedAgentCount > 0 ? " (pass --rescan to force a full re-run)" : ""
        }`,
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
          `\nValidating ${validatable.length} finding(s)${scopeNote}${carryNote}${modeNote} (one at a time)`,
        );
        const fileCache = new Map<string, string | null>();
        // Validation always runs sequentially — one finding at a time —
        // so progress is legible and per-finding failures don't get
        // tangled with parallel siblings.
        await runConcurrent(validatable, 1, async (finding) => {
          // Scope-only branch: never read the file, only ask the LLM to
          // classify against --scope, and only persist `out-of-scope`.
          // Findings the scope doesn't disqualify are left untouched so a
          // follow-up `revalidate` (full mode) can still assess them.
          if (scopeOnlyValidate) {
            try {
              const result = await detector.validateFindingByScope({
                finding,
                scope: scopeContent!,
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
              signal: scanAbortController.signal,
            });
            finding.validation = {
              verdict: result.verdict,
              reasoning: result.reasoning,
            };
            if (opts.verbose) {
              console.log(`    ${finding.filePath}: ${result.verdict}`);
            }
          } catch (err) {
            handleDetectorError(opts, `validate:${finding.id}`, err, scanAbortController);
          }
        });
        // Persist validation verdicts back into FileRecords. Group by
        // file so each record is rewritten once even when N findings
        // share a path.
        const byFile = new Map<string, Finding[]>();
        for (const f of validatable) {
          if (!f.validation) continue;
          const normalized = f.filePath.replace(/\\/g, "/");
          if (isAbsolute(normalized)) continue;
          const list = byFile.get(normalized) ?? [];
          list.push(f);
          byFile.set(normalized, list);
        }
        for (const [normalized, group] of byFile) {
          const record = readFileRecord(outDir, normalized);
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
            agentSlugs: Array.from(new Set(group.map((f) => f.agentSlug))),
            findingCount: group.length,
          });
          record.status = "validated";
          try {
            writeFileRecord(outDir, record);
          } catch (err) {
            if (opts.verbose) {
              console.error(`    persist failed for ${normalized}: ${(err as Error).message}`);
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
        const scoredByFile = new Map<string, Finding[]>();
        // Sequential — same legibility argument as validation. The
        // scorer is one call per finding; parallelizing it would tangle
        // progress + rate-limit pressure with the validator above.
        await runConcurrent(scorable, 1, async (finding) => {
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
              signal: scanAbortController.signal,
            });
            finding.cvss = cvss;
            finding.severity = cvss.severity;
            const normalized = finding.filePath.replace(/\\/g, "/");
            const list = scoredByFile.get(normalized) ?? [];
            list.push(finding);
            scoredByFile.set(normalized, list);
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
        // Persist scored findings back into the FileRecord. Grouped by
        // file so each record is rewritten once per scoring run.
        for (const [normalized, group] of scoredByFile) {
          if (isAbsolute(normalized)) continue;
          const record = readFileRecord(outDir, normalized);
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
            agentSlugs: Array.from(new Set(group.map((f) => f.agentSlug))),
            findingCount: group.length,
          });
          try {
            writeFileRecord(outDir, record);
          } catch (err) {
            if (opts.verbose) {
              console.error(`    persist failed for ${normalized}: ${(err as Error).message}`);
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

    const completedAt = new Date();

    const report = writeMarkdownReport({
      outDir,
      root,
      startedAt,
      completedAt,
      findings,
      filesScanned: touchedFiles.size,
      byAgent,
      excludeFalsePositives: opts.excludeFalsePositives,
    });

    completeRun(outDir, runMeta.runId, "done", {
      filesScanned: touchedFiles.size,
      findingsCount: findings.length,
      totalDurationMs: completedAt.getTime() - startedAt.getTime(),
    });
    runFinalized = true;
    process.off("SIGINT", sigintHandler);

    console.log(`\nDone. ${findings.length} finding(s) across ${touchedFiles.size} file(s).`);
    console.log(`  Summary: ${report.summaryPath}`);
    console.log(`  Findings dir: ${outDir}\\findings`);

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
        completeRun(outDir, runMeta.runId, "error", {});
      } catch {
        // best-effort
      }
    }
    process.off("SIGINT", sigintHandler);
    if (err instanceof FatalScanError) {
      // Single clean line. The action handler also prints "scan failed:"
      // around it, so the user sees the diagnostic message once.
      throw new Error(err.message);
    }
    throw err;
  }
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
 * *why* a hunt sidecar got ignored on resume.
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
      "path to a SECURITY.md-style scope file. With --validate, scope rules are threaded into the full classifier (verdicts include `out-of-scope`). WITHOUT --validate, triggers scope-only validation: the model never re-reads the source and only persists `out-of-scope` verdicts (cheap pre-filter).",
    )
    .option("-o, --output <path>", "output directory for findings", "./scan-results/")
    .option(
      "--validate",
      "run a full second-pass LLM validation phase per finding (slower; reduces false positives). Combine with --scope to thread scope rules into the classifier.",
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
      "Restrict the scan to specific agents. A value can be: a slug (`sql-injection`), a path to a `.md` agent file, a directory of `.md` files, or a `.txt` file listing slugs/paths one per line (# for comments). Multiple values can be comma- or whitespace-separated within one `-t`, or `-t` may be repeated.",
      collect,
      [] as string[],
    )
    .option(
      "--diff <commit>",
      "Restrict the scan to a single commit's own changes (parent → commit), independent of the working tree. Each agent's candidate files are intersected with the files touched in <commit>, and the commit patch is injected into the agent's prompt as a focus hint (tools stay unrestricted so it can chase context outward).",
    )
    .option("--concurrency <n>", "parallel file processing", (v) => parseInt(v, 10), 5)
    .option(
      "--max-turns <n>",
      "Max tool-use turns per LLM session. When set, applies uniformly to every agent batch, recon, and the validator. When unset: agent batches use the agent's `where.maxTurnsPerBatch` (default 30), recon 30, validator 30.",
      (v) => parseInt(v, 10),
    )
    .option(
      "--max-files-per-batch <n>",
      "Walker mode: candidate files packed into one investigation batch. Overrides the agent's `maxFilesPerBatch`. Default 5. Different from --concurrency: batch size = files per LLM session; --concurrency = sessions in parallel.",
      (v) => parseInt(v, 10),
    )
    .option(
      "--effort <level>",
      "SDK reasoning effort for tool-using calls (recon, agent runs, validate). One of: low, medium, high, max. Default: SDK default (no override).",
    )
    .option(
      "--thinking <mode>",
      "SDK thinking mode for tool-using calls. One of: off, adaptive, enabled. `adaptive` matches Claude Code interactive — the model decides per call.",
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
      "--score",
      "Run the CVSS 3.1 scoring phase after detection (and after --validate when set). The agent picks the 8 base metrics; the score and severity bucket are computed deterministically. Findings the validator marked false-positive or out-of-scope are skipped.",
    )
    .option(
      "--rescore",
      "Re-score findings even when they already carry a CVSS score on disk (default: skip them)",
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
      "skip files larger than this in KB (default 500)",
      (v) => parseInt(v, 10),
      500,
    )
    .option(
      "--no-default-excludes",
      "Don't apply the shared default exclude set (node_modules, .git, build dirs, lockfiles, binaries). Scans everything except your explicit --exclude paths. Per-agent opt-out is `where.useDefaultExcludes: false`.",
    )
    .option("-v, --verbose", "verbose output")
    .action(async (path: string, opts: ScanOpts) => {
      try {
        await runScan(path, opts);
      } catch (err) {
        console.error(`scan failed: ${err instanceof Error ? err.message : String(err)}`);
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
