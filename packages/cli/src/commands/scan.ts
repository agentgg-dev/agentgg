import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import type { Agent, FileRecord, Finding, Surface } from "@agentgg/core";
import {
  completeRun,
  createRunMeta,
  getOfficialAgentsDir,
  hashContent,
  loadUserConfig,
  readFileRecord,
  upsertScanMeta,
  writeFileRecord,
  writeRunMeta,
} from "@agentgg/core";
import type { Command } from "commander";
import { loadAllAgents } from "../agent-catalog.js";
import { installOfficialAgents } from "../agents-install.js";
import { runConcurrent } from "../concurrent.js";
import { diagnoseScanError } from "../diagnostics.js";
import { listChangedFiles, loadCommitPatch } from "../diff.js";
import { type CredentialOverrides, resolveDetector } from "../llm.js";
import { evaluatePreFilter } from "../pre-filter.js";
import { writeMarkdownReport } from "../reporters/md.js";
import { resolveTemplates } from "../template.js";
import { DEFAULT_VIEWER_PORT, openBrowser, startViewer } from "../viewer-server.js";
import { printReady } from "./view.js";
import { type WalkConfig, walkForAgents } from "../walker.js";

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
  model?: string;
  concurrency?: number;
  diff?: string;
  template?: string[];
  verbose?: boolean;
  exclude?: string[];
  only?: string[];
  maxFileSize?: number; // KB
  /** Re-analyze files even when a prior FileRecord covers them with the same contentHash. */
  rescan?: boolean;
  /** Re-validate findings even when they already have a verdict on disk. */
  revalidateAll?: boolean;
  /**
   * Max tool-use turns per LLM session. When set, applies uniformly across
   * every mode (file/walker/hunt) and the validator. When unset, each context
   * uses its own internal default (file=5, walker=30, hunt=150, validator=30).
   */
  maxTurns?: number;
  /** Walker mode: candidate files per investigation batch. Overrides agent default. */
  maxFilesPerBatch?: number;
  /** SDK reasoning effort. Maps to `effort` option. */
  effort?: "low" | "medium" | "high" | "max";
  /** SDK thinking mode. `adaptive` is what deepsec uses; `off` skips entirely. */
  thinking?: "off" | "adaptive" | "enabled";
  /** Keep false-positive findings in the markdown report instead of filtering them out. */
  includeFalsePositives?: boolean;
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
 * Orchestrate a scan. Each agent's declared `mode` decides its shape:
 *
 *   - `mode: "file"` (default) → walk the repo, route each surviving file
 *     to the agents whose `filePatterns` match it, run one LLM call per
 *     (agent, file).
 *
 *   - `mode: "hunt"` → run one tool-enabled LLM session per agent across
 *     the whole repo. Under `--diff <commit>`, the agent is handed
 *     `git show <commit>` (message + patch) and told to focus its
 *     investigation on that commit; tools stay unrestricted so it can
 *     chase callers / imports / related files outward for context.
 *
 *   - `mode: "walker"` → enumerate by `filePatterns`, narrow with
 *     `preFilter` regexes, then pool matching files across agents into
 *     batched LLM sessions. Under `--diff <commit>`, the candidate file
 *     list is intersected with the files touched in that commit so only
 *     those files are investigated.
 *
 * `--diff <commit>` always means "review just this commit" — its own
 * patch (parent → commit), independent of the working tree state.
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
      console.error(
        "\nInterrupted. Partial state persisted; re-run the same command to resume.",
      );
    }
    process.exit(130);
  };
  process.on("SIGINT", sigintHandler);

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
    process.stdout.write(
      "[INF] agentgg-agents are not installed, installing...\n",
    );
    try {
      const { version, count } = await installOfficialAgents(env);
      process.stdout.write(
        `[INF] Successfully installed agentgg-agents at ~/.agentgg/agentgg-agents (${count} agents, ${version})\n`,
      );
    } catch (err) {
      process.stderr.write(
        `[WRN] Could not auto-install agents: ${(err as Error).message}\n`,
      );
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
  const selectedAgents: Agent[] =
    templateInputs.length > 0
      ? resolveTemplates(templateInputs, catalog.agents, officialAgentsDir)
      : existsSync(baseDir)
        ? resolveTemplates([baseDir], catalog.agents, officialAgentsDir)
        : catalog.agents;
  if (selectedAgents.length === 0) {
    throw new Error("No agents selected — nothing to scan.");
  }

  // `--diff <commit>` scopes the scan to a single commit's own changes
  // (parent → commit), independent of working tree state.
  //  - file & walker modes: intersect their candidate list with the
  //    files touched in the commit (`git diff-tree --name-only`).
  //  - hunt mode: `git show <commit>` (message + patch) is injected
  //    into the hunter's prompt as a focus hint; tools stay
  //    unrestricted so it can chase context outward.
  const diffFiles: Set<string> | undefined = opts.diff
    ? new Set(listChangedFiles(opts.diff, root))
    : undefined;
  const diffPatch: string | undefined = opts.diff
    ? loadCommitPatch(opts.diff, root)
    : undefined;

  const excludePatterns = [...(opts.exclude ?? [])];
  const includePatterns = opts.only ?? [];
  const maxFileSizeBytes = (opts.maxFileSize ?? 500) * 1024;

  // Read scope file once if --scope is set. Passed verbatim into the
  // validator prompt so `out-of-scope` becomes a meaningful verdict.
  // Missing-file is fatal: the user explicitly asked for scope.
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

  // `--scope` without `--validate` triggers scope-only validation:
  // a cheap, file-read-free pre-filter that classifies each finding
  // against the scope document alone. `--validate` with or without
  // `--scope` runs the full source-reading classifier.
  const scopeOnlyValidate = !opts.validate && !!scopeContent;

  const walkCfg: WalkConfig = {
    excludePatterns,
    includePatterns,
    maxFileSizeBytes,
  };

  const startedAt = new Date();

  console.log(`Scanning ${root}`);
  console.log(
    `Agents: ${selectedAgents.map((a) => `${a.slug}[${a.mode}]`).join(", ")}`,
  );
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
    console.log(`Validation: scope-only (scope: ${opts.scope}; only out-of-scope verdicts persisted)`);
  }
  if (excludePatterns.length > 0) {
    console.log(`Excluding: ${excludePatterns.join(", ")}`);
  }
  if (includePatterns.length > 0) {
    console.log(`Only: ${includePatterns.join(", ")}`);
  }
  console.log("");

  const findings: Finding[] = [];
  const surfaces: Surface[] = [];
  const byAgent: Record<string, number> = {};
  const surfacesByAgent: Record<string, number> = {};
  const touchedFiles = new Set<string>();

  // Initialise or load the FileRecord for one relative path. Shared
  // by persistDetection and persistSurfaces so both helpers see the
  // same on-disk state when a single file is touched by both a vuln
  // agent and a recon agent in the same walker batch.
  function loadOrCreateRecord(relPath: string, fileContent: string): {
    record: FileRecord;
    normalized: string;
  } {
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
        surfaces: [],
        analysisHistory: [],
        scope: { outOfScope: false },
        status: "pending",
      };
    }
    return { record, normalized };
  }

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
    const { record, normalized } = loadOrCreateRecord(relPath, fileContent);
    const byId = new Map(record.findings.map((f) => [f.id, f]));
    // Stamp runId = "last run that emitted this finding" so the viewer
    // can scope to the latest run. On re-detection (same id, different
    // run), the new entry overwrites — last-seen wins.
    for (const f of newFindings) byId.set(f.id, { ...f, runId: runMeta.runId });
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
        console.error(
          `    persist failed for ${normalized}: ${(err as Error).message}`,
        );
      }
    }
  }

  // Mirror of persistDetection for recon agents (agent.outputType ===
  // "surface"). Surfaces live in `FileRecord.surfaces` so the validation
  // pipeline (which iterates `record.findings`) ignores them cleanly.
  // The AnalysisRun entry's `findingCount` is reused to mean "artifacts
  // persisted" — we don't add a separate surfaceCount field because
  // (a) the AnalysisRun schema is in core and (b) the count is
  // bookkeeping for the operator, not load-bearing for any logic.
  function persistSurfaces(
    relPath: string,
    agent: Agent,
    fileContent: string,
    newSurfaces: Surface[],
  ): void {
    const { record, normalized } = loadOrCreateRecord(relPath, fileContent);
    const byId = new Map((record.surfaces ?? []).map((s) => [s.id, s]));
    // Stamp runId same way as findings — see persistDetection.
    for (const s of newSurfaces) byId.set(s.id, { ...s, runId: runMeta.runId });
    record.surfaces = [...byId.values()];
    record.analysisHistory.push({
      runId: runMeta.runId,
      phase: "detect",
      ranAt: new Date().toISOString(),
      durationMs: 0,
      provider: detector.name,
      agentSlugs: [agent.slug],
      findingCount: newSurfaces.length,
    });
    record.status = "analyzed";
    try {
      writeFileRecord(outDir, record);
    } catch (err) {
      if (opts.verbose) {
        console.error(
          `    persist failed for ${normalized}: ${(err as Error).message}`,
        );
      }
    }
  }

  const fileAgents = selectedAgents.filter((a) => a.mode === "file");
  const huntAgents = selectedAgents.filter((a) => a.mode === "hunt");
  const walkerAgents = selectedAgents.filter((a) => a.mode === "walker");

  // -------- hunt-mode agents (run FIRST) --------
  // Hunt agents are the heavier pass — give them a head start so the
  // total wall-clock time is dominated by file-mode work that runs
  // after, not waiting on a long-running hunt to finish.
  // Under --diff, the hunter still runs but receives the commit patch
  // in its prompt as a focus hint; tools stay unrestricted so it can
  // chase context outward beyond the diff.
  for (const agent of huntAgents) {
    console.log(
      opts.diff
        ? `  ${agent.slug}[hunt]: reviewing commit ${opts.diff} (Read/Glob/Grep)`
        : `  ${agent.slug}[hunt]: scanning whole repo (Read/Glob/Grep)`,
    );
    try {
      // Merge the agent's declared `excludePatterns` (from
      // frontmatter) with the CLI's --exclude list, deduped.
      // Either alone is honored; both compose additively.
      const agentExcludes = Array.from(
        new Set([...excludePatterns, ...(agent.excludePatterns ?? [])]),
      );
      const huntFindings = await detector.hunt({
        agent,
        rootDir: root,
        excludePatterns: agentExcludes,
        includePatterns,
        maxFileSizeKb: opts.maxFileSize ?? 500,
        maxTurns: opts.maxTurns ?? 150,
        diff:
          opts.diff && diffPatch !== undefined
            ? { commit: opts.diff, patch: diffPatch }
            : undefined,
      });
      // Drop findings where the model invented a path that doesn't exist on
      // disk — common with smaller models that copy the example filePath from
      // the output-format instruction instead of using a real path.
      const validHuntFindings = huntFindings.filter((f) => {
        if (!f.filePath || f.filePath === "(unknown)") return true;
        if (existsSync(resolve(root, f.filePath))) return true;
        if (opts.verbose) {
          console.log(`    ${agent.slug}: dropping finding with non-existent path: ${f.filePath}`);
        }
        return false;
      });
      findings.push(...validHuntFindings);
      byAgent[agent.slug] = (byAgent[agent.slug] ?? 0) + validHuntFindings.length;
      for (const f of validHuntFindings) touchedFiles.add(f.filePath);
      const droppedCount = huntFindings.length - validHuntFindings.length;
      console.log(
        `    ${agent.slug}: ${validHuntFindings.length} finding(s) across ${
          new Set(validHuntFindings.map((f) => f.filePath)).size
        } file(s)${droppedCount > 0 ? ` (${droppedCount} dropped: path not found in repo)` : ""}`,
      );

      // Persist hunt findings per-file. We need each file's content to
      // stamp a contentHash on the FileRecord; skip files that won't
      // read (e.g. the model invented a path, or the file is binary).
      const byFile = new Map<string, Finding[]>();
      for (const f of validHuntFindings) {
        if (!f.filePath || f.filePath === "(unknown)") continue;
        const list = byFile.get(f.filePath) ?? [];
        list.push(f);
        byFile.set(f.filePath, list);
      }
      for (const [relPath, group] of byFile) {
        let content: string;
        try {
          content = readFileSync(resolve(root, relPath), "utf8");
        } catch {
          continue;
        }
        persistDetection(relPath, agent, content, group);
      }
    } catch (err) {
      logDetectionError(opts, `hunt:${agent.slug}`, err);
    }
  }

  // -------- walker-mode agents (run AFTER hunts, BEFORE file mode) --------
  // Deepsec-style: walker enumerates by filePatterns, each agent's
  // preFilter regexes narrow to candidates, then matching candidates
  // are POOLED ACROSS AGENTS by file. A file flagged by N agents is
  // investigated ONCE in a session that carries all N agents'
  // detection briefs + all N agents' hits, then findings are
  // attributed back per-agent. Same cost shape as deepsec — same
  // file is never paid for twice.
  // Under --diff, each agent's file list is intersected with the diff
  // before pooling so unchanged files never enter the candidate set.
  if (walkerAgents.length > 0) {
    const walkerWork = walkForAgents(root, walkerAgents, walkCfg);

    // file → { content, agentSlug → hits } — the cross-agent pool.
    // Reading each file at most once even when many agents match.
    type PooledFile = {
      relPath: string;
      content: string;
      hitsByAgent: Map<string, { line: number; label: string; snippet: string }[]>;
    };
    const pool = new Map<string, PooledFile>();
    const agentsBySlug = new Map(walkerAgents.map((a) => [a.slug, a]));

    for (const { agent, files } of walkerWork) {
      const scopedFiles = diffFiles
        ? files.filter((f) => diffFiles.has(f))
        : files;
      for (const relPath of scopedFiles) {
        let entry = pool.get(relPath);
        if (!entry) {
          let content: string;
          try {
            content = readFileSync(resolve(root, relPath), "utf8");
          } catch {
            continue;
          }
          entry = { relPath, content, hitsByAgent: new Map() };
          pool.set(relPath, entry);
        }
        const hits = evaluatePreFilter(entry.content, agent.preFilter ?? []);
        if (hits.length > 0) {
          entry.hitsByAgent.set(agent.slug, hits);
          touchedFiles.add(relPath);
        }
      }
    }

    // Drop files with no hits from any agent — they were walked but
    // nothing flagged them. Files with at least one agent's hits
    // become the candidates for batched investigation.
    const candidates: PooledFile[] = [];
    for (const entry of pool.values()) {
      if (entry.hitsByAgent.size > 0) candidates.push(entry);
    }

    // Use the largest declared maxFilesPerBatch / maxTurnsPerBatch
    // across participating agents as the batch sizing. The unified
    // --max-turns CLI flag overrides per-batch turns when set; agents
    // with smaller declared budgets implicitly benefit from the larger
    // value when pooled with others.
    const concurrency = Math.max(1, opts.concurrency ?? 5);
    const declaredBatchSize = Math.max(
      ...walkerAgents.map((a) => a.maxFilesPerBatch ?? 5),
    );
    const batchSize = Math.max(
      1,
      opts.maxFilesPerBatch ?? declaredBatchSize,
    );
    const declaredMaxTurns = Math.max(
      ...walkerAgents.map((a) => a.maxTurnsPerBatch ?? 30),
    );
    const maxTurnsPerBatch = opts.maxTurns ?? declaredMaxTurns;

    const batches: PooledFile[][] = [];
    for (let i = 0; i < candidates.length; i += batchSize) {
      batches.push(candidates.slice(i, i + batchSize));
    }

    const totalAgentHits = candidates.reduce(
      (n, c) => n + c.hitsByAgent.size,
      0,
    );
    console.log(
      `  walker: ${walkerAgents.length} agent(s), ${candidates.length} candidate file(s), ${totalAgentHits} (file × agent) hit pair(s) → ${batches.length} batch(es) of up to ${batchSize} (concurrency ${concurrency})`,
    );

    await runConcurrent(batches, concurrency, async (batch) => {
      // Union of agents that flagged any file in this batch — those
      // are the briefs the investigator needs.
      const agentSlugsInBatch = new Set<string>();
      for (const c of batch) {
        for (const slug of c.hitsByAgent.keys()) agentSlugsInBatch.add(slug);
      }
      const agentsInBatch = Array.from(agentSlugsInBatch)
        .map((s) => agentsBySlug.get(s))
        .filter((a): a is NonNullable<typeof a> => Boolean(a));

      const labels = batch.map((c) => c.relPath).join(", ");
      try {
        const { findings: batchFindings, surfaces: batchSurfaces } =
          await detector.investigate({
            agents: agentsInBatch,
            rootDir: root,
            candidates: batch.map((c) => ({
              filePath: c.relPath,
              content: c.content,
              hitsByAgent: Array.from(c.hitsByAgent.entries()).map(
                ([agentSlug, hits]) => ({ agentSlug, hits }),
              ),
            })),
            maxTurns: maxTurnsPerBatch,
          });
        findings.push(...batchFindings);
        surfaces.push(...batchSurfaces);
        for (const f of batchFindings) {
          byAgent[f.agentSlug] = (byAgent[f.agentSlug] ?? 0) + 1;
        }
        for (const s of batchSurfaces) {
          surfacesByAgent[s.agentSlug] = (surfacesByAgent[s.agentSlug] ?? 0) + 1;
        }
        if (opts.verbose || batchFindings.length > 0 || batchSurfaces.length > 0) {
          const surfaceNote =
            batchSurfaces.length > 0 ? `, ${batchSurfaces.length} surface(s)` : "";
          console.log(
            `    batch [${labels}]: ${batchFindings.length} finding(s)${surfaceNote} across ${agentsInBatch.length} agent(s)`,
          );
        }
        // Persist per (file, agent) pair: each finding goes to its
        // owning agent's record on its filePath. A finding whose
        // filePath is outside the batch (model followed an import)
        // still gets routed to the right FileRecord.
        for (const f of batchFindings) {
          if (!f.filePath || f.filePath === "(unknown)") continue;
          const owningAgent = agentsBySlug.get(f.agentSlug);
          if (!owningAgent) continue;
          const inBatch = batch.find((c) => c.relPath === f.filePath);
          let content: string;
          if (inBatch) {
            content = inBatch.content;
          } else {
            try {
              content = readFileSync(resolve(root, f.filePath), "utf8");
            } catch {
              continue;
            }
          }
          persistDetection(f.filePath, owningAgent, content, [f]);
        }
        // Same persistence shape for surfaces: route each into its
        // owning recon agent's FileRecord.surfaces[]. Mirrors the
        // findings loop above so a file flagged by both a vuln and a
        // recon agent ends up with entries in both arrays.
        for (const s of batchSurfaces) {
          if (!s.filePath || s.filePath === "(unknown)") continue;
          const owningAgent = agentsBySlug.get(s.agentSlug);
          if (!owningAgent) continue;
          const inBatch = batch.find((c) => c.relPath === s.filePath);
          let content: string;
          if (inBatch) {
            content = inBatch.content;
          } else {
            try {
              content = readFileSync(resolve(root, s.filePath), "utf8");
            } catch {
              continue;
            }
          }
          persistSurfaces(s.filePath, owningAgent, content, [s]);
        }
        // Stamp empty AnalysisRun for (batch member, agent) pairs
        // that produced zero artifacts so status reports "analyzed".
        // The agent's outputType picks which persist call to make so
        // we don't write an empty findings entry for a recon agent
        // (or vice versa).
        for (const c of batch) {
          for (const slug of c.hitsByAgent.keys()) {
            const owningAgent = agentsBySlug.get(slug);
            if (!owningAgent) continue;
            if (owningAgent.outputType === "surface") {
              const sHere = batchSurfaces.some(
                (s) => s.filePath === c.relPath && s.agentSlug === slug,
              );
              if (sHere) continue;
              persistSurfaces(c.relPath, owningAgent, c.content, []);
            } else {
              const fHere = batchFindings.some(
                (f) => f.filePath === c.relPath && f.agentSlug === slug,
              );
              if (fHere) continue;
              persistDetection(c.relPath, owningAgent, c.content, []);
            }
          }
        }
      } catch (err) {
        logDetectionError(opts, `walker:batch[${labels}]`, err);
      }
    });
  }

  // -------- file-mode agents (run AFTER hunts) --------
  if (fileAgents.length > 0) {
    const work = walkForAgents(root, fileAgents, walkCfg);
    for (const f of work.flatMap((w) => w.files)) touchedFiles.add(f);

    for (const { agent, files } of work) {
      // When --diff is on, intersect the agent's file list with the
      // set of files git says changed since the given commit. This is
      // the whole point of --diff: only spend LLM calls on what moved.
      const filteredFiles = diffFiles
        ? files.filter((f) => diffFiles.has(f))
        : files;

      if (filteredFiles.length === 0) {
        if (opts.verbose) console.log(`  ${agent.slug}[file]: no matching files`);
        continue;
      }
      const concurrency = Math.max(1, opts.concurrency ?? 5);
      console.log(
        `  ${agent.slug}[file]: ${filteredFiles.length} file(s) (concurrency ${concurrency})`,
      );
      // Parallel within an agent, sequential across agents. JS is
      // single-threaded so the array/object mutations between awaits
      // are race-free; runConcurrent just decides which task runs next.
      let cachedCount = 0;
      await runConcurrent(filteredFiles, concurrency, async (relPath) => {
        const absPath = resolve(root, relPath);
        let content: string;
        try {
          content = readFileSync(absPath, "utf8");
        } catch (err) {
          if (opts.verbose) {
            console.log(`    skip ${relPath}: ${(err as Error).message}`);
          }
          return;
        }
        // Resume path: if a prior run already analyzed this exact
        // content with this agent, lift the persisted findings into
        // memory and skip the LLM call. `--rescan` bypasses the check.
        const normalized = relPath.replace(/\\/g, "/");
        if (!opts.rescan) {
          const fileHash = hashContent(content);
          let existing;
          try {
            existing = readFileRecord(outDir, normalized);
          } catch {
            existing = null;
          }
          const ranBefore =
            !!existing &&
            existing.contentHash === fileHash &&
            existing.analysisHistory.some(
              (a) =>
                a.phase === "detect" && a.agentSlugs.includes(agent.slug),
            );
          if (ranBefore && existing) {
            const cached = existing.findings.filter(
              (f) => f.agentSlug === agent.slug,
            );
            findings.push(...cached);
            byAgent[agent.slug] = (byAgent[agent.slug] ?? 0) + cached.length;
            cachedCount++;
            if (opts.verbose) {
              console.log(
                `    ${relPath}: cached (${cached.length} finding(s) from disk)`,
              );
            }
            return;
          }
        }
        try {
          const fileFindings = await detector.detectFile({
            agent,
            filePath: relPath,
            content,
          });
          findings.push(...fileFindings);
          byAgent[agent.slug] = (byAgent[agent.slug] ?? 0) + fileFindings.length;
          if (opts.verbose || fileFindings.length > 0) {
            console.log(`    ${relPath}: ${fileFindings.length} finding(s)`);
          }
          // Always upsert the FileRecord even when no findings — that
          // way `status` reports "analyzed" for clean files, not
          // "pending."
          persistDetection(relPath, agent, content, fileFindings);
        } catch (err) {
          logDetectionError(opts, relPath, err);
        }
      });
      if (cachedCount > 0) {
        console.log(
          `    ${cachedCount} file(s) reused from prior run (pass --rescan to force).`,
        );
      }
    }
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
    const candidates = findings.filter(
      (f) => f.filePath && f.filePath !== "(unknown)",
    );
    // Resume path: skip findings that already carry a verdict on disk.
    // `--revalidate-all` bypasses the skip and forces re-classification.
    const validatable = opts.revalidateAll
      ? candidates
      : candidates.filter((f) => !f.validation);
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
            logDetectionError(opts, `scope-validate:${finding.id}`, err);
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
          });
          finding.validation = {
            verdict: result.verdict,
            reasoning: result.reasoning,
          };
          if (opts.verbose) {
            console.log(`    ${finding.filePath}: ${result.verdict}`);
          }
        } catch (err) {
          logDetectionError(opts, `validate:${finding.id}`, err);
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
          // A validate pass also bumps runId so the viewer keeps showing
          // findings that were re-touched by the latest run, even when
          // the detect phase didn't re-emit them this round.
          return live?.validation
            ? { ...rec, runId: runMeta.runId, validation: live.validation }
            : rec;
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
            console.error(
              `    persist failed for ${normalized}: ${(err as Error).message}`,
            );
          }
        }
      }
      // Final tally combines this-run verdicts and carried-over ones so
      // the summary reflects every classified finding, not just freshly
      // validated ones.
      const finalVerdicts: Record<string, number> = {};
      for (const f of candidates) {
        if (!f.validation) continue;
        finalVerdicts[f.validation.verdict] =
          (finalVerdicts[f.validation.verdict] ?? 0) + 1;
      }
      const summary = Object.entries(finalVerdicts)
        .sort()
        .map(([v, n]) => `${v}=${n}`)
        .join(", ");
      console.log(`  Verdicts: ${summary || "(none)"}`);
    }
  }

  const completedAt = new Date();

  const report = writeMarkdownReport({
    outDir,
    root,
    startedAt,
    completedAt,
    findings,
    surfaces,
    filesScanned: touchedFiles.size,
    byAgent,
    surfacesByAgent,
    includeFalsePositives: opts.includeFalsePositives,
  });

  completeRun(outDir, runMeta.runId, "done", {
    filesScanned: touchedFiles.size,
    findingsCount: findings.length,
    totalDurationMs: completedAt.getTime() - startedAt.getTime(),
  });
  runFinalized = true;
  process.off("SIGINT", sigintHandler);

  const surfaceNote = surfaces.length > 0 ? `, ${surfaces.length} surface(s)` : "";
  console.log(
    `\nDone. ${findings.length} finding(s)${surfaceNote} across ${touchedFiles.size} file(s).`,
  );
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
}

function logDetectionError(opts: ScanOpts, label: string, err: unknown): void {
  const e = err as Error & {
    cause?: unknown;
    responseBody?: string;
    statusCode?: number;
    url?: string;
  };
  const msg = e.message || String(err);

  const diagnostic = diagnoseScanError(err);
  if (diagnostic) {
    console.error(`    ${label}: ${diagnostic.format()}`);
    if (opts.verbose && e.stack) {
      console.error(
        e.stack
          .split("\n")
          .slice(0, 8)
          .map((l) => `      ${l}`)
          .join("\n"),
      );
    }
    return;
  }

  console.error(`    ${label}: detection failed — ${msg}`);
  if (e.statusCode) console.error(`      HTTP ${e.statusCode} ${e.url ?? ""}`);
  if (e.responseBody) {
    console.error(`      Response: ${String(e.responseBody).slice(0, 300)}`);
  }
  if (e.cause && typeof e.cause === "object") {
    const c = e.cause as Error & { responseBody?: string; statusCode?: number };
    if (c.message && c.message !== msg) console.error(`      Cause: ${c.message}`);
    if (c.statusCode) console.error(`      Cause HTTP: ${c.statusCode}`);
    if (c.responseBody) {
      console.error(`      Cause body: ${String(c.responseBody).slice(0, 300)}`);
    }
  }
  if (opts.verbose && e.stack) {
    console.error(
      e.stack
        .split("\n")
        .slice(0, 8)
        .map((l) => `      ${l}`)
        .join("\n"),
    );
  }
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
    .option(
      "-o, --output <path>",
      "output directory for findings",
      "./scan-results/",
    )
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
      "LLM provider for this run: anthropic | openai | ollama (overrides saved default)",
    )
    .option(
      "--api-key <key>",
      "One-shot API key for the selected provider (not persisted). For Anthropic, also accepts an sk-ant-oat… OAuth token.",
    )
    .option(
      "--oauth-token <token>",
      "One-shot Anthropic OAuth token (sk-ant-oat…). Not persisted.",
    )
    .option("--base-url <url>", "One-shot Ollama base URL (not persisted)")
    .option("--model <name>", "One-shot model override for the selected provider (not persisted)")
    .option(
      "-t, --template <value>",
      "Restrict the scan to specific agents. A value can be: a slug (`sql-injection`), a path to a `.md` agent file, a directory of `.md` files, or a `.txt` file listing slugs/paths one per line (# for comments). Multiple values can be comma- or whitespace-separated within one `-t`, or `-t` may be repeated.",
      collect,
      [] as string[],
    )
    .option(
      "--diff <commit>",
      "Restrict the scan to a single commit's own changes (parent → commit), independent of the working tree. File- and walker-mode agents only see files touched in <commit>; hunt-mode agents receive `git show <commit>` (message + patch) in their prompt as a focus hint, with tools unrestricted so they can chase context outward.",
    )
    .option("--concurrency <n>", "parallel file processing", (v) => parseInt(v, 10), 5)
    .option(
      "--max-turns <n>",
      "Max tool-use turns per LLM session. Overrides all per-mode defaults: file=5, walker=30, hunt=150, validator=30. When set, applies uniformly across every mode in this run.",
      (v) => parseInt(v, 10),
    )
    .option(
      "--max-files-per-batch <n>",
      "Walker mode: candidate files packed into one investigation batch. Overrides the agent's `maxFilesPerBatch`. Default 5. Different from --concurrency: batch size = files per LLM session; --concurrency = sessions in parallel.",
      (v) => parseInt(v, 10),
    )
    .option(
      "--effort <level>",
      "SDK reasoning effort for tool-using calls (hunt / walker / validate). One of: low, medium, high, max. Default: SDK default (no override).",
    )
    .option(
      "--thinking <mode>",
      "SDK thinking mode for tool-using calls. One of: off, adaptive, enabled. `adaptive` matches Claude Code interactive and deepsec.",
    )
    .option(
      "--include-false-positives",
      "Write per-finding markdown reports for findings the validator marked false-positive (default: skip them). FP findings always stay in state/files/* regardless.",
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
    .option("-v, --verbose", "verbose output")
    .action(async (path: string, opts: ScanOpts) => {
      try {
        await runScan(path, opts);
      } catch (err) {
        console.error(`scan failed: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
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
    throw new Error(
      `--serve: invalid port "${value}" (expected an integer between 1 and 65535)`,
    );
  }
  return n;
}
