import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, extname, join, resolve, sep } from "node:path";
import { promisify } from "node:util";
import { type Agent, getSemgrepCorePath, isSemgrepPreFilter } from "@agentgg/core";
import type { TaintStep } from "./pre-filter.js";
import {
  type InstallResult,
  installSemgrepCore,
  SEMGREP_VERSION,
  type SemgrepFailure,
} from "./semgrep-install.js";
import { inspectSemgrepRule, type RuleInspection } from "./semgrep-rule.js";

const execFileAsync = promisify(execFile);

/**
 * One line a `semgrepRule` preFilter matched. No snippet: the caller has
 * the file content already and fills it in, which also keeps the
 * suppression check (see `isSemgrepSuppressed`) on the caller's side.
 */
export interface SemgrepHit {
  line: number;
  /** Last line of the match. Unset when the engine reports no end. */
  endLine?: number;
  label: string;
  /** Rule `message`, metavariables already substituted. Unset if it equals `label`. */
  message?: string;
  /** Allow-listed `metadata:` keys. See `METADATA_KEYS`. */
  metadata?: Record<string, string>;
  /** Taint-mode path. Only `mode: taint` rules produce one. */
  taint?: TaintStep[];
}

/** repo-relative path → hits in that file. */
export type SemgrepHits = Map<string, SemgrepHit[]>;

export interface PreFilterOutcome {
  hits: SemgrepHits;
  /** Non-null when semgrep could not run; the caller records it. */
  degraded: SemgrepFailure | null;
}

export interface PreFilterDeps {
  /** Injected so the degraded path is testable without a real install. */
  ensure?: (env: NodeJS.ProcessEnv) => Promise<EnsureResult>;
  /**
   * The invocation itself, injected so result distribution is testable
   * without a binary. Resolves to raw stdout; rejects like `execFile` does.
   */
  run?: (bin: string, args: ReadonlyArray<string>) => Promise<string>;
  /**
   * Progress lines for `--verbose`. Separate from `onWarn` because these are
   * the positive signal that semgrep ran at all — nothing else in the scan
   * output distinguishes "semgrep found these anchors" from "the regexes did".
   */
  onInfo?: (message: string) => void;
}

/**
 * File extension → the value `semgrep-core -lang` expects.
 *
 * `semgrep-core` does not guess a file's language, so this table is the
 * only thing that decides which rules apply. A missing entry means the
 * file is skipped, not that it is scanned with the wrong parser.
 */
const LANG_BY_EXT: Readonly<Record<string, string>> = {
  ".ts": "ts",
  ".tsx": "ts",
  ".mts": "ts",
  ".cts": "ts",
  ".js": "js",
  ".jsx": "js",
  ".mjs": "js",
  ".cjs": "js",
  ".py": "python",
  ".rb": "ruby",
  ".go": "go",
  ".php": "php",
  ".java": "java",
  ".kt": "kotlin",
  ".cs": "csharp",
  ".rs": "rust",
  ".scala": "scala",
  ".swift": "swift",
  ".c": "c",
  ".h": "c",
  ".cc": "cpp",
  ".cpp": "cpp",
  ".hpp": "cpp",
  ".sh": "bash",
  ".lua": "lua",
  ".sol": "solidity",
  ".tf": "terraform",
  ".vue": "vue",
  ".ex": "elixir",
  ".dart": "dart",
  ".json": "json",
  ".yaml": "yaml",
  ".yml": "yaml",
  ".xml": "xml",
  ".html": "html",
};

/** The semgrep language for a path, or null when we do not scan it. */
export function semgrepLangFor(relPath: string): string | null {
  return LANG_BY_EXT[extname(relPath).toLowerCase()] ?? null;
}

/**
 * Resolve a `semgrepRule` name to a file, searching `rulesDirs` in order.
 * The caller puts the `--semgrep-rules` dirs first and the catalog's own
 * rules dir last, so a local rule shadows a catalog rule of the same name.
 * The name is schema-constrained to lowercase segments with no dots, so
 * it cannot traverse out and cannot name a registry pack. Returns null
 * when the file is absent; the caller warns rather than failing the scan.
 */
export function resolveSemgrepRule(rulesDirs: ReadonlyArray<string>, name: string): string | null {
  for (const rulesDir of rulesDirs) {
    // Both extensions: semgrep treats them interchangeably, and the installer
    // accepts both, so resolving only `.yml` would put a `.yaml` rule on disk
    // and then report it missing at scan time.
    for (const ext of [".yml", ".yaml"]) {
      const path = join(rulesDir, `${name}${ext}`);
      if (existsSync(path)) return path;
    }
  }
  return null;
}

/** Path to the rules dir inside a downloaded agent catalog. */
export function getSemgrepRulesDir(officialAgentsDir: string): string {
  return join(officialAgentsDir, "semgrep-rules");
}

/**
 * The `// nosemgrep` convention, which lives in semgrep's Python layer and
 * so is not applied by `semgrep-core`. A finding is suppressed when its
 * own line or the line above carries the marker.
 */
export function isSemgrepSuppressed(lines: ReadonlyArray<string>, line: number): boolean {
  const own = lines[line - 1] ?? "";
  const above = line >= 2 ? (lines[line - 2] ?? "") : "";
  return own.includes("nosemgrep") || above.includes("nosemgrep");
}

/**
 * Per-file engine trouble. `severity` is `warn` for a partial parse, where
 * the file was still scanned and only the unparsable span was skipped, and
 * `error` when the file was lost. Both name the file in `location`.
 */
interface CoreError {
  message?: string;
  severity?: string;
  location?: { path?: string; start?: RawLoc };
}

/** What one `-json` run reports: the matches, plus per-file trouble. */
interface CoreOutput {
  results?: RawResult[];
  errors?: CoreError[];
}

/** `semgrep-core` prints a progress dot before the JSON payload. */
function parseCoreJson(stdout: string): CoreOutput {
  const start = stdout.indexOf("{");
  if (start < 0) return {};
  return JSON.parse(stdout.slice(start));
}

interface RawLoc {
  line?: number;
}

/**
 * A taint endpoint is a two-element tuple, not an object:
 * `["CliLoc", [{ start, end, path }, "req.query"]]`. The second slot holds
 * the source text, which is why we do not re-read the line from the file.
 */
type RawTaintEndpoint = [string, [{ start?: RawLoc }, string]];

interface RawDataflowTrace {
  taint_source?: unknown;
  intermediate_vars?: Array<{ location?: { start?: RawLoc }; content?: string }>;
  taint_sink?: unknown;
}

interface RawResult {
  check_id?: string;
  /** Absolute path, echoed back from the target list. */
  path?: string;
  start?: RawLoc;
  end?: RawLoc;
  extra?: {
    message?: string;
    metadata?: Record<string, unknown>;
    dataflow_trace?: RawDataflowTrace;
  };
}

/**
 * The `metadata:` keys worth prompt space. A registry rule carries vendor
 * bookkeeping (`semgrep.dev`, `source-rule-url`, `technology`, licence ids)
 * that costs tokens and tells the model nothing about the code.
 */
const METADATA_KEYS: ReadonlyArray<string> = ["cwe", "owasp", "confidence", "likelihood", "impact"];

/** Collapse to one line and cap, so one anchor cannot flood the prompt. */
function oneLine(text: string, max = 200): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

/** Allow-listed metadata, flattened. Arrays join; anything else is dropped. */
function pickMetadata(meta: Record<string, unknown> | undefined): Record<string, string> | null {
  if (!meta) return null;
  const out: Record<string, string> = {};
  for (const key of METADATA_KEYS) {
    const value = meta[key];
    if (typeof value === "string") out[key] = oneLine(value, 80);
    else if (typeof value === "number" || typeof value === "boolean") out[key] = String(value);
    else if (Array.isArray(value)) {
      const parts = value.filter((v) => typeof v === "string") as string[];
      if (parts.length > 0) out[key] = oneLine(parts.join(", "), 80);
    }
  }
  return Object.keys(out).length > 0 ? out : null;
}

/** One end of a taint path, or null when the tuple is not the shape we expect. */
function taintEndpoint(raw: unknown, kind: TaintStep["kind"]): TaintStep | null {
  if (!Array.isArray(raw) || raw.length < 2) return null;
  const payload = (raw as RawTaintEndpoint)[1];
  if (!Array.isArray(payload) || payload.length < 2) return null;
  const line = payload[0]?.start?.line;
  const code = payload[1];
  if (typeof line !== "number" || typeof code !== "string") return null;
  return { kind, line, code: oneLine(code, 120) };
}

/** How many intermediate steps survive. Beyond this the path stops informing. */
const MAX_TAINT_STEPS = 6;

/**
 * Flatten `dataflow_trace` into source → through → sink. Returns null unless
 * both ends parsed: half a path is worse than none, because the model would
 * read the surviving end as the whole story.
 */
function taintSteps(trace: RawDataflowTrace | undefined): TaintStep[] | null {
  if (!trace) return null;
  const source = taintEndpoint(trace.taint_source, "source");
  const sink = taintEndpoint(trace.taint_sink, "sink");
  if (!source || !sink) return null;
  const kept: TaintStep[] = [];
  let dropped = 0;
  let firstDroppedLine = 0;
  for (const v of trace.intermediate_vars ?? []) {
    const line = v.location?.start?.line;
    if (typeof line !== "number" || typeof v.content !== "string") continue;
    const code = oneLine(v.content, 120);
    // The engine emits token fragments (a lone backtick, a brace) as steps.
    // They carry no dataflow meaning and read as noise beside real variables.
    if (code.length < 2 || !/\w/.test(code)) continue;
    const prev = kept[kept.length - 1];
    if (prev && prev.line === line && prev.code === code) continue;
    if (kept.length >= MAX_TAINT_STEPS) {
      if (dropped === 0) firstDroppedLine = line;
      dropped++;
      continue;
    }
    kept.push({ kind: "through", line, code });
  }
  // Say what was cut. A silently shortened path still reads as the whole
  // path, and the model would then trust a route it was never shown. The
  // marker carries the first dropped step's line, never the sink's: a real
  // but unrelated line is worse than no line at all.
  const middle =
    dropped > 0
      ? [
          ...kept,
          { kind: "elided" as const, line: firstDroppedLine, code: `${dropped} steps omitted` },
        ]
      : kept;
  return [source, ...middle, sink];
}

/**
 * One engine result → one anchor. Exported for tests: the interesting logic
 * is this mapping, and covering it needs no binary and no child process.
 */
export function toSemgrepHit(r: RawResult, line: number, entryLabel?: string): SemgrepHit {
  const message = r.extra?.message ? oneLine(r.extra.message) : undefined;
  const label = entryLabel ?? message ?? r.check_id ?? "semgrep";
  const hit: SemgrepHit = { line, endLine: r.end?.line, label };
  // Without a declared `label`, the label already IS the message. Printing
  // both would repeat the same sentence on two lines of every anchor.
  if (message && message !== label) hit.message = message;
  const metadata = pickMetadata(r.extra?.metadata);
  if (metadata) hit.metadata = metadata;
  const taint = taintSteps(r.extra?.dataflow_trace);
  if (taint) hit.taint = taint;
  return hit;
}

/**
 * What `execFile` rejects with. `code` is the errno string when the spawn
 * itself failed and the numeric exit status when the process ran and exited,
 * so the two cases are told apart by type, not by value.
 */
type ExecFailure = Omit<NodeJS.ErrnoException, "code"> & {
  code?: string | number;
  killed?: boolean;
  stdout?: string;
  stderr?: string;
};

/** One line naming why a `semgrep-core` call failed, for the warning text. */
function describeExecError(err: ExecFailure): string {
  // The loader's reason ("error while loading shared libraries: …") lands on
  // stderr and is the only thing that identifies a packaging fault, so it wins
  // over the exit status.
  const first = (err.stderr ?? "").split(/\r?\n/).find((l) => l.trim());
  if (first) return first.trim().slice(0, 200);
  if (err.code !== undefined) return `exit ${err.code}`;
  return (err.message ?? "unknown error").split(/\r?\n/)[0].slice(0, 200);
}

/**
 * Locate the analysis binary. `AGENTGG_SEMGREP_CORE` wins so a developer
 * can point at the copy inside a pip install; otherwise we take
 * `semgrep-core` from PATH (and, once packaged, the bundled build).
 */
export function resolveSemgrepCore(env: NodeJS.ProcessEnv = process.env): string {
  const override = env.AGENTGG_SEMGREP_CORE;
  if (override && existsSync(override)) return override;
  return "semgrep-core";
}

/**
 * Which arm of the resolution order won. Logged because "semgrep ran" and
 * "semgrep ran the version we pinned" are different claims — a `path` result
 * is neither version-pinned nor checksum-verified.
 */
export type SemgrepSource = "override" | "cache" | "path" | "fetched";

export type EnsureResult =
  | { ok: true; bin: string; source: SemgrepSource }
  | { ok: false; reason: SemgrepFailure };

export interface EnsureDeps {
  install?: (env: NodeJS.ProcessEnv) => Promise<InstallResult>;
}

/**
 * First match for `name` on PATH, or null. Node has no `which`, and shelling
 * out to one would cost a process on every scan.
 */
function findOnPath(name: string, env: NodeJS.ProcessEnv): string | null {
  const exts = process.platform === "win32" ? [".exe", ".cmd", ""] : [""];
  for (const entry of (env.PATH ?? "").split(delimiter)) {
    if (!entry) continue;
    for (const ext of exts) {
      const candidate = join(entry, `${name}${ext}`);
      if (existsSync(candidate)) return candidate;
    }
  }
  return null;
}

/**
 * Process-lifetime memo. One scan asks per agent, so without this a dead
 * network would be retried once per agent, and two agents starting together
 * would both download the same 60 MB wheel.
 */
let inflight: Promise<EnsureResult> | null = null;

/** Test-only: forget the memo so each case starts clean. */
export function resetSemgrepResolution(): void {
  inflight = null;
}

/**
 * Resolve the analysis binary, fetching it if this is the first scan that
 * needs it. Order: explicit override, versioned cache, PATH, download.
 * Never throws — a failure is a typed reason the caller records against the
 * agent so the report cannot imply coverage the scan did not have.
 */
export async function ensureSemgrepCore(
  env: NodeJS.ProcessEnv = process.env,
  deps: EnsureDeps = {},
): Promise<EnsureResult> {
  if (inflight) return inflight;
  inflight = (async (): Promise<EnsureResult> => {
    const override = env.AGENTGG_SEMGREP_CORE;
    if (override && existsSync(override)) return { ok: true, bin: override, source: "override" };

    const cached = getSemgrepCorePath(SEMGREP_VERSION, env);
    if (existsSync(cached)) return { ok: true, bin: cached, source: "cache" };

    // A copy the developer already installed. Neither version-pinned nor
    // checksum-verified, so it ranks below the cache and is only reached when
    // nothing has been fetched yet.
    const onPath = findOnPath("semgrep-core", env);
    if (onPath) {
      console.warn(`warning: using semgrep-core from PATH (${onPath}); version is not pinned`);
      return { ok: true, bin: onPath, source: "path" };
    }

    const install = deps.install ?? ((e: NodeJS.ProcessEnv) => installSemgrepCore(e));
    const result = await install(env);
    return result.ok
      ? { ok: true, bin: result.path, source: "fetched" }
      : { ok: false, reason: result.reason };
  })();
  return inflight;
}

/**
 * A `-targets` entry. `semgrep-core` only accepts `-lang` with ONE file, so
 * batching needs this file instead. `ppath` is the project-relative path the
 * engine echoes back in diagnostics; `fpath` is what it actually opens.
 */
type CodeTarget = [
  "CodeTarget",
  { products: ["sast"]; analyzer: string; path: { fpath: string; ppath: string } },
];

/** One agent's slice of the project run. */
export interface ProjectAgentInput {
  agent: Agent;
  /** repo-relative paths the walker already chose for this agent. */
  files: ReadonlyArray<string>;
}

export interface ProjectOutcome {
  /** agent slug → that agent's hits, already labelled and file-filtered. */
  byAgent: Map<string, SemgrepHits>;
  /** agent slug → why that agent's semgrep coverage is incomplete. */
  degradedByAgent: Map<string, SemgrepFailure>;
}

/** One agent's use of one rule file. The label is per entry, not per rule. */
interface RuleUsage {
  slug: string;
  rulePath: string;
  label?: string;
}

/** Per-rule-per-file ceiling inside the engine, so one file cannot stall the run. */
const RULE_TIMEOUT_SECONDS = 5;
/** Rules allowed to time out on one file before the engine drops that file. */
const TIMEOUT_THRESHOLD = 3;
/** Whole-run ceiling. One process now carries the entire scan. */
const RUN_TIMEOUT_MS = 600_000;
/** One payload now holds every file's results plus `paths.scanned`. */
const MAX_BUFFER = 256 * 1024 * 1024;
/** File-level messages printed in full before the rest are counted. */
const MAX_REPORTED_ERRORS = 5;

/** Compare two absolute paths the way the host filesystem does. */
function pathKey(absolute: string): string {
  const normalized = absolute.split(sep).join("/");
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

/**
 * Run every declared `semgrepRule` across the whole scan in ONE
 * `semgrep-core` process.
 *
 * This is what semgrep's own wrapper does: merge the rules, name the targets
 * in a `-targets` file, invoke once. It matters because the engine parses each
 * file a single time and matches every rule against that one parse tree, and
 * because its per-rule string pre-filter only pays off when rules share a
 * process. Running per (rule, file) threw both away and cost `rules x files`
 * spawns.
 *
 * agentgg still owns file selection: every target is named explicitly. A rule
 * carrying its own `paths:` narrows that set further, which the caller is told
 * about — coverage narrower than the file list is what `degraded` exists for.
 */
export async function runSemgrepProject(
  root: string,
  inputs: ReadonlyArray<ProjectAgentInput>,
  rulesDirs: ReadonlyArray<string>,
  concurrency: number,
  onWarn?: (message: string) => void,
  env: NodeJS.ProcessEnv = process.env,
  deps: PreFilterDeps = {},
): Promise<ProjectOutcome> {
  const byAgent = new Map<string, SemgrepHits>();
  const degradedByAgent = new Map<string, SemgrepFailure>();

  // ---- resolve and vet each distinct rule file once ----
  const usages: RuleUsage[] = [];
  const inspected = new Map<string, RuleInspection>();
  for (const { agent } of inputs) {
    for (const entry of agent.where.preFilter.filter(isSemgrepPreFilter)) {
      const rulePath = resolveSemgrepRule(rulesDirs, entry.semgrepRule);
      if (!rulePath) {
        onWarn?.(
          `${agent.slug}: semgrep rule '${entry.semgrepRule}' not found in ${rulesDirs.join(", ")}`,
        );
        continue;
      }
      if (!inspected.has(rulePath)) {
        let report: RuleInspection;
        try {
          report = inspectSemgrepRule(readFileSync(rulePath, "utf8"));
        } catch {
          report = { unsupported: null, langs: null, pathScoped: [], rules: null };
        }
        inspected.set(rulePath, report);
        if (report.unsupported) {
          onWarn?.(`semgrep rule '${entry.semgrepRule}' cannot run — ${report.unsupported}`);
        } else if (report.rules === null) {
          onWarn?.(`semgrep rule '${entry.semgrepRule}' did not parse; skipping it`);
        } else if (report.pathScoped.length > 0) {
          // Not an error. Said out loud because the engine honours `paths:`
          // and so scans fewer files than agentgg selected.
          onWarn?.(
            `semgrep rule '${entry.semgrepRule}': ${report.pathScoped.join(", ")} carry their own paths: filter, so they see fewer files than the agent's scope`,
          );
        }
      }
      const report = inspected.get(rulePath);
      if (!report) continue;
      if (report.unsupported) {
        degradedByAgent.set(agent.slug, "unsupported rule");
        continue;
      }
      if (report.rules === null) continue;
      usages.push({ slug: agent.slug, rulePath, label: entry.label });
    }
  }
  if (usages.length === 0) return { byAgent, degradedByAgent };

  // ---- merge every rule into one file, ids rewritten so `check_id` is unique ----
  // Two rule files may legitimately define the same id; without the rewrite a
  // result could not be attributed back to the file the agent named.
  const merged: Array<Record<string, unknown>> = [];
  const ruleOfCheckId = new Map<string, string>();
  const rulePaths = [...new Set(usages.map((u) => u.rulePath))];
  for (const [index, rulePath] of rulePaths.entries()) {
    const report = inspected.get(rulePath);
    for (const [n, rule] of (report?.rules ?? []).entries()) {
      const checkId = `agentgg-${index}-${n}-${typeof rule.id === "string" ? rule.id : "rule"}`;
      merged.push({ ...rule, id: checkId });
      ruleOfCheckId.set(checkId, rulePath);
    }
  }
  if (merged.length === 0) return { byAgent, degradedByAgent };

  // Languages the merged rules could match. A rule that declares none is
  // unknown, and one unknown rule opens the targets back up to every file —
  // a missed language costs time, never coverage.
  let ruleLangs: Set<string> | null = new Set<string>();
  for (const rulePath of rulePaths) {
    const langs = inspected.get(rulePath)?.langs;
    if (!langs) {
      ruleLangs = null;
      break;
    }
    for (const l of langs) ruleLangs.add(l);
  }

  // ---- targets: the union across agents that actually declare a rule ----
  const filesBySlug = new Map<string, ReadonlySet<string>>();
  const targets: CodeTarget[] = [];
  const relOfAbs = new Map<string, string>();
  const slugsWithRules = new Set(usages.map((u) => u.slug));
  for (const { agent, files } of inputs) {
    if (!slugsWithRules.has(agent.slug)) continue;
    filesBySlug.set(agent.slug, new Set(files));
    for (const relPath of files) {
      const analyzer = semgrepLangFor(relPath);
      if (!analyzer) continue;
      if (ruleLangs && !ruleLangs.has(analyzer)) continue;
      const fpath = resolve(root, relPath);
      const key = pathKey(fpath);
      if (relOfAbs.has(key)) continue;
      relOfAbs.set(key, relPath);
      targets.push([
        "CodeTarget",
        { products: ["sast"], analyzer, path: { fpath, ppath: `/${relPath}` } },
      ]);
    }
  }
  // Resolve the binary only once there is real work, so a scan whose rules
  // match no file's language never triggers a 60 MB download.
  if (targets.length === 0) return { byAgent, degradedByAgent };

  const ensure = deps.ensure ?? ((e: NodeJS.ProcessEnv) => ensureSemgrepCore(e));
  const resolved = await ensure(env);
  if (!resolved.ok) {
    onWarn?.(`semgrep unavailable (${resolved.reason}) — regex preFilters only`);
    for (const slug of slugsWithRules) degradedByAgent.set(slug, resolved.reason);
    return { byAgent, degradedByAgent };
  }
  deps.onInfo?.(`semgrep-core: ${resolved.bin} (${resolved.source})`);
  // Printed before the run, so `--verbose` shows the planned work even when
  // the invocation then fails. The result line below reports what came back.
  deps.onInfo?.(`semgrep: ${merged.length} rule(s) over ${targets.length} file(s)`);

  // ---- one invocation ----
  const work = mkdtempSync(join(tmpdir(), "agentgg-semgrep-"));
  let stdout: string;
  try {
    const rulesFile = join(work, "rules.json");
    const targetsFile = join(work, "targets.json");
    writeFileSync(rulesFile, JSON.stringify({ rules: merged }));
    writeFileSync(targetsFile, JSON.stringify(["Targets", targets]));
    const args = [
      "-rules",
      rulesFile,
      "-targets",
      targetsFile,
      "-json",
      "-j",
      String(Math.max(1, concurrency)),
      "-timeout",
      String(RULE_TIMEOUT_SECONDS),
      "-timeout_threshold",
      String(TIMEOUT_THRESHOLD),
    ];
    const run =
      deps.run ??
      (async (bin: string, a: ReadonlyArray<string>) =>
        (await execFileAsync(bin, [...a], { maxBuffer: MAX_BUFFER, timeout: RUN_TIMEOUT_MS }))
          .stdout);
    try {
      stdout = await run(resolved.bin, args);
    } catch (err) {
      const e = err as ExecFailure;
      // A run that printed no JSON never started. One that timed out did
      // start, so the two are told apart and recorded differently. Either
      // way this warns: a silent zero here reads as "semgrep found nothing".
      if (e.killed || e.code === "ETIMEDOUT") {
        onWarn?.(`semgrep-core timed out after ${RUN_TIMEOUT_MS / 1000}s`);
        for (const slug of slugsWithRules) degradedByAgent.set(slug, "run timed out");
        return { byAgent, degradedByAgent };
      }
      onWarn?.(`semgrep-core would not start (${resolved.bin}): ${describeExecError(e)}`);
      for (const slug of slugsWithRules) degradedByAgent.set(slug, "binary failed to start");
      return { byAgent, degradedByAgent };
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
  }

  // ---- distribute results back to the agents that asked for each rule ----
  let parsed: CoreOutput;
  try {
    parsed = parseCoreJson(stdout);
  } catch {
    onWarn?.("semgrep-core returned output this build could not parse");
    for (const slug of slugsWithRules) degradedByAgent.set(slug, "binary failed to start");
    return { byAgent, degradedByAgent };
  }
  // Per-file engine trouble. One file is affected, not the run, which is why
  // this warns rather than degrading the agent. Capped because a repo with a
  // vendored bundle can produce one of these per file, and a wall of them
  // buries the warnings that matter.
  const errors = parsed.errors ?? [];
  for (const e of errors.slice(0, MAX_REPORTED_ERRORS)) {
    const where = relOfAbs.get(pathKey(e.location?.path ?? ""));
    const at = where ? `${where}:${e.location?.start?.line ?? "?"}: ` : "";
    const severity = e.severity === "warn" ? "partial parse" : "error";
    onWarn?.(`semgrep-core ${at}${oneLine(e.message ?? "unknown error")} (${severity})`);
  }
  if (errors.length > MAX_REPORTED_ERRORS) {
    onWarn?.(`semgrep-core: ${errors.length - MAX_REPORTED_ERRORS} more file-level message(s)`);
  }

  // rule file → its results, keyed by repo-relative path. Built once; each
  // usage then takes a labelled copy of the slice its agent's scope covers.
  const byRule = new Map<string, Map<string, RawResult[]>>();
  for (const r of parsed.results ?? []) {
    const rulePath = r.check_id ? ruleOfCheckId.get(r.check_id) : undefined;
    const relPath = relOfAbs.get(pathKey(r.path ?? ""));
    if (!rulePath || !relPath || typeof r.start?.line !== "number") continue;
    const perFile = byRule.get(rulePath) ?? new Map<string, RawResult[]>();
    const bucket = perFile.get(relPath) ?? [];
    bucket.push(r);
    perFile.set(relPath, bucket);
    byRule.set(rulePath, perFile);
  }

  for (const usage of usages) {
    const perFile = byRule.get(usage.rulePath);
    if (!perFile) continue;
    const scope = filesBySlug.get(usage.slug);
    const hits = byAgent.get(usage.slug) ?? new Map<string, SemgrepHit[]>();
    for (const [relPath, results] of perFile) {
      if (scope && !scope.has(relPath)) continue;
      const bucket = hits.get(relPath) ?? [];
      for (const r of results) {
        const line = r.start?.line;
        if (typeof line !== "number") continue;
        bucket.push(toSemgrepHit(r, line, usage.label));
      }
      if (bucket.length > 0) hits.set(relPath, bucket);
    }
    if (hits.size > 0) byAgent.set(usage.slug, hits);
  }

  let anchors = 0;
  for (const hits of byAgent.values()) {
    for (const bucket of hits.values()) anchors += bucket.length;
  }
  deps.onInfo?.(`semgrep produced ${anchors} anchor(s) for ${byAgent.size} agent(s)`);

  return { byAgent, degradedByAgent };
}

/**
 * Single-agent view of `runSemgrepProject`, for a caller that holds one
 * agent. A scan should use the project run instead: it shares one parse of
 * each file across every agent, which this cannot.
 */
export async function runSemgrepPreFilter(
  root: string,
  agent: Agent,
  files: ReadonlyArray<string>,
  rulesDirs: ReadonlyArray<string>,
  concurrency: number,
  onWarn?: (message: string) => void,
  env: NodeJS.ProcessEnv = process.env,
  deps: PreFilterDeps = {},
): Promise<PreFilterOutcome> {
  const out = await runSemgrepProject(
    root,
    [{ agent, files }],
    rulesDirs,
    concurrency,
    onWarn ? (m) => onWarn(m.startsWith(`${agent.slug}:`) ? m : `${agent.slug}: ${m}`) : undefined,
    env,
    deps,
  );
  return {
    hits: out.byAgent.get(agent.slug) ?? new Map(),
    degraded: out.degradedByAgent.get(agent.slug) ?? null,
  };
}
