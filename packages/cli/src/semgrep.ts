import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { delimiter, extname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { type Agent, getSemgrepCorePath, isSemgrepPreFilter } from "@agentgg/core";
import { runConcurrent } from "./concurrent.js";
import type { TaintStep } from "./pre-filter.js";
import {
  type InstallResult,
  installSemgrepCore,
  SEMGREP_VERSION,
  type SemgrepFailure,
} from "./semgrep-install.js";

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

/** Rule-file spellings that mean the same language as a `-lang` value. */
const LANG_ALIASES: Readonly<Record<string, string>> = {
  typescript: "ts",
  javascript: "js",
  py: "python",
  python2: "python",
  python3: "python",
  rb: "ruby",
  golang: "go",
  kt: "kotlin",
  "c#": "csharp",
  "c++": "cpp",
  sh: "bash",
  sol: "solidity",
  tf: "terraform",
  ex: "elixir",
};

function normalizeLang(name: string): string {
  const lower = name
    .trim()
    .replace(/^["']|["']$/g, "")
    .toLowerCase();
  return LANG_ALIASES[lower] ?? lower;
}

/**
 * The set of languages a rule file declares, so we only spawn the binary
 * for files it could match. Without this, a TypeScript-only rule still
 * costs one process per Python file an agent's `where` happens to include.
 *
 * Deliberately a text scan, not a YAML parse: the cli has no YAML parser
 * and this needs no dependency to be useful. Returning null means "could
 * not tell", and the caller then runs the rule against everything — the
 * pre-existing behaviour, so a parse miss costs time and never coverage.
 */
export function semgrepRuleLanguages(source: string): Set<string> | null {
  const langs = new Set<string>();
  // Flow style: `languages: [ts, javascript]`
  for (const m of source.matchAll(/^\s*languages:\s*\[([^\]]*)\]/gm)) {
    for (const part of m[1].split(",")) {
      if (part.trim()) langs.add(normalizeLang(part));
    }
  }
  // Block style: `languages:` followed by `- ts` lines.
  for (const m of source.matchAll(
    /^([ \t]*)languages:[ \t]*(?:#.*)?\r?\n((?:\1[ \t]+-[ \t]*\S+\r?\n?)+)/gm,
  )) {
    for (const line of m[2].split(/\r?\n/)) {
      const item = line.replace(/^[ \t]*-[ \t]*/, "").trim();
      if (item) langs.add(normalizeLang(item));
    }
  }
  return langs.size > 0 ? langs : null;
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

/** `semgrep-core` prints a progress dot before the JSON payload. */
function parseCoreJson(stdout: string): { results?: RawResult[] } {
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
 * Run every `semgrepRule` an agent declares over the file set the walker
 * already chose, one `semgrep-core` process per (rule file, source file).
 *
 * agentgg owns file selection: `semgrep-core` scans exactly the file it is
 * given and applies no ignore rules of its own, so the hits key to the
 * same list the agent will review. Failures degrade to "no hits from that
 * rule" instead of aborting the scan, matching how a bad preFilter regex
 * is treated.
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
  const hits: SemgrepHits = new Map();
  const entries = agent.where.preFilter.filter(isSemgrepPreFilter);
  if (entries.length === 0 || files.length === 0) return { hits, degraded: null };

  const rules: Array<{ path: string; label?: string; langs: Set<string> | null }> = [];
  for (const entry of entries) {
    const path = resolveSemgrepRule(rulesDirs, entry.semgrepRule);
    if (!path) {
      onWarn?.(
        `${agent.slug}: semgrep rule '${entry.semgrepRule}' not found in ${rulesDirs.join(", ")}`,
      );
      continue;
    }
    let langs: Set<string> | null = null;
    try {
      langs = semgrepRuleLanguages(readFileSync(path, "utf8"));
    } catch {
      // Unreadable rule file — treat as "languages unknown" and let the
      // binary decide, same as an unparseable `languages:` block.
    }
    rules.push({ path, label: entry.label, langs });
  }
  if (rules.length === 0) return { hits, degraded: null };

  const jobs: Array<{ rule: (typeof rules)[number]; relPath: string; lang: string }> = [];
  for (const relPath of files) {
    const lang = semgrepLangFor(relPath);
    if (!lang) continue;
    for (const rule of rules) {
      if (rule.langs && !rule.langs.has(lang)) continue;
      jobs.push({ rule, relPath, lang });
    }
  }

  // Resolve the binary only once there is real work, so an agent whose rules
  // match no file's language never triggers a 60 MB download.
  if (jobs.length === 0) return { hits, degraded: null };

  const ensure = deps.ensure ?? ((e: NodeJS.ProcessEnv) => ensureSemgrepCore(e));
  const resolved = await ensure(env);
  if (!resolved.ok) {
    onWarn?.(`${agent.slug}: semgrep unavailable (${resolved.reason}) — regex preFilters only`);
    return { hits, degraded: resolved.reason };
  }
  const bin = resolved.bin;
  deps.onInfo?.(`semgrep-core: ${bin} (${resolved.source})`);

  let startFailure: SemgrepFailure | null = null;
  await runConcurrent(jobs, Math.max(1, concurrency), async (job) => {
    if (startFailure) return;
    let stdout: string;
    try {
      const out = await execFileAsync(
        bin,
        ["-rules", job.rule.path, "-lang", job.lang, "-json", resolve(root, job.relPath)],
        { maxBuffer: 32 * 1024 * 1024, timeout: 60_000 },
      );
      stdout = out.stdout;
    } catch (err) {
      const e = err as ExecFailure;
      // A binary that will not start (missing, not executable, wrong glibc, or
      // unable to load its shared libraries) fails the same way for every job
      // and prints no JSON. Record it once and stop the rest. Anything that did
      // print JSON started fine, so only that one file is skipped. Either way
      // this warns: a silent zero here reads as "semgrep found nothing".
      if (e.killed || e.code === "ETIMEDOUT") {
        onWarn?.(`${agent.slug}: semgrep-core timed out on ${job.relPath}`);
        return;
      }
      if (!e.stdout?.includes("{")) {
        startFailure = "binary failed to start";
        onWarn?.(`${agent.slug}: semgrep-core would not start (${bin}): ${describeExecError(e)}`);
      } else {
        onWarn?.(`${agent.slug}: semgrep-core failed on ${job.relPath}: ${describeExecError(e)}`);
      }
      return;
    }
    let results: RawResult[];
    try {
      results = parseCoreJson(stdout).results ?? [];
    } catch {
      return;
    }
    if (results.length === 0) return;
    const bucket = hits.get(job.relPath) ?? [];
    for (const r of results) {
      const line = r.start?.line;
      if (typeof line !== "number") continue;
      bucket.push(toSemgrepHit(r, line, job.rule.label));
    }
    if (bucket.length > 0) hits.set(job.relPath, bucket);
  });

  let anchors = 0;
  for (const bucket of hits.values()) anchors += bucket.length;
  deps.onInfo?.(
    `${agent.slug}: semgrep ran ${rules.length} rule(s) over ${jobs.length} file-job(s) → ${anchors} anchor(s) in ${hits.size} file(s)`,
  );

  return { hits, degraded: startFailure };
}
