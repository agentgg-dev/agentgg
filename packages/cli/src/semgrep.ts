import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { type Agent, isSemgrepPreFilter } from "@agentgg/core";
import { runConcurrent } from "./concurrent.js";

const execFileAsync = promisify(execFile);

/**
 * One line a `semgrepRule` preFilter matched. No snippet: the caller has
 * the file content already and fills it in, which also keeps the
 * suppression check (see `isSemgrepSuppressed`) on the caller's side.
 */
export interface SemgrepHit {
  line: number;
  label: string;
}

/** repo-relative path → hits in that file. */
export type SemgrepHits = Map<string, SemgrepHit[]>;

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
 * Resolve a `semgrepRule` name to a file under the catalog's rules dir.
 * The name is schema-constrained to lowercase segments with no dots, so
 * it cannot traverse out and cannot name a registry pack. Returns null
 * when the file is absent; the caller warns rather than failing the scan.
 */
export function resolveSemgrepRule(rulesDir: string, name: string): string | null {
  const path = join(rulesDir, `${name}.yml`);
  return existsSync(path) ? path : null;
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

interface RawResult {
  check_id?: string;
  start?: { line?: number };
  extra?: { message?: string };
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
  rulesDir: string,
  concurrency: number,
  onWarn?: (message: string) => void,
  env: NodeJS.ProcessEnv = process.env,
): Promise<SemgrepHits> {
  const hits: SemgrepHits = new Map();
  const entries = agent.where.preFilter.filter(isSemgrepPreFilter);
  if (entries.length === 0 || files.length === 0) return hits;

  const rules: Array<{ path: string; label?: string; langs: Set<string> | null }> = [];
  for (const entry of entries) {
    const path = resolveSemgrepRule(rulesDir, entry.semgrepRule);
    if (!path) {
      onWarn?.(`${agent.slug}: semgrep rule '${entry.semgrepRule}' not found in ${rulesDir}`);
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
  if (rules.length === 0) return hits;

  const jobs: Array<{ rule: (typeof rules)[number]; relPath: string; lang: string }> = [];
  for (const relPath of files) {
    const lang = semgrepLangFor(relPath);
    if (!lang) continue;
    for (const rule of rules) {
      if (rule.langs && !rule.langs.has(lang)) continue;
      jobs.push({ rule, relPath, lang });
    }
  }

  const bin = resolveSemgrepCore(env);
  let spawnFailed = false;
  await runConcurrent(jobs, Math.max(1, concurrency), async (job) => {
    if (spawnFailed) return;
    let stdout: string;
    try {
      const out = await execFileAsync(
        bin,
        ["-rules", job.rule.path, "-lang", job.lang, "-json", resolve(root, job.relPath)],
        { maxBuffer: 32 * 1024 * 1024, timeout: 60_000 },
      );
      stdout = out.stdout;
    } catch (err) {
      // ENOENT means the binary is missing — warn once, not per file.
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        spawnFailed = true;
        onWarn?.(`semgrep-core not found ('${bin}') — semgrepRule preFilters were skipped`);
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
      bucket.push({ line, label: job.rule.label ?? r.extra?.message ?? r.check_id ?? "semgrep" });
    }
    if (bucket.length > 0) hits.set(job.relPath, bucket);
  });

  return hits;
}
