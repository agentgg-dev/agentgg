import { readdirSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import type { Agent } from "@agentgg/core";
import { minimatch } from "minimatch";

/**
 * Shared default exclude set. NOT hardcoded walker policy — it's data the
 * caller opts into and merges with CLI `--exclude` and the agent's
 * `where.excludePatterns`. An agent can drop it by setting
 * `where.useDefaultExcludes: false`. All entries are minimatch globs:
 * directory-name globs prune the walk; file globs skip individual files.
 *
 * The walker itself enforces nothing beyond the `excludePatterns` it's
 * handed — file scope is owned by the agent template's `where`.
 */
export const DEFAULT_EXCLUDES: string[] = [
  // Dependency / build / VCS / tooling directories (pruned during descent).
  "**/node_modules",
  "**/.git",
  "**/.hg",
  "**/.svn",
  "**/dist",
  "**/build",
  "**/out",
  "**/coverage",
  "**/.next",
  "**/.nuxt",
  "**/.cache",
  "**/.turbo",
  "**/.vercel",
  "**/__pycache__",
  "**/.venv",
  "**/venv",
  "**/target",
  "**/vendor",
  "**/.idea",
  "**/.vscode",
  "**/.DS_Store",
  "**/scan-results",
  // Lockfiles — rarely useful to scan, often massive.
  "**/package-lock.json",
  "**/pnpm-lock.yaml",
  "**/yarn.lock",
  "**/Cargo.lock",
  "**/Gemfile.lock",
  "**/poetry.lock",
  "**/Pipfile.lock",
  "**/composer.lock",
  "**/go.sum",
  // Binary / minified / asset files — an LLM can't use these.
  "**/*.min.js",
  "**/*.min.css",
  "**/*.map",
  "**/*.png",
  "**/*.jpg",
  "**/*.jpeg",
  "**/*.gif",
  "**/*.svg",
  "**/*.ico",
  "**/*.webp",
  "**/*.bmp",
  "**/*.woff",
  "**/*.woff2",
  "**/*.ttf",
  "**/*.otf",
  "**/*.eot",
  "**/*.pdf",
  "**/*.zip",
  "**/*.gz",
  "**/*.tar",
  "**/*.7z",
  "**/*.rar",
  "**/*.mp3",
  "**/*.mp4",
  "**/*.webm",
  "**/*.mov",
  "**/*.avi",
  "**/*.wav",
  "**/*.ogg",
  "**/*.exe",
  "**/*.dll",
  "**/*.so",
  "**/*.dylib",
  "**/*.class",
  "**/*.jar",
  "**/*.wasm",
];

export interface WalkConfig {
  /**
   * Globs to exclude. The CALLER decides what goes here — typically
   * `DEFAULT_EXCLUDES` (unless opted out) plus CLI `--exclude` plus the
   * agent's `where.excludePatterns`. The walker applies exactly this list
   * and nothing else. Directory-matching globs prune the descent.
   */
  excludePatterns?: string[];
  /** Restrict scan to files matching at least one of these globs (if non-empty). */
  includePatterns?: string[];
  /** Files larger than this in bytes are skipped. Default 500KB. */
  maxFileSizeBytes?: number;
}

const DEFAULT_MAX_FILE_SIZE = 500 * 1024;

export interface AgentWorkItem {
  agent: Agent;
  files: string[]; // POSIX-style relative paths from root
}

/**
 * Walk `root` applying `cfg`, then route each surviving file to the
 * agents whose `where.filePatterns` match it (and drop any the agent's
 * `where.excludePatterns` rejects). Paths are POSIX-style relative to
 * `root`. The walker carries no opinions of its own beyond `cfg`.
 */
export function walkForAgents(
  root: string,
  agents: ReadonlyArray<Agent>,
  cfg: WalkConfig = {},
): AgentWorkItem[] {
  const absRoot = resolve(root);
  const allFiles = collectFiles(absRoot, absRoot, cfg);

  return agents.map((agent) => ({
    agent,
    files: allFiles
      .filter((f) => includedByWhere(f, agent.where.extensions, agent.where.filePatterns))
      .filter((f) => !agent.where.excludePatterns.some((p) => pathMatches(f, p))),
  }));
}

/**
 * Lower-level helper: collect every file under `root` that survives the
 * walker's filter pipeline. Callers that want their own per-file routing
 * use this directly (precondition census, recon scope).
 */
export function collectAllFiles(root: string, cfg: WalkConfig = {}): string[] {
  const absRoot = resolve(root);
  return collectFiles(absRoot, absRoot, cfg);
}

function collectFiles(root: string, dir: string, cfg: WalkConfig): string[] {
  const excludePatterns = cfg.excludePatterns ?? [];
  const includePatterns = cfg.includePatterns ?? [];
  const maxSize = cfg.maxFileSizeBytes ?? DEFAULT_MAX_FILE_SIZE;
  const out: string[] = [];

  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }

  for (const name of entries) {
    const abs = join(dir, name);
    let stat: ReturnType<typeof statSync>;
    try {
      stat = statSync(abs);
    } catch {
      continue;
    }
    const rel = toPosix(relative(root, abs));

    if (stat.isDirectory()) {
      // Prune excluded directories so we never descend into (and pay for
      // statting) node_modules, .git, etc.
      if (isExcludedDir(rel, excludePatterns)) continue;
      out.push(...collectFiles(root, abs, cfg));
      continue;
    }
    if (!stat.isFile()) continue;

    if (excludePatterns.some((p) => minimatch(rel, p, { dot: true }))) continue;
    if (stat.size > maxSize) continue;
    if (
      includePatterns.length > 0 &&
      !includePatterns.some((p) => minimatch(rel, p, { dot: true }))
    ) {
      continue;
    }

    out.push(rel);
  }
  return out;
}

/**
 * A directory is pruned when its relative path matches an exclude glob.
 * Patterns are tested both directly and with a trailing `/**` (or `/*`)
 * stripped, so both `**​/vendor` and `vendor/**` prune the `vendor` dir.
 */
function isExcludedDir(relDir: string, patterns: string[]): boolean {
  return patterns.some((p) => {
    if (minimatch(relDir, p, { dot: true })) return true;
    const base = p.replace(/\/\*\*?$/, "").replace(/\/+$/, "");
    return base !== p && minimatch(relDir, base, { dot: true });
  });
}

function toPosix(p: string): string {
  return sep === "\\" ? p.split(sep).join("/") : p;
}

/**
 * Does one file path match one `where` pattern? A pattern can be:
 *   - a glob          ("**​/*.ts", "api/**")  → standard minimatch
 *   - a directory     ("api/routes")          → matches EVERY file under it
 *   - an exact file   ("src/index.ts")        → matches just that file
 *
 * So you can point `where` at a folder and the agent runs on everything in
 * it — no need to remember to append `/**`.
 */
export function pathMatches(filePath: string, pattern: string): boolean {
  if (minimatch(filePath, pattern, { dot: true })) return true;
  // No glob metacharacters → treat it as a plain path: either an exact file,
  // or a directory whose contents we want (everything under it).
  if (!/[*?[\]{}]/.test(pattern)) {
    const base = pattern.replace(/\/+$/, "");
    return filePath === base || filePath.startsWith(`${base}/`);
  }
  return false;
}

/**
 * True when a file's name ends with one of the given extensions. Accepts
 * "ts" or ".ts" (leading dot optional), case-insensitive. Empty list →
 * matches nothing (the include decision falls to `filePatterns`).
 */
export function matchesExtension(filePath: string, extensions: string[]): boolean {
  if (extensions.length === 0) return false;
  const lower = filePath.toLowerCase();
  return extensions.some((e) => {
    const ext = e.startsWith(".") ? e.toLowerCase() : `.${e.toLowerCase()}`;
    return lower.endsWith(ext);
  });
}

/**
 * Which files a `where` includes (before exclusion). A file is included when:
 *   - BOTH `extensions` and `filePatterns` are empty → every file (the agent
 *     roams the whole repo), OR
 *   - its extension is one of `extensions` (the simple, nuclei-style knob), OR
 *   - it matches one of `filePatterns` (glob / directory / file — the complex
 *     escape hatch).
 * `excludePatterns` is applied separately by the caller.
 */
export function includedByWhere(
  filePath: string,
  extensions: string[],
  filePatterns: string[],
): boolean {
  if (extensions.length === 0 && filePatterns.length === 0) return true;
  if (matchesExtension(filePath, extensions)) return true;
  if (filePatterns.length > 0 && filePatterns.some((p) => pathMatches(filePath, p))) return true;
  return false;
}

