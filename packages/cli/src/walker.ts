import { readdirSync, statSync } from "node:fs";
import { extname, join, relative, resolve, sep } from "node:path";
import { minimatch } from "minimatch";
import type { Agent } from "@agentgg/core";

/**
 * Directories and filenames the walker never enters. Conservative list:
 * dependency caches, build outputs, VCS metadata, lockfiles, IDE/OS junk.
 */
const DEFAULT_IGNORES = new Set([
  "node_modules",
  ".git",
  ".hg",
  ".svn",
  "dist",
  "build",
  "out",
  "coverage",
  ".next",
  ".nuxt",
  ".cache",
  ".turbo",
  ".vercel",
  "__pycache__",
  ".venv",
  "venv",
  "target",
  "vendor",
  ".idea",
  ".vscode",
  ".DS_Store",
  "scan-results",
  // lockfiles — rarely useful for scanning, often massive
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "Cargo.lock",
  "Gemfile.lock",
  "poetry.lock",
  "Pipfile.lock",
  "composer.lock",
  "go.sum",
]);

/**
 * Extensions for binary / minified / asset files we never want to send
 * to an LLM. Cheap suffix check before any read.
 */
const SKIP_EXTENSIONS = new Set([
  ".min.js",
  ".min.css",
  ".map",
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".svg",
  ".ico",
  ".webp",
  ".bmp",
  ".woff",
  ".woff2",
  ".ttf",
  ".otf",
  ".eot",
  ".pdf",
  ".zip",
  ".gz",
  ".tar",
  ".7z",
  ".rar",
  ".mp3",
  ".mp4",
  ".webm",
  ".mov",
  ".avi",
  ".wav",
  ".ogg",
  ".exe",
  ".dll",
  ".so",
  ".dylib",
  ".class",
  ".jar",
  ".wasm",
]);

/** Convenience set of test/fixture globs applied when `--exclude-tests` is on. */
export const TEST_EXCLUDE_PATTERNS = [
  "**/*.test.*",
  "**/*.spec.*",
  "**/__tests__/**",
  "**/__mocks__/**",
  "**/test/**",
  "**/tests/**",
  "**/spec/**",
  "**/e2e/**",
  "**/fixtures/**",
  "**/__fixtures__/**",
];

export interface WalkConfig {
  /** Globs to exclude after the default-ignore pass. Repeatable via CLI. */
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
 * Walk `root`, apply default ignores + user config, then route each
 * surviving file to the file-mode agents whose `filePatterns` match it.
 * Hunt-mode agents are not represented here — they discover their own
 * files at runtime via tools.
 *
 * Paths in the result are POSIX-style relative to `root`.
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
    files: allFiles.filter((f) => matchesAnyPattern(f, agent.filePatterns)),
  }));
}

/**
 * Lower-level helper: collect every file under `root` that survives the
 * walker's filter pipeline. Useful for callers that want their own
 * per-file routing.
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
    if (DEFAULT_IGNORES.has(name)) continue;
    const abs = join(dir, name);
    let stat: ReturnType<typeof statSync>;
    try {
      stat = statSync(abs);
    } catch {
      continue;
    }

    if (stat.isDirectory()) {
      out.push(...collectFiles(root, abs, cfg));
      continue;
    }
    if (!stat.isFile()) continue;

    // Skip by extension before doing anything more expensive.
    if (hasSkipExtension(name)) continue;
    // Skip oversized files.
    if (stat.size > maxSize) continue;

    const rel = toPosix(relative(root, abs));

    // User-supplied excludes apply on top of defaults.
    if (excludePatterns.some((p) => minimatch(rel, p, { dot: false }))) continue;

    // `--only` mode: skip anything that doesn't match at least one include.
    if (
      includePatterns.length > 0 &&
      !includePatterns.some((p) => minimatch(rel, p, { dot: false }))
    ) {
      continue;
    }

    out.push(rel);
  }
  return out;
}

function hasSkipExtension(name: string): boolean {
  const lower = name.toLowerCase();
  // Two-segment endings like ".min.js" first.
  for (const ext of SKIP_EXTENSIONS) {
    if (lower.endsWith(ext)) return true;
  }
  // Fall back to simple extname (already covered above, but kept for clarity).
  return SKIP_EXTENSIONS.has(extname(lower));
}

function toPosix(p: string): string {
  return sep === "\\" ? p.split(sep).join("/") : p;
}

/**
 * Empty filePatterns = "all files" (agent runs against everything that
 * survives the walker). Otherwise the file matches if ANY pattern
 * matches. Standard minimatch dialect, globstar on, dotfiles off.
 */
export function matchesAnyPattern(filePath: string, patterns: string[]): boolean {
  if (patterns.length === 0) return true;
  return patterns.some((p) => minimatch(filePath, p, { dot: false }));
}
