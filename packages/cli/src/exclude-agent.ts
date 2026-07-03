import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import matter from "gray-matter";

/**
 * The built-in smart-exclude agent. Its instructions live in an editable
 * agent file (`src/agents/exclude.md`, copied to `dist/agents/exclude.md`
 * at bundle time) rather than hardcoded in the engine, exactly like the
 * recon agent. It runs once, before recon, and produces a list of folder
 * globs that are applied like CLI `--exclude` paths.
 *
 * Resolved relative to this module via `import.meta.url`: in dev (tsx)
 * that points at `src/agents/`; in the esbuild bundle it points at
 * `dist/`, where the bundle step has placed `agents/exclude.md`.
 */
let cached: string | null = null;

export function loadExcludeInstructions(): string {
  if (cached !== null) return cached;
  const url = new URL("./agents/exclude.md", import.meta.url);
  const raw = readFileSync(fileURLToPath(url), "utf8");
  // The body is the agent's instructions; frontmatter (name/description)
  // is metadata only.
  cached = matter(raw).content.trim();
  return cached;
}
