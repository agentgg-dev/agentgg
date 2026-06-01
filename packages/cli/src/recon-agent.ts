import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import matter from "gray-matter";

/**
 * The built-in recon agent. Its instructions live in an editable agent
 * file (`src/agents/recon.md`, copied to `dist/agents/recon.md` at
 * bundle time) rather than hardcoded in the engine — recon is a real
 * agent with a set of instructions, run like any other and producing a
 * structured file output (`state/recon.json`).
 *
 * Resolved relative to this module via `import.meta.url`: in dev (tsx)
 * that points at `src/agents/`; in the esbuild bundle it points at
 * `dist/`, where the bundle step has placed `agents/recon.md`.
 */
let cached: string | null = null;

export function loadReconInstructions(): string {
  if (cached !== null) return cached;
  const url = new URL("./agents/recon.md", import.meta.url);
  const raw = readFileSync(fileURLToPath(url), "utf8");
  // The body is the agent's instructions; frontmatter (name/description)
  // is metadata only.
  cached = matter(raw).content.trim();
  return cached;
}
