import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import matter from "gray-matter";

/**
 * Built-in `create` agent instructions. Loaded once per process. Mirrors
 * `recon-agent.ts`: the prompt body lives in an editable markdown file
 * (`src/agents/create.md`, copied to `dist/agents/create.md` at bundle
 * time by `scripts/bundle-cli.mjs`) rather than hardcoded here, so it can
 * be iterated on without a code change.
 */
let cached: string | null = null;

export function loadCreateInstructions(): string {
  if (cached !== null) return cached;
  const url = new URL("./agents/create.md", import.meta.url);
  const raw = readFileSync(fileURLToPath(url), "utf8");
  cached = matter(raw).content.trim();
  return cached;
}
