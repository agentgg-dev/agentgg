import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/**
 * The bundled default security scope. Commands that accept `--scope`
 * (scan, revalidate) fall back to this whenever the flag is omitted, so
 * the validator always has the trust-boundary rules it needs to reason
 * about `out-of-scope`. An explicit `--scope <path>` overrides it;
 * `--no-scope` opts out entirely.
 *
 * The doc lives at `src/scope/default-scope.md`, copied to `dist/scope/`
 * at bundle time (same mechanism as the built-in agent files) and
 * resolved relative to this module via `import.meta.url`: in dev (tsx)
 * that points at `src/scope/`; in the esbuild bundle it points at
 * `dist/scope/`.
 */
let cached: string | null = null;

export function loadDefaultScope(): string {
  if (cached !== null) return cached;
  const url = new URL("./scope/default-scope.md", import.meta.url);
  cached = readFileSync(fileURLToPath(url), "utf8");
  return cached;
}
