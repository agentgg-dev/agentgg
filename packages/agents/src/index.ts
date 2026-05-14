import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { type Agent, loadAgentsFromDir } from "@agentgg/core";

/**
 * Path to the bundled agent definitions. Resolves the same way at
 * runtime whether we're running from `dist/index.js` (compiled) or
 * `src/index.ts` (tsx dev mode) — both sit one level deep relative to
 * the package's `agents/` directory.
 */
const HERE = dirname(fileURLToPath(import.meta.url));
const BUILTIN_AGENTS_DIR = resolve(HERE, "..", "agents");

/**
 * Built-in agent set, loaded from `packages/agents/agents/*.md` at
 * module import time. Each `.md` file is a self-contained agent —
 * YAML frontmatter for metadata, markdown body for the prompt.
 *
 * To add an agent, drop a new `.md` file in that directory. No code
 * change needed. The same loader handles user-installed packs, project-
 * local agents, and community-installed agents — see `agentgg agents
 * install <source>` for the runtime equivalents.
 *
 * Per parse failures are surfaced as warnings on stderr rather than
 * crashing the import, so one broken builtin (e.g. mid-edit) doesn't
 * take the whole CLI offline. The errors are still recoverable from
 * `BUILTIN_AGENT_ERRORS` if a caller wants to surface them.
 */
const loaded = loadAgentsFromDir(BUILTIN_AGENTS_DIR, {
  kind: "builtin",
  collectErrors: true,
});

if (loaded.errors.length > 0) {
  for (const err of loaded.errors) {
    console.warn(
      `[@agentgg/agents] Skipped invalid builtin '${err.filePath ?? "?"}': ${err.message}`,
    );
  }
}

export const BUILTIN_AGENTS: ReadonlyArray<Agent> = loaded.agents;
export const BUILTIN_AGENT_ERRORS = loaded.errors;
