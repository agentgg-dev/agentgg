import { existsSync } from "node:fs";
import { BUILTIN_AGENTS } from "@agentgg/agents";
import { type Agent, loadAgentsFromDir } from "@agentgg/core";
import { getCustomAgentsDir } from "./agents-fs.js";

/**
 * Build the active agent catalog: built-in agents first, then any the
 * user installed via `agentgg agents add`. Both `agents list` and `scan`
 * read from this so they're always in sync.
 *
 * Parse errors from the custom directory are collected, not thrown —
 * one malformed file in `~/.agentgg/agents/custom/` shouldn't block a
 * scan that doesn't even reference it.
 */
export function loadAllAgents(
  env: NodeJS.ProcessEnv = process.env,
): { agents: Agent[]; errors: string[] } {
  const errors: string[] = [];
  const all: Agent[] = [...BUILTIN_AGENTS];
  const customDir = getCustomAgentsDir(env);
  if (existsSync(customDir)) {
    const loaded = loadAgentsFromDir(customDir, {
      kind: "custom",
      collectErrors: true,
    });
    all.push(...loaded.agents);
    for (const err of loaded.errors) {
      errors.push(`${err.filePath ?? "?"}: ${err.message}`);
    }
  }
  return { agents: all, errors };
}
