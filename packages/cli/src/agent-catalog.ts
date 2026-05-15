import { existsSync } from "node:fs";
import { type Agent, getOfficialAgentsDir, loadAgentsFromDir } from "@agentgg/core";
import { getCustomAgentsDir } from "./agents-fs.js";

/**
 * Build the active agent catalog: official agents downloaded from the
 * agentgg-agents repo first, then any the user installed via
 * `agentgg agents add`. Both `agents list` and `scan` read from this so
 * they're always in sync.
 *
 * Parse errors from either directory are collected, not thrown — one
 * malformed file shouldn't block a scan that doesn't even reference it.
 * Run `agentgg agents update` to install or refresh official agents.
 */
export function loadAllAgents(
  env: NodeJS.ProcessEnv = process.env,
): { agents: Agent[]; errors: string[] } {
  const errors: string[] = [];
  const all: Agent[] = [];

  // Official agents — downloaded from agentgg-dev/agentgg-agents
  const officialDir = getOfficialAgentsDir(env);
  if (existsSync(officialDir)) {
    const loaded = loadAgentsFromDir(officialDir, {
      kind: "official",
      collectErrors: true,
    });
    all.push(...loaded.agents);
    for (const err of loaded.errors) {
      errors.push(`${err.filePath ?? "?"}: ${err.message}`);
    }
  }

  // Custom agents — user-installed via `agentgg agents add`
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
