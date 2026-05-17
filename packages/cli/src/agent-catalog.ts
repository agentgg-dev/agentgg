import { existsSync } from "node:fs";
import { basename, extname } from "node:path";
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
 *
 * Structural violations of the official tree (duplicate slugs, filename
 * not matching slug) are returned in `violations`. They're separate from
 * `errors` because they indicate a corrupt catalog rather than one bad
 * file — `scan` refuses to run with any violation, while `agents list`
 * surfaces them as warnings so the user can see what's broken.
 */
export function loadAllAgents(
  env: NodeJS.ProcessEnv = process.env,
): { agents: Agent[]; errors: string[]; violations: string[] } {
  const errors: string[] = [];
  const all: Agent[] = [];
  const officialAgents: Agent[] = [];

  // Official agents — downloaded from agentgg-dev/agentgg-agents
  const officialDir = getOfficialAgentsDir(env);
  if (existsSync(officialDir)) {
    const loaded = loadAgentsFromDir(officialDir, {
      kind: "official",
      collectErrors: true,
    });
    officialAgents.push(...loaded.agents);
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

  const violations = validateOfficialAgents(officialAgents);
  return { agents: all, errors, violations };
}

/**
 * Structural checks for the official agent tree. Enforces two invariants
 * that the user gets to rely on:
 *
 *   1. Slug uniqueness — `scan -t <slug>` resolves to exactly one agent.
 *   2. Filename matches slug — `<slug>.md` is the only filename allowed,
 *      so a `grep`/`find` by filename and a slug lookup are equivalent.
 *      Subdirectory location is irrelevant (taxonomy is free).
 *
 * Custom agents are exempt: hand-dropped files in the custom dir don't
 * have to follow the convention, and shadowing official slugs is allowed
 * intentionally (the fork-and-tweak workflow). The `agentgg agents
 * validate` command runs the same checks against an arbitrary path so
 * the agents repo's pre-commit hook can guard the curated tree before it
 * ships.
 */
export function validateOfficialAgents(agents: ReadonlyArray<Agent>): string[] {
  const violations: string[] = [];

  // Duplicate slug check — bucket by slug, report any bucket > 1 with all paths.
  const bySlug = new Map<string, string[]>();
  for (const a of agents) {
    const path = a.source?.path ?? "(unknown path)";
    const bucket = bySlug.get(a.slug);
    if (bucket) bucket.push(path);
    else bySlug.set(a.slug, [path]);
  }
  for (const [slug, paths] of bySlug) {
    if (paths.length > 1) {
      violations.push(
        `duplicate slug '${slug}' in ${paths.length} files:\n` +
          paths.map((p) => `    ${p}`).join("\n"),
      );
    }
  }

  // Filename-matches-slug check.
  for (const a of agents) {
    const path = a.source?.path;
    if (!path) continue;
    const expected = `${a.slug}.md`;
    const actual = basename(path);
    if (actual !== expected && extname(actual).toLowerCase() === ".md") {
      violations.push(
        `filename does not match slug: '${actual}' should be '${expected}'\n    ${path}`,
      );
    }
  }

  return violations;
}
