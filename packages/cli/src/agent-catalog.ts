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
 * Structural checks (slug uniqueness, filename == slug) live in
 * `lintOfficialAgents` and are intentionally NOT run here. The
 * agentgg-agents repo's pre-commit hook is the gate. At scan time we
 * trust the published catalog and let `-t <slug>` resolve to every
 * matching agent — official-vs-custom shadowing is allowed by design
 * (the fork-and-tweak workflow), and `resolveTemplates` runs both.
 */
export function loadAllAgents(env: NodeJS.ProcessEnv = process.env): {
  agents: Agent[];
  errors: string[];
} {
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

/**
 * Structural checks for an official agent tree. Run by `agentgg agents
 * lint` (CLI) and the agentgg-agents pre-commit hook. Two invariants:
 *
 *   1. Slug uniqueness — every official agent has a globally unique
 *      slug. Lets users rely on slug as a stable identifier even though
 *      `resolveTemplates` itself does not depend on this (it returns all
 *      slug matches, supporting official-vs-custom shadowing).
 *   2. Filename matches slug — `<slug>.md` is the only filename allowed,
 *      so a `grep`/`find` by filename and a slug lookup are equivalent.
 *      Subdirectory location is irrelevant (taxonomy is free).
 *
 * Custom agents are exempt: hand-dropped files in the custom dir don't
 * have to follow the convention, and shadowing official slugs is allowed
 * intentionally.
 */
export function lintOfficialAgents(agents: ReadonlyArray<Agent>): string[] {
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

  // Regex-compilation check. Every regex an agent declares — in
  // `where.preFilter` and in `precondition.regex.patterns` — must compile
  // under `new RegExp`, or it silently does nothing at scan time (the
  // evaluators swallow bad patterns). Catch them here instead.
  for (const a of agents) {
    const path = a.source?.path ?? "(unknown path)";
    const patterns: Array<{ regex: string; field: string }> = [
      ...a.where.preFilter.map((p) => ({ regex: p.regex, field: "where.preFilter" })),
      ...(a.precondition?.regex?.patterns ?? []).map((p) => ({
        regex: p.regex,
        field: "precondition.regex.patterns",
      })),
    ];
    for (const { regex, field } of patterns) {
      try {
        new RegExp(regex);
      } catch (err) {
        violations.push(
          `invalid regex in ${field}: /${regex}/ — ${(err as Error).message}\n    ${path}`,
        );
      }
    }
  }

  return violations;
}
