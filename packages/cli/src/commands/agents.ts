import { existsSync, statSync } from "node:fs";
import { relative, resolve, sep } from "node:path";
import { type Agent, getOfficialAgentsDir, loadAgentsFromDir } from "@agentgg/core";
import type { Command } from "commander";
import { loadAllAgents, validateOfficialAgents } from "../agent-catalog.js";
import { addAgents, getCustomAgentsDir, removeAgent } from "../agents-fs.js";
import { getInstalledVersion, installOfficialAgents } from "../agents-install.js";

const SUMMARY_THRESHOLD = 30;

export function getCategory(agent: Agent, env: NodeJS.ProcessEnv = process.env): string {
  const fullPath = agent.source?.path;
  if (!fullPath) return "-";
  const officialDir = getOfficialAgentsDir(env);
  const customDir = getCustomAgentsDir(env);
  let rel: string | null = null;
  if (fullPath.startsWith(officialDir)) rel = relative(officialDir, fullPath);
  else if (fullPath.startsWith(customDir)) rel = relative(customDir, fullPath);
  if (rel === null) return "-";
  const parts = rel.split(sep).filter(Boolean);
  return parts.length >= 2 ? parts[parts.length - 2] : "(root)";
}

export function formatAgentsTable(
  agents: ReadonlyArray<Agent>,
  env: NodeJS.ProcessEnv = process.env,
): string {
  if (agents.length === 0) return "No agents installed.";

  const rows = agents.map((a) => ({
    slug: a.slug,
    category: getCategory(a, env),
    mode: a.mode,
    noise: a.noiseTier,
    description: truncate(a.description, 56),
  }));

  const widths = {
    slug: Math.max(4, ...rows.map((r) => r.slug.length)),
    category: Math.max(8, ...rows.map((r) => r.category.length)),
    mode: Math.max(4, ...rows.map((r) => r.mode.length)),
    noise: Math.max(5, ...rows.map((r) => r.noise.length)),
  };

  const header =
    pad("SLUG", widths.slug) +
    "  " +
    pad("CATEGORY", widths.category) +
    "  " +
    pad("MODE", widths.mode) +
    "  " +
    pad("NOISE", widths.noise) +
    "  DESCRIPTION";

  const body = rows
    .map(
      (r) =>
        pad(r.slug, widths.slug) +
        "  " +
        pad(r.category, widths.category) +
        "  " +
        pad(r.mode, widths.mode) +
        "  " +
        pad(r.noise, widths.noise) +
        "  " +
        r.description,
    )
    .join("\n");

  const footer = `\n${agents.length} agent${agents.length === 1 ? "" : "s"}`;
  return `${header}\n${body}${footer}`;
}

export function formatCategorySummary(
  agents: ReadonlyArray<Agent>,
  env: NodeJS.ProcessEnv = process.env,
): string {
  const counts = new Map<string, number>();
  for (const a of agents) {
    const cat = getCategory(a, env);
    counts.set(cat, (counts.get(cat) ?? 0) + 1);
  }
  const sorted = [...counts.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  const nameWidth = Math.max(8, ...sorted.map(([n]) => n.length));
  const body = sorted
    .map(
      ([name, n]) =>
        "  " + pad(name, nameWidth) + "  " + n + " agent" + (n === 1 ? "" : "s"),
    )
    .join("\n");
  return (
    "CATEGORY\n" +
    body +
    `\n\n${agents.length} agents total. ` +
    "Use --category <name>, --mode, or --noise to filter. " +
    "Use --all to dump everything."
  );
}

function parseList(s: string | undefined): string[] | null {
  if (!s) return null;
  const parts = s
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
  return parts.length === 0 ? null : parts;
}

function matches(values: string[] | null, target: string): boolean {
  return values === null || values.includes(target);
}

function pad(s: string, width: number): string {
  return s.length >= width ? s : s + " ".repeat(width - s.length);
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}

export function registerAgentsCommand(program: Command): void {
  const agents = program.command("agents").description("manage installed agents");

  agents
    .command("list")
    .description("list installed agents (builtins + user-installed)")
    .option("--json", "emit raw JSON instead of a table")
    .option("--all", "show full table even when no filters are applied")
    .option(
      "--category <names>",
      "filter by category, comma-separated (e.g. auth,injection)",
    )
    .option(
      "--mode <modes>",
      "filter by mode, comma-separated (file, hunt, walker)",
    )
    .option(
      "--noise <tiers>",
      "filter by noise tier, comma-separated (precise, normal, loud)",
    )
    .action(
      (opts: {
        json?: boolean;
        all?: boolean;
        category?: string;
        mode?: string;
        noise?: string;
      }) => {
        const { agents: all, errors, violations } = loadAllAgents();
        for (const err of errors) {
          console.warn(`warning: ${err}`);
        }
        for (const v of violations) {
          console.warn(`warning: ${v}`);
        }

        const categories = parseList(opts.category);
        const modes = parseList(opts.mode);
        const noises = parseList(opts.noise);
        const hasFilters =
          categories !== null || modes !== null || noises !== null;

        const filtered = all.filter(
          (a) =>
            matches(categories, getCategory(a)) &&
            matches(modes, a.mode) &&
            matches(noises, a.noiseTier),
        );

        if (opts.json) {
          console.log(JSON.stringify(filtered, null, 2));
          return;
        }

        if (!hasFilters && !opts.all && filtered.length > SUMMARY_THRESHOLD) {
          console.log(formatCategorySummary(filtered));
          return;
        }

        console.log(formatAgentsTable(filtered));
      },
    );

  agents
    .command("info <slug>")
    .description("show full details for one installed agent")
    .action((slug: string) => {
      const { agents: all } = loadAllAgents();
      const match = all.find((a) => a.slug === slug);
      if (!match) {
        console.error(`No agent with slug '${slug}'.`);
        process.exit(1);
      }
      console.log(JSON.stringify(match, null, 2));
    });

  agents
    .command("add <file-or-dir>")
    .description(
      "install a local .md agent (or every .md in a directory) into ~/.agentgg/agents/custom/",
    )
    .action((source: string) => {
      try {
        const result = addAgents(source);
        for (const a of result.added) {
          console.log(`✓ added ${a.slug}  (${a.to})`);
        }
        for (const s of result.skipped) {
          console.log(`✗ skipped ${s.from}  — ${s.reason}`);
        }
        if (result.added.length === 0) {
          process.exit(1);
        }
      } catch (err) {
        console.error(`add failed: ${(err as Error).message}`);
        process.exit(1);
      }
    });

  agents
    .command("remove <slug>")
    .description("remove a user-installed agent by slug (built-ins cannot be removed)")
    .action((slug: string) => {
      try {
        const path = removeAgent(slug);
        console.log(`✓ removed ${slug}  (${path})`);
      } catch (err) {
        console.error(`remove failed: ${(err as Error).message}`);
        process.exit(1);
      }
    });

  agents
    .command("validate [path]")
    .description(
      "validate an agents tree (defaults to the installed official dir) — checks for duplicate slugs and filename != slug",
    )
    .action((path: string | undefined) => {
      const env = process.env;
      const target = path ? resolve(path) : getOfficialAgentsDir(env);
      if (!existsSync(target)) {
        console.error(`No such file or directory: ${target}`);
        process.exit(1);
      }
      if (!statSync(target).isDirectory()) {
        console.error(`Not a directory: ${target}`);
        process.exit(1);
      }
      const { agents: loaded, errors } = loadAgentsFromDir(target, {
        kind: "official",
        collectErrors: true,
      });
      const parseErrors = errors.map(
        (e) => `parse error: ${e.filePath ?? "?"}: ${e.message}`,
      );
      const violations = validateOfficialAgents(loaded);
      const all = [...parseErrors, ...violations];
      if (all.length === 0) {
        console.log(`✓ ${loaded.length} agents valid (${target})`);
        return;
      }
      for (const v of all) console.error(v);
      console.error(
        `\n${all.length} problem${all.length === 1 ? "" : "s"} in ${target}`,
      );
      process.exit(1);
    });

  agents
    .command("update")
    .description("pull latest agents from agentgg-dev/agentgg-agents")
    .option("--force", "re-download even if already on the latest version")
    .action(async (opts: { force?: boolean }) => {
      const installed = getInstalledVersion();
      if (installed) {
        process.stdout.write(
          `[INF] Current version: ${installed.version} (installed ${installed.installedAt})\n`,
        );
      }
      process.stdout.write("[INF] Checking for updates...\n");
      try {
        const { version, count } = await installOfficialAgents(process.env, {
          force: opts.force,
        });
        process.stdout.write(
          `[INF] Successfully installed agentgg-agents at ~/.agentgg/agentgg-agents (${count} agents, ${version})\n`,
        );
      } catch (err) {
        console.error(`[ERR] Update failed: ${(err as Error).message}`);
        process.exit(1);
      }
    });
}
