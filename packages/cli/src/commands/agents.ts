import type { Agent } from "@agentgg/core";
import type { Command } from "commander";
import { loadAllAgents } from "../agent-catalog.js";
import { addAgents, removeAgent } from "../agents-fs.js";
import { stub } from "../stub.js";

export function formatAgentsTable(agents: ReadonlyArray<Agent>): string {
  if (agents.length === 0) return "No agents installed.";

  const rows = agents.map((a) => ({
    slug: a.slug,
    mode: a.mode,
    noise: a.noiseTier,
    source: a.source?.kind ?? "builtin",
    description: truncate(a.description, 56),
  }));

  const widths = {
    slug: Math.max(4, ...rows.map((r) => r.slug.length)),
    mode: Math.max(4, ...rows.map((r) => r.mode.length)),
    noise: Math.max(5, ...rows.map((r) => r.noise.length)),
    source: Math.max(6, ...rows.map((r) => r.source.length)),
  };

  const header =
    pad("SLUG", widths.slug) +
    "  " +
    pad("MODE", widths.mode) +
    "  " +
    pad("NOISE", widths.noise) +
    "  " +
    pad("SOURCE", widths.source) +
    "  DESCRIPTION";

  const body = rows
    .map(
      (r) =>
        pad(r.slug, widths.slug) +
        "  " +
        pad(r.mode, widths.mode) +
        "  " +
        pad(r.noise, widths.noise) +
        "  " +
        pad(r.source, widths.source) +
        "  " +
        r.description,
    )
    .join("\n");

  const footer = `\n${agents.length} agent${agents.length === 1 ? "" : "s"}`;
  return `${header}\n${body}${footer}`;
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
    .action((opts: { json?: boolean }) => {
      const { agents: all, errors } = loadAllAgents();
      for (const err of errors) {
        console.warn(`warning: ${err}`);
      }
      if (opts.json) {
        console.log(JSON.stringify(all, null, 2));
        return;
      }
      console.log(formatAgentsTable(all));
    });

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
    .command("update")
    .description("pull latest from the official agent repo (not yet wired)")
    .action((opts: Record<string, unknown>) => stub("agents update", opts));
}
