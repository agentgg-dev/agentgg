import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
} from "node:fs";
import { basename, extname, join, resolve } from "node:path";
import { type Agent, getAgentsDir, loadAgentFile, parseAgentMarkdown } from "@agentgg/core";

/**
 * On-disk location where user-installed agents live. The scan command
 * loads this directory alongside the built-in catalog every run.
 */
export function getCustomAgentsDir(env: NodeJS.ProcessEnv = process.env): string {
  return join(getAgentsDir(env), "custom");
}

export interface AddResult {
  added: Array<{ slug: string; from: string; to: string }>;
  skipped: Array<{ from: string; reason: string }>;
}

/**
 * Add an agent (or a directory of agents) to `~/.agentgg/agents/custom/`.
 *
 *   - Single file: validate via `loadAgentFile`, then copy to
 *     `<customDir>/<slug>.md` (using the agent's slug as filename, not
 *     whatever the file happened to be called). Makes `remove <slug>`
 *     unambiguous later.
 *   - Directory: walk for `.md` files, validate each, copy each.
 *   - Refuses to overwrite an existing custom agent with the same slug.
 *     User should `agents remove <slug>` first.
 *   - Doesn't validate against built-in slugs — collision is fine, the
 *     scan command resolves it (built-ins win unless we change that
 *     later).
 *
 * Returns a summary so the CLI can print one line per action.
 */
export function addAgents(
  source: string,
  env: NodeJS.ProcessEnv = process.env,
  options: { allAgentsInDir?: Agent[] } = {},
): AddResult {
  const abs = resolve(source);
  if (!existsSync(abs)) {
    throw new Error(`No such file or directory: ${source}`);
  }
  const customDir = getCustomAgentsDir(env);
  mkdirSync(customDir, { recursive: true });

  const result: AddResult = { added: [], skipped: [] };
  const filesToTry: string[] = [];

  if (statSync(abs).isDirectory()) {
    for (const name of readdirSync(abs)) {
      if (extname(name).toLowerCase() === ".md") {
        filesToTry.push(join(abs, name));
      }
    }
    if (filesToTry.length === 0) {
      throw new Error(`No .md files found in directory: ${source}`);
    }
  } else {
    if (extname(abs).toLowerCase() !== ".md") {
      throw new Error(`Not a .md file: ${source}`);
    }
    filesToTry.push(abs);
  }

  for (const filePath of filesToTry) {
    let agent: Agent;
    try {
      // Parse via the same loader scan.ts uses, so anything that scans
      // successfully also adds successfully.
      agent =
        options.allAgentsInDir?.find((a) => a.source?.path === filePath) ??
        loadAgentFile(filePath, "custom");
    } catch (err) {
      result.skipped.push({
        from: filePath,
        reason: (err as Error).message,
      });
      continue;
    }

    const destPath = join(customDir, `${agent.slug}.md`);
    if (existsSync(destPath)) {
      result.skipped.push({
        from: filePath,
        reason: `Already installed (run \`agentgg agents remove ${agent.slug}\` first)`,
      });
      continue;
    }

    copyFileSync(filePath, destPath);
    result.added.push({ slug: agent.slug, from: filePath, to: destPath });
  }
  return result;
}

/**
 * Remove a user-installed agent by slug. Built-ins are never removable
 * — they live inside the npm package, not the custom dir.
 *
 * Returns the absolute path of the file that was deleted (callers
 * print this so users can see what just disappeared). Throws if no
 * matching custom agent is installed.
 */
export function removeAgent(
  slug: string,
  env: NodeJS.ProcessEnv = process.env,
): string {
  const customDir = getCustomAgentsDir(env);
  // Filename convention from `addAgents` is `<slug>.md`. But a user might
  // have hand-dropped a file with a different filename whose frontmatter
  // happens to have this slug — scan that case too.
  const directPath = join(customDir, `${slug}.md`);
  if (existsSync(directPath)) {
    rmSync(directPath);
    return directPath;
  }
  if (!existsSync(customDir)) {
    throw new Error(
      `No user-installed agent with slug '${slug}' — no custom agents installed yet (directory ${customDir} doesn't exist).`,
    );
  }
  for (const name of readdirSync(customDir)) {
    if (extname(name).toLowerCase() !== ".md") continue;
    const full = join(customDir, name);
    try {
      const text = readFileSync(full, "utf8");
      const agent = parseAgentMarkdown(text);
      if (agent.slug === slug) {
        rmSync(full);
        return full;
      }
    } catch {
      // Malformed file — skip; the user can clean it up separately.
    }
  }
  throw new Error(
    `No user-installed agent with slug '${slug}'. (Built-ins can't be removed; ${basename(customDir)}/ is for user additions only.)`,
  );
}
