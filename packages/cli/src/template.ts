import { existsSync, readFileSync, statSync } from "node:fs";
import { extname, resolve } from "node:path";
import { type Agent, loadAgentFile, loadAgentsFromDir } from "@agentgg/core";

/**
 * Resolve `--template` / `-t` arguments into a concrete `Agent[]`.
 *
 * Each value (after comma/whitespace splitting) is auto-detected:
 *   - Path to a `.md` file → load that one agent
 *   - Path to a directory → load every `.md` agent inside (non-recursive)
 *   - Path to a `.txt` file → read line-by-line, recursively resolve each
 *     entry as a slug or path. `#` starts a whole-line comment; blank
 *     lines are skipped. Useful when a curated agent list is long enough
 *     to be annoying on the command line.
 *   - Otherwise → treat as a slug, look up in `availableAgents`.
 *
 * Multiple values can be passed three equivalent ways:
 *   - One `-t` per value: `-t a -t b -t c`
 *   - Comma-separated:    `-t a,b,c`
 *   - Whitespace-separated (quoted): `-t "a b c"`
 *
 * All three can be mixed. Duplicate inputs are deduped by file path —
 * if a user passes the same agent twice (once by slug, once by its
 * file, once via a list file), it still only runs once. But two
 * distinct agents that happen to share a slug (e.g. an official agent
 * and a custom one shadowing it) both run, matching the fork-and-tweak
 * workflow we support across official+custom. Same shape as nuclei's
 * `-t/-templates`.
 *
 * On unresolvable inputs, throws with a precise per-entry error list.
 * The scan command surfaces this as a clean error before any LLM call.
 */
export function resolveTemplates(
  inputs: string[],
  availableAgents: ReadonlyArray<Agent>,
  officialAgentsDir?: string,
): Agent[] {
  const tokens = expandTokens(inputs);
  if (tokens.length === 0) return [];

  const errors: string[] = [];
  // Dedupe by source path, not slug — see header comment.
  const seen = new Map<string, Agent>();
  const dedupKey = (a: Agent): string => a.source?.path ?? `slug:${a.slug}`;

  for (const token of tokens) {
    if (looksLikeFilesystemPath(token)) {
      try {
        const found = loadFromPath(token, officialAgentsDir);
        for (const agent of found) {
          const key = dedupKey(agent);
          if (!seen.has(key)) seen.set(key, agent);
        }
      } catch (err) {
        errors.push(`'${token}': ${(err as Error).message}`);
      }
      continue;
    }
    const matches = availableAgents.filter((a) => a.slug === token);
    if (matches.length === 0) {
      errors.push(
        `'${token}': no installed agent with that slug. ` +
          `Run \`agentgg agents list\` to see what's available, or pass a path to a .md file.`,
      );
      continue;
    }
    for (const m of matches) {
      const key = dedupKey(m);
      if (!seen.has(key)) seen.set(key, m);
    }
  }

  if (errors.length > 0) {
    throw new Error(`Could not resolve --template:\n${errors.map((e) => `  ${e}`).join("\n")}`);
  }
  return [...seen.values()];
}

/**
 * Split each `-t` value on commas and whitespace, then walk through
 * the resulting tokens expanding any `.txt` list files in place. List
 * files are read once each (cycle-safe) and may themselves reference
 * other list files. Whole-line `#` comments and blank lines inside
 * list files are ignored.
 */
function expandTokens(inputs: string[]): string[] {
  const out: string[] = [];
  const seenListFiles = new Set<string>();

  function visit(raw: string): void {
    for (const token of raw.split(/[\s,]+/).filter(Boolean)) {
      if (isListFilePath(token)) {
        const abs = resolve(token);
        if (seenListFiles.has(abs)) continue; // cycle / dup — already expanded
        seenListFiles.add(abs);
        if (!existsSync(abs)) {
          throw new Error(`--template: list file does not exist: ${abs}`);
        }
        let content: string;
        try {
          content = readFileSync(abs, "utf8");
        } catch (err) {
          throw new Error(`--template: cannot read list file ${abs}: ${(err as Error).message}`);
        }
        for (const line of content.split(/\r?\n/)) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith("#")) continue;
          visit(trimmed);
        }
        continue;
      }
      out.push(token);
    }
  }

  for (const input of inputs) visit(input);
  return out;
}

/** A `.txt` value is always treated as a list-of-agents file. */
function isListFilePath(s: string): boolean {
  return s.toLowerCase().endsWith(".txt");
}

/**
 * Heuristic: does this look like a filesystem path rather than a slug?
 *
 * Slugs are kebab-case `[a-z0-9][a-z0-9-]*`. Anything containing path
 * separators or ending in `.md` is treated as filesystem. We don't
 * stat-check first because a missing path with `/` in it should
 * produce a "no such file" error, not a "no such slug" error.
 */
function looksLikeFilesystemPath(s: string): boolean {
  if (s.endsWith(".md")) return true;
  if (s.includes("/") || s.includes("\\")) return true;
  if (s.startsWith(".") || s.startsWith("~")) return true;
  return false;
}

function loadFromPath(p: string, officialAgentsDir?: string): Agent[] {
  let abs = resolve(p);
  // If the path doesn't exist locally, try resolving it relative to the
  // official agents directory — lets users write `-t basic/injection/`
  // instead of the full ~/.agentgg/agentgg-agents/basic/injection/ path,
  // mirroring how nuclei resolves `-t cves/` against ~/nuclei-templates/.
  if (!existsSync(abs) && officialAgentsDir) {
    const candidate = resolve(officialAgentsDir, p);
    if (existsSync(candidate)) abs = candidate;
  }
  if (!existsSync(abs)) throw new Error(`No such file or directory`);
  const st = statSync(abs);
  if (st.isDirectory()) {
    const { agents, errors } = loadAgentsFromDir(abs, {
      kind: "project",
      collectErrors: true,
    });
    if (agents.length === 0) {
      throw new Error(
        `No valid .md agents found in directory${errors.length > 0 ? ` (${errors.length} parse error(s))` : ""}`,
      );
    }
    return agents;
  }
  if (extname(abs).toLowerCase() !== ".md") {
    throw new Error(`Not a .md file`);
  }
  return [loadAgentFile(abs, "project")];
}
