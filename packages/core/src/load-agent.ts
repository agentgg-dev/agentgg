import { readdirSync, readFileSync, type Stats, statSync } from "node:fs";
import { basename, extname, join, resolve } from "node:path";
import matter from "gray-matter";
import { Agent } from "./types.js";

/**
 * Errors thrown by the loader. Carries `filePath` so callers (CLI's
 * `agents list`, `agents lint`, error logs) can point at the offending
 * file precisely instead of saying "something failed somewhere."
 */
export class AgentParseError extends Error {
  readonly filePath?: string;
  readonly cause?: unknown;
  constructor(message: string, opts: { filePath?: string; cause?: unknown } = {}) {
    super(message);
    this.name = "AgentParseError";
    if (opts.filePath !== undefined) this.filePath = opts.filePath;
    if (opts.cause !== undefined) this.cause = opts.cause;
  }
}

export type AgentSourceKind = "builtin" | "official" | "community" | "project" | "custom";

/**
 * Parse a single markdown agent file's content. Frontmatter becomes the
 * Agent's metadata; the markdown body becomes its `prompt`. Pure — no
 * filesystem access, suitable for in-memory parsing (e.g. `agents lint
 * --stdin`).
 *
 * Throws AgentParseError with the original Zod issues attached as
 * `cause` when validation fails.
 */
export function parseAgentMarkdown(
  text: string,
  source?: { kind: AgentSourceKind; path: string; pack?: string },
): Agent {
  let parsed: ReturnType<typeof matter>;
  try {
    parsed = matter(text);
  } catch (err) {
    throw new AgentParseError(`Failed to parse YAML frontmatter: ${(err as Error).message}`, {
      filePath: source?.path,
      cause: err,
    });
  }

  const frontmatter = parsed.data;
  const body = parsed.content.trim();

  if (!body) {
    throw new AgentParseError("Agent file has no prompt body after frontmatter.", {
      filePath: source?.path,
    });
  }

  const merged: Record<string, unknown> = {
    ...frontmatter,
    prompt: body,
  };
  if (source !== undefined) {
    merged.source = source;
  }

  const result = Agent.safeParse(merged);
  if (!result.success) {
    throw new AgentParseError(
      `Agent schema validation failed: ${formatZodIssues(result.error.issues)}`,
      { filePath: source?.path, cause: result.error },
    );
  }
  return result.data;
}

/**
 * Read + parse one `.md` agent file from disk. Stamps `source` from
 * the file path and the caller-supplied `kind`.
 */
export function loadAgentFile(
  absPath: string,
  kind: AgentSourceKind = "custom",
  pack?: string,
): Agent {
  let text: string;
  try {
    text = readFileSync(absPath, "utf8");
  } catch (err) {
    throw new AgentParseError(`Failed to read agent file: ${(err as Error).message}`, {
      filePath: absPath,
      cause: err,
    });
  }
  return parseAgentMarkdown(text, {
    kind,
    path: absPath,
    ...(pack !== undefined ? { pack } : {}),
  });
}

export interface LoadAgentsDirOptions {
  kind?: AgentSourceKind;
  pack?: string;
  /** If true, collect parse errors instead of throwing on the first failure. */
  collectErrors?: boolean;
}

export interface LoadAgentsDirResult {
  agents: Agent[];
  errors: AgentParseError[];
}

/**
 * Walk a directory recursively, parse every `.md` file as an agent,
 * and return the result. `package.json`, READMEs, and other non-.md
 * files are ignored. Subdirectories are walked depth-first.
 *
 * Two modes:
 *   - default: throw on the first parse failure
 *   - `collectErrors: true`: collect all errors, return both lists
 *     (used by `agents list` so one broken file doesn't hide the rest)
 */
export function loadAgentsFromDir(
  dirPath: string,
  options: LoadAgentsDirOptions = {},
): LoadAgentsDirResult {
  const { kind = "custom", pack, collectErrors = false } = options;
  const absDir = resolve(dirPath);

  const agents: Agent[] = [];
  const errors: AgentParseError[] = [];

  function walk(dir: string): void {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch (err) {
      throw new AgentParseError(`Failed to read agents directory: ${(err as Error).message}`, {
        filePath: dir,
        cause: err,
      });
    }

    for (const name of entries) {
      const abs = join(dir, name);
      let st: Stats;
      try {
        st = statSync(abs);
      } catch {
        continue;
      }

      if (st.isDirectory()) {
        if (isSkippedDir(name)) continue;
        walk(abs);
        continue;
      }

      if (extname(name).toLowerCase() !== ".md") continue;
      // Skip README.md / SECURITY.md / CHANGELOG.md etc. — they're not agents.
      if (isReservedDoc(name)) continue;
      if (!st.isFile()) continue;

      try {
        agents.push(loadAgentFile(abs, kind, pack));
      } catch (err) {
        if (collectErrors && err instanceof AgentParseError) {
          errors.push(err);
          continue;
        }
        throw err;
      }
    }
  }

  walk(absDir);
  return { agents, errors };
}

function isSkippedDir(name: string): boolean {
  return name === ".git" || name === ".github" || name === "node_modules";
}

function isReservedDoc(name: string): boolean {
  const base = basename(name).toUpperCase();
  return [
    "README.MD",
    "CHANGELOG.MD",
    "CONTRIBUTING.MD",
    "LICENSE.MD",
    "NOTICE.MD",
    "SECURITY.MD",
    "CODE_OF_CONDUCT.MD",
  ].includes(base);
}

function formatZodIssues(issues: { path: (string | number)[]; message: string }[]): string {
  if (issues.length === 0) return "(no issues recorded)";
  return issues
    .map((i) => {
      const path = i.path.length > 0 ? i.path.join(".") : "(root)";
      return `${path}: ${i.message}`;
    })
    .join("; ");
}
