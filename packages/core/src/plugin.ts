import type { Agent, CandidateMatch, Finding, FileRecord, NoiseTier } from "./types.js";

// ---------------------------------------------------------------------------
// Matcher — optional regex pre-filter that narrows what each agent looks at.
// ---------------------------------------------------------------------------
//
// Agents in agentgg are markdown files describing what the LLM should look
// for, but for cost control we also support cheap regex pre-filters that run
// before any LLM call. A matcher fires when its regex hits a file; only files
// with at least one hit (across all enabled matchers for an agent) are sent
// to the LLM.
//
// Matchers are optional. An agent with no matcher (and no `prefilter` in its
// frontmatter) runs the LLM over every file matching its `filePatterns`.

export interface MatcherPlugin {
  /** Slug of the agent this matcher pre-filters for. */
  agentSlug: string;
  description: string;
  noiseTier: NoiseTier;
  filePatterns: string[];
  /** Optional inline test cases — strings the matcher must flag. */
  examples?: string[];
  match(content: string, filePath: string): CandidateMatch[];
}

// ---------------------------------------------------------------------------
// Notifier — where confirmed findings get reported (Slack, GitHub Issues, …)
// ---------------------------------------------------------------------------

export interface NotifyParams {
  finding: Finding;
  record: FileRecord;
  projectId: string;
}

export interface FindingNotification {
  notifierName: string;
  notifiedAt: string;
  externalId?: string;
  externalUrl?: string;
  extra?: Record<string, unknown>;
}

export interface NotifierPlugin {
  name: string;
  notify(params: NotifyParams): Promise<FindingNotification>;
}

// ---------------------------------------------------------------------------
// Reporter — output format (markdown folder is the built-in; plugins can
// add SARIF, JSON, PR-comment, etc.)
// ---------------------------------------------------------------------------

export interface ReporterParams {
  outDir: string;
  records: FileRecord[];
  meta: {
    projectId: string;
    runId: string;
    scanStartedAt: string;
    scanCompletedAt: string;
  };
}

export interface ReporterPlugin {
  name: string;
  /** File extension or short label shown in `--format <x>`. */
  format: string;
  emit(params: ReporterParams): Promise<void>;
}

// ---------------------------------------------------------------------------
// Agent loader — lets plugins ship a bundled set of markdown agents.
// ---------------------------------------------------------------------------
//
// Plugins typically register agents by pointing at a directory of `.md`
// files; the loader walks it, parses frontmatter, and registers each agent.
// We accept either a static array (already-parsed) or a directory path.

export interface AgentLoaderPlugin {
  name: string;
  /** Already-parsed agents (e.g. authored inline in a plugin). */
  agents?: Agent[];
  /** Directory of `.md` files to scan and parse. Relative to the plugin file. */
  agentsDir?: string;
}

// ---------------------------------------------------------------------------
// Umbrella plugin shape
// ---------------------------------------------------------------------------

export interface AgentggPlugin {
  name: string;
  /** Additive: agents this plugin contributes. */
  agents?: AgentLoaderPlugin[];
  /** Additive: optional regex pre-filters that narrow LLM input. */
  matchers?: MatcherPlugin[];
  /** Additive: notifiers (Slack / GitHub Issues / etc.). */
  notifiers?: NotifierPlugin[];
  /** Additive: alternate output formats. */
  reporters?: ReporterPlugin[];
  /**
   * Hook for plugins to register their own CLI subcommands. Receives a
   * Commander program (typed loosely so core stays dep-free).
   */
  commands?: (program: unknown) => void;
}

// ---------------------------------------------------------------------------
// Top-level config (agentgg.config.ts)
// ---------------------------------------------------------------------------

export interface ProjectDeclaration {
  id: string;
  /** Path to the codebase root, absolute or relative to the config file. */
  root: string;
  githubUrl?: string;
  /** Additional paths the loader checks for project-local agents. */
  agentsDirs?: string[];
  /** Path to a SECURITY.md (or alternate scope file) for this project. */
  scopeFile?: string;
  /** Extra context to inject into every agent prompt. */
  promptAppend?: string;
}

export interface AgentggConfig {
  projects: ProjectDeclaration[];
  plugins?: AgentggPlugin[];
  /** Default provider: claude | openai | ollama (or anything a plugin adds). */
  defaultProvider?: string;
  /** Model used in the detection phase. */
  detectModel?: string;
  /** Model used in the validation phase. Defaults to detectModel. */
  validateModel?: string;
}

/**
 * Identity helper so `agentgg.config.ts` files get autocomplete + type
 * checking. Mirrors the pattern most modern TS tools (Vite, Vitest, etc.)
 * use.
 */
export function defineConfig(config: AgentggConfig): AgentggConfig {
  return config;
}
