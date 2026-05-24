import type { Agent, CvssScore, Finding } from "@agentgg/core";
import { query } from "@anthropic-ai/claude-agent-sdk";
import type { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import {
  buildDetectPrompt,
  buildHuntPrompt,
  buildInvestigatePrompt,
  DetectionResult,
  type Detector,
  type HuntArgs,
  hydrateFinding,
  type InvestigateArgs,
  type RuleHitsForFile,
} from "../detect.js";
import { asCvssScore, buildScorePrompt, LlmScore } from "../scoring.js";
import {
  asValidationField,
  buildScopeValidatePrompt,
  buildValidatePrompt,
  LlmValidation,
} from "../validator.js";

const ENV_ALLOWLIST = new Set<string>([
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "SHELL",
  "TERM",
  "TZ",
  "LANG",
  "LANGUAGE",
  "LC_ALL",
  "LC_CTYPE",
  "TMPDIR",
  "TMP",
  "TEMP",
  "PWD",
  "NODE_PATH",
  "NODE_OPTIONS",
  // Windows-specific essentials
  "USERPROFILE",
  "APPDATA",
  "LOCALAPPDATA",
  "PROGRAMFILES",
  "PROGRAMDATA",
  "SYSTEMROOT",
  "WINDIR",
  "COMSPEC",
  "PATHEXT",
]);

/**
 * Detector backed by `@anthropic-ai/claude-agent-sdk`. Spawns the
 * `claude` CLI as a child process. Handles every Detector method
 * (file, hunt, walker, validate) for both Anthropic auth types
 * (`apiKey` and `oauthToken`).
 *
 * File mode is a one-turn agent with no tools — the prompt already
 * contains the full file content. Hunt and walker modes open
 * Read/Glob/Grep and let the agent decide which files to read, up to
 * a caller-supplied `maxTurns` cap.
 */
export class ClaudeAgentDetector implements Detector {
  readonly name: string;
  private readonly apiKey?: string;
  private readonly oauthToken?: string;
  private readonly model: string;
  private readonly verbose: boolean;
  private readonly validateMaxTurns: number;
  private readonly effort?: "low" | "medium" | "high" | "max";
  private readonly thinking?: "off" | "adaptive" | "enabled";

  constructor(opts: {
    apiKey?: string;
    oauthToken?: string;
    model: string;
    /** Stream tool-use messages (Glob/Grep/Read/etc.) to stdout as the agent runs. */
    verbose?: boolean;
    /** Turn cap for the validator's single-finding call. Default 30. */
    validateMaxTurns?: number;
    /** SDK `effort` passed on every tool-using call. */
    effort?: "low" | "medium" | "high" | "max";
    /** SDK `thinking` mode. `adaptive` matches Claude Code interactive — the model decides per call. */
    thinking?: "off" | "adaptive" | "enabled";
  }) {
    if (!opts.apiKey && !opts.oauthToken) {
      throw new Error("ClaudeAgentDetector needs either apiKey or oauthToken");
    }
    this.apiKey = opts.apiKey;
    this.oauthToken = opts.oauthToken;
    this.model = opts.model;
    this.verbose = opts.verbose ?? false;
    this.validateMaxTurns = opts.validateMaxTurns ?? 30;
    this.effort = opts.effort;
    this.thinking = opts.thinking;
    this.name = opts.oauthToken ? "anthropic-oauth" : "anthropic-api";
  }

  async detectFile(args: {
    agent: Agent;
    filePath: string;
    content: string;
    ruleHits?: ReadonlyArray<RuleHitsForFile>;
    signal?: AbortSignal;
  }): Promise<Finding[]> {
    const { agent, filePath, content, ruleHits, signal } = args;
    const prompt = buildDetectPrompt(agent, filePath, content, ruleHits);
    // Single-turn: no tools needed — the file content is already in the
    // prompt. `tools: []` removes all built-in tools from the model's
    // context, so it can't burn turns on speculative tool calls.
    // maxTurns kept at 5 as a safety margin pending separate revert.
    const result = await this.runStructured({
      prompt,
      tools: [],
      maxTurns: 5,
      schema: DetectionResult,
      signal,
    });
    return result.findings.map((f) => hydrateFinding(f, agent, filePath));
  }

  async hunt(args: HuntArgs & { signal?: AbortSignal }): Promise<Finding[]> {
    const {
      agent,
      rootDir,
      excludePatterns,
      includePatterns,
      maxFileSizeKb,
      maxTurns,
      diff,
      ruleHits,
    } = args;
    const prompt = buildHuntPrompt(agent, {
      excludePatterns,
      includePatterns,
      maxFileSizeKb,
      diff,
      ruleHits,
    });

    // Single agentic run with SDK-enforced structured output. The
    // model can chat in any narrative form during the session; the
    // SDK constrains the *final* output to match the JSON schema
    // generated from `DetectionResult`. No fence parsing, no string
    // escapes, no shape conflicts — the typed object arrives as
    // `msg.structured_output` and is Zod-validated defensively.
    const result = await this.runStructured({
      prompt,
      tools: ["Read", "Glob", "Grep"],
      maxTurns,
      cwd: rootDir,
      schema: DetectionResult,
      signal: args.signal,
    });

    return result.findings.map((f) => hydrateFinding(f, agent, f.filePath ?? "(unknown)"));
  }

  async investigate(args: InvestigateArgs & { signal?: AbortSignal }): Promise<Finding[]> {
    const { agents, rootDir, candidates, maxTurns } = args;
    const prompt = buildInvestigatePrompt(agents, candidates);

    // Walker-mode batched flow: the model sees N candidate files in
    // one session — possibly with hits from multiple agents pooled
    // per file — and can cross-reference between them, with tools
    // to chase context outside the batch. Same SDK structured output
    // guarantee as hunt — final output is schema-validated by the
    // SDK, no fence parsing.
    const result = await this.runStructured({
      prompt,
      tools: ["Read", "Glob", "Grep"],
      maxTurns,
      cwd: rootDir,
      schema: DetectionResult,
      signal: args.signal,
    });

    // Attribution rules:
    // - Single-agent batch: every finding is stamped with that agent.
    // - Multi-agent batch: the model is told to set `agentSlug` per
    //   finding; we trust that tag. Findings without a recognized
    //   agentSlug in a multi-agent batch are dropped (they're either
    //   model-invented or unattributable).
    const agentsBySlug = new Map(agents.map((a) => [a.slug, a]));
    const fallbackFilePath = candidates[0]?.filePath ?? "(unknown)";
    const findings: Finding[] = [];
    for (const f of result.findings) {
      const owningAgent = (() => {
        if (agents.length === 1) return agents[0];
        if (f.agentSlug && agentsBySlug.has(f.agentSlug)) {
          return agentsBySlug.get(f.agentSlug)!;
        }
        return undefined;
      })();
      if (!owningAgent) continue;
      findings.push(hydrateFinding(f, owningAgent, f.filePath ?? fallbackFilePath));
    }
    return findings;
  }

  async validateFinding(args: {
    finding: Finding;
    fileContent: string;
    scope?: string;
    signal?: AbortSignal;
  }) {
    const prompt = buildValidatePrompt(args);
    // Single-turn: `tools: []` removes all built-in tools from the
    // model's context, so the validator can't burn turns on speculative
    // Grep/Read calls. validateMaxTurns kept as-is pending separate
    // revert of the workaround budget.
    const validated = await this.runStructured({
      prompt,
      tools: [],
      maxTurns: this.validateMaxTurns,
      schema: LlmValidation,
      signal: args.signal,
    });
    return asValidationField(validated);
  }

  async validateFindingByScope(args: { finding: Finding; scope: string; signal?: AbortSignal }) {
    const prompt = buildScopeValidatePrompt(args);
    const validated = await this.runStructured({
      prompt,
      tools: [],
      maxTurns: this.validateMaxTurns,
      schema: LlmValidation,
      signal: args.signal,
    });
    return asValidationField(validated);
  }

  async scoreFinding(args: {
    finding: Finding;
    fileContent: string;
    signal?: AbortSignal;
  }): Promise<CvssScore> {
    // Single-turn, no tools — same constraint as validation: the
    // prompt already carries the full file content, so the model
    // shouldn't burn turns on speculative reads.
    const llmScore = await this.runStructured({
      prompt: buildScorePrompt(args),
      tools: [],
      maxTurns: this.validateMaxTurns,
      schema: LlmScore,
      signal: args.signal,
    });
    return asCvssScore(llmScore);
  }

  /**
   * Variant of `run` that asks the SDK to enforce a JSON schema on the
   * final output and returns the Zod-validated structured result.
   *
   * Used by `hunt()` to skip the text→JSON parsing step entirely. The
   * SDK converts the schema into a tool-call-style structured-output
   * constraint at the protocol level, so the model literally cannot
   * emit fences, prose, or mistyped fields in the final answer. The
   * Zod `parse` at the end is defensive belt-and-suspenders in case
   * the SDK ever hands us something unexpected.
   */
  private async runStructured<T extends z.ZodTypeAny>(opts: {
    prompt: string;
    /**
     * Built-in tools the model is permitted to call. `[]` removes all
     * tools from its context (true single-turn behavior). A non-empty
     * list whitelists exactly those tool names. Maps to the SDK's
     * `tools` option — NOT `allowedTools`, which is auto-approval, not
     * restriction.
     */
    tools: string[];
    maxTurns: number;
    cwd?: string;
    schema: T;
    /**
     * Parent scan abort signal. When the orchestrator decides to bail
     * (fatal quota / auth diagnostic in a sibling worker), this signal
     * fires; we mirror it onto a local `AbortController` and hand the
     * controller to the SDK so its in-flight subprocess request is
     * cancelled immediately rather than waiting for the next message.
     */
    signal?: AbortSignal;
  }): Promise<z.infer<T>> {
    const jsonSchema = zodToJsonSchema(opts.schema) as Record<string, unknown>;
    // Bridge: parent gives us a signal, SDK wants a controller. Make a
    // local controller and link parent → local so aborting the parent
    // aborts ours. If the parent is already aborted, fail fast before
    // even spawning the subprocess.
    const sdkAbortController = new AbortController();
    // Pull into a local const so the addEventListener arrow closure sees
    // a definitely-non-undefined reference (the outer `opts.signal` would
    // require a non-null assertion inside the closure).
    const parentSignal = opts.signal;
    if (parentSignal) {
      if (parentSignal.aborted) {
        sdkAbortController.abort(parentSignal.reason);
      } else {
        parentSignal.addEventListener(
          "abort",
          () => sdkAbortController.abort(parentSignal.reason),
          { once: true },
        );
      }
    }
    let structured: unknown;
    let resultText = "";
    try {
      for await (const message of query({
        prompt: opts.prompt,
        options: {
          ...(opts.cwd ? { cwd: opts.cwd } : {}),
          ...(process.env.CLAUDE_CODE_EXECUTABLE
            ? { pathToClaudeCodeExecutable: process.env.CLAUDE_CODE_EXECUTABLE }
            : {}),
          ...(this.effort ? { effort: this.effort } : {}),
          ...(this.thinking && this.thinking !== "off"
            ? { thinking: { type: this.thinking } }
            : {}),
          tools: opts.tools,
          permissionMode: "bypassPermissions",
          maxTurns: opts.maxTurns,
          model: this.model,
          env: this.buildEnv(),
          outputFormat: { type: "json_schema", schema: jsonSchema },
          abortController: sdkAbortController,
        },
      })) {
        const msg = message as Record<string, unknown>;
        if (this.verbose && msg.type === "assistant") {
          this.printToolUses(msg);
        }
        if (msg.type === "result" && msg.subtype === "success") {
          structured = (msg as { structured_output?: unknown }).structured_output;
          resultText = String((msg as { result?: unknown }).result ?? "");
          if (this.verbose) this.logUsage(msg);
        }
      }
    } catch (err) {
      if (process.env.AGENTGG_DEBUG) {
        const util = await import("node:util");
        console.error("---- ClaudeAgentDetector.runStructured raw error ----");
        console.error(util.inspect(err, { depth: 5, colors: false }));
        console.error("------------------------------------------------------");
      }
      throw err;
    }
    if (structured === undefined) {
      throw new Error(
        `Claude Agent SDK produced no structured_output. Raw result text: ${resultText.slice(0, 200)}…`,
      );
    }
    return opts.schema.parse(structured) as z.infer<T>;
  }

  /**
   * Render the SDK's per-call usage block. The result message carries
   * `usage` with cache hit/miss token counts — surfacing it lets the
   * operator confirm the SDK's automatic prompt caching is firing.
   * A cache_read_input_tokens > 0 means the prefix was served from the
   * 5-min ephemeral cache at ~0.1× the normal input rate.
   */
  private logUsage(msg: Record<string, unknown>): void {
    const usage = msg.usage as
      | {
          input_tokens?: number;
          output_tokens?: number;
          cache_creation_input_tokens?: number;
          cache_read_input_tokens?: number;
        }
      | undefined;
    if (!usage) return;
    const inTok = usage.input_tokens ?? 0;
    const outTok = usage.output_tokens ?? 0;
    const cacheWrite = usage.cache_creation_input_tokens ?? 0;
    const cacheRead = usage.cache_read_input_tokens ?? 0;
    const cost = msg.total_cost_usd as number | undefined;
    const costStr = typeof cost === "number" ? ` cost=$${cost.toFixed(4)}` : "";
    console.log(
      `    [usage] in=${inTok} out=${outTok} cache_read=${cacheRead} cache_write=${cacheWrite}${costStr}`,
    );
  }

  /**
   * Render tool-use blocks from one SDK assistant message to stdout.
   * The SDK emits an assistant message whenever the model produces a
   * turn; each turn's `content` is a list of blocks, some of which are
   * `tool_use` blocks carrying the tool name + input args. Mirroring
   * Claude Code's interactive output so the operator can see what the
   * agent is doing instead of staring at silence.
   */
  private printToolUses(msg: Record<string, unknown>): void {
    const message = msg.message as { content?: unknown[] } | undefined;
    if (!message || !Array.isArray(message.content)) return;
    for (const block of message.content) {
      const b = block as { type?: string; name?: string; input?: Record<string, unknown> };
      if (b.type !== "tool_use" || !b.name) continue;
      if (b.name === "StructuredOutput") continue;
      const arg = formatToolArg(b.name, b.input ?? {});
      console.log(arg ? `    ${b.name} ${arg}` : `    ${b.name}`);
    }
  }

  private buildEnv(): Record<string, string> {
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) {
      if (typeof v !== "string") continue;
      if (ENV_ALLOWLIST.has(k) || k.startsWith("LC_") || k === "Path") {
        env[k] = v;
      }
    }
    if (this.oauthToken) env.CLAUDE_CODE_OAUTH_TOKEN = this.oauthToken;
    if (this.apiKey) env.ANTHROPIC_API_KEY = this.apiKey;
    return env;
  }
}

/**
 * Format a tool_use block's input args into a one-line summary for
 * the verbose stream. Picks the field most useful per tool — file
 * path for Read, pattern for Glob/Grep, command for Bash — and elides
 * the rest. Long values are truncated so output stays readable on
 * narrow terminals.
 */
function formatToolArg(name: string, input: Record<string, unknown>): string {
  const pick = (key: string): string | undefined => {
    const v = input[key];
    return typeof v === "string" && v.length > 0 ? v : undefined;
  };
  let value: string | undefined;
  switch (name) {
    case "Read":
    case "Write":
    case "Edit":
      value = pick("file_path") ?? pick("path");
      break;
    case "Glob":
      value = pick("pattern");
      break;
    case "Grep":
      value = pick("pattern");
      break;
    case "Bash":
      value = pick("command");
      break;
    default:
      value = pick("path") ?? pick("file_path") ?? pick("pattern") ?? pick("command");
  }
  if (!value) return "";
  return value.length > 100 ? `${value.slice(0, 97)}…` : value;
}
