import type { CvssScore, Finding } from "@agentgg/core";
import { query } from "@anthropic-ai/claude-agent-sdk";
import type { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import {
  buildAgentPrompt,
  buildPreconditionPrompt,
  buildReconPrompt,
  DetectionResult,
  type Detector,
  hydrateFinding,
  PreconditionCheck,
  type PreconditionCheckArgs,
  type ReconArgs,
  ReconResult,
  type RunAgentArgs,
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

  async recon(args: ReconArgs & { signal?: AbortSignal }): Promise<ReconResult> {
    const prompt = buildReconPrompt({
      instructions: args.instructions,
      fingerprintTags: args.fingerprintTags,
      excludePatterns: args.excludePatterns,
      includePatterns: args.includePatterns,
      maxFileSizeKb: args.maxFileSizeKb,
    });
    // Tool-enabled survey with SDK-enforced structured output. Same
    // mechanism as hunt — the model explores with Read/Glob/Grep and the
    // final answer is constrained to the ReconResult schema.
    return this.runStructured({
      prompt,
      tools: ["Read", "Glob", "Grep"],
      maxTurns: args.maxTurns,
      cwd: args.rootDir,
      schema: ReconResult,
      signal: args.signal,
    });
  }

  async checkPrecondition(
    args: PreconditionCheckArgs & { signal?: AbortSignal },
  ): Promise<PreconditionCheck> {
    // Cheap single call, no tools — the recon brief is already in the
    // prompt, so the model just judges relevance.
    return this.runStructured({
      prompt: buildPreconditionPrompt(args),
      tools: [],
      maxTurns: 3,
      schema: PreconditionCheck,
      signal: args.signal,
    });
  }

  async runAgent(args: RunAgentArgs & { signal?: AbortSignal }): Promise<Finding[]> {
    const prompt = buildAgentPrompt(args);
    // Always tool-enabled. The model investigates the seeded candidate
    // files (or roams the repo when there are none), with SDK-enforced
    // structured output.
    const result = await this.runStructured({
      prompt,
      tools: ["Read", "Glob", "Grep"],
      maxTurns: args.maxTurns,
      cwd: args.rootDir,
      schema: DetectionResult,
      signal: args.signal,
    });
    const fallback = args.candidates[0]?.filePath ?? "(unknown)";
    return result.findings.map((f) => hydrateFinding(f, args.agent, f.filePath ?? fallback));
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
