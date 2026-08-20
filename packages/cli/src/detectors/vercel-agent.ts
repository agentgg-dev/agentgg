import { readdir, readFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import type { CvssScore, Finding, ReconReport } from "@agentgg/core";
import {
  generateObject,
  generateText,
  type LanguageModelV1,
  NoSuchToolError,
  type ToolCallRepairFunction,
  type ToolSet,
  tool,
} from "ai";
import { minimatch } from "minimatch";
import { z } from "zod";
import { AgentSpec } from "../agent-spec.js";
import { buildDedupePrompt, LlmDedup } from "../deduper.js";
import {
  buildAgentPrompt,
  buildCreateAgentPrompt,
  buildExcludePrompt,
  buildPreconditionPrompt,
  buildReconPrompt,
  type CreateAgentArgs,
  DetectionResult,
  type DetectionResult as DetectionResultType,
  type Detector,
  hydrateFinding,
  PreconditionCheck,
  type PreconditionCheckArgs,
  type ReconArgs,
  ReconResult,
  type RunAgentArgs,
  type SuggestExcludesArgs,
  SuggestExcludesResult,
} from "../detect.js";
import { asCvssScore, buildScorePrompt, LlmScore } from "../scoring.js";
import type { CallUsage, UsageMeter } from "../usage-meter.js";
import {
  asValidationField,
  buildScopeValidatePrompt,
  buildValidatePrompt,
  LlmValidation,
} from "../validator.js";
import { looksLikeRefusal } from "./refusal.js";

export type Effort = "low" | "medium" | "high" | "max";
export type Thinking = "off" | "adaptive" | "enabled";

/**
 * Parse the retry delay from a rate-limit error message. Different providers
 * embed the delay in different formats; we try each in turn.
 *
 *   - OpenAI: "Please try again in 1.5s"
 *   - Standard HTTP: "Retry-After: 60" (seconds)
 *   - Anthropic: "retry after: 60s"
 *
 * Returns milliseconds (with a 200ms buffer), or null when no pattern matches.
 */
export function parseRetryAfterMs(message: string): number | null {
  const tryAgain = message.match(/try again in ([\d.]+)s/i);
  if (tryAgain) return Math.ceil(parseFloat(tryAgain[1] as string) * 1000) + 200;
  const retryAfter = message.match(/retry[- ]?after[:\s]+([\d.]+)\s*s?\b/i);
  if (retryAfter) return Math.ceil(parseFloat(retryAfter[1] as string) * 1000) + 200;
  return null;
}

/**
 * Recognize a rate-limit / quota error across the providers we support.
 * The wording differs widely:
 *
 *   - OpenAI:    "Rate limit reached for ... tokens per minute"
 *   - Anthropic: "tpm" / "tokens-per-minute" mentions
 *   - Vertex:    "AI_RetryError: Failed after 3 attempts. Last error: Too Many Requests"
 *                (the underlying body says "429 Too Many Requests"; the Vercel AI
 *                SDK wraps it in an AI_RetryError after its own internal retries)
 *   - Vertex:    "RESOURCE_EXHAUSTED" (gRPC status code 8 surfaced as text)
 *   - Generic:   bare HTTP 429 / "Quota exceeded"
 *
 * Exported for unit-testing the matching set without spinning up `withTpmRetry`.
 */
export function isRateLimitError(message: string): boolean {
  if (/tokens per min/i.test(message)) return true;
  if (/\btpm\b/i.test(message)) return true;
  if (/too many requests/i.test(message)) return true;
  if (/\b429\b/.test(message)) return true;
  if (/AI_RetryError/.test(message)) return true;
  if (/RESOURCE_EXHAUSTED/.test(message)) return true;
  if (/quota exceeded/i.test(message)) return true;
  return false;
}

/**
 * Recognize a *transient* upstream/transport failure worth retrying with a
 * short backoff — distinct from a rate-limit (handled above) and from a
 * deterministic request error like context overflow (never retried).
 *
 * These are the Vertex MaaS gateway / network flakes seen in production: the
 * gateway returns HTTP 200 with a plain-text `upstream request timeout` body
 * (which the OpenAI-compatible parser rejects as "Invalid JSON response"),
 * drops the connection ("Headers Timeout", "Cannot connect to API"), or 5xxs.
 * A naive rerun usually clears them, so retrying in-process saves the agent.
 *
 * Run against the full error haystack (message + responseBody + cause), since
 * the actionable text often lives in the response body, not `err.message`.
 */
export function isTransientUpstreamError(message: string): boolean {
  if (/upstream request timeout/i.test(message)) return true;
  if (/invalid json response/i.test(message)) return true;
  if (/headers timeout/i.test(message)) return true;
  if (/cannot connect to api/i.test(message)) return true;
  if (/fetch failed/i.test(message)) return true;
  if (/socket hang ?up/i.test(message)) return true;
  if (/\b(?:ECONNRESET|ETIMEDOUT|ECONNREFUSED|EAI_AGAIN|EPIPE)\b/.test(message)) return true;
  if (/\bterminated\b/i.test(message)) return true;
  if (/service unavailable/i.test(message)) return true;
  if (/bad gateway/i.test(message)) return true;
  if (/gateway timeout/i.test(message)) return true;
  if (/\b50[234]\b/.test(message)) return true;
  // OpenRouter routes to third-party hosts; a routed provider being down
  // or flapping surfaces as one of these. All are re-routable on retry.
  if (/provider returned error/i.test(message)) return true;
  if (/no instances available/i.test(message)) return true;
  return false;
}

/**
 * Recognize a context-length overflow. The agent's accumulated tool transcript
 * (file contents) outgrew the model's context window, so the provider 400s.
 * This is DETERMINISTIC — re-sending the same oversized request just burns
 * another call — so `withTpmRetry` throws it straight through with a clearer
 * message instead of retrying. Prevention lives in the per-session tool-output
 * budget (see buildTools / TOOL_OUTPUT_BUDGET_BYTES).
 *
 *   - Vertex/GLM-5: "The input (207058 tokens) is longer than the model's
 *                    context length (202752 tokens)." (INVALID_ARGUMENT)
 *   - OpenAI:        "context_length_exceeded" / "maximum context length"
 *   - Anthropic:     "prompt is too long: N tokens > M maximum"
 */
export function isContextLengthError(message: string): boolean {
  if (/longer than the model'?s context length/i.test(message)) return true;
  if (/context[_ ]length[_ ]exceeded/i.test(message)) return true;
  if (/maximum context length/i.test(message)) return true;
  if (/exceeds the (?:maximum )?context window/i.test(message)) return true;
  if (/prompt is too long/i.test(message)) return true;
  if (/reduce the length/i.test(message)) return true;
  return false;
}

/**
 * Flatten an error into one searchable string: its message plus the fields the
 * Vercel AI SDK's APICallError hangs the useful detail off of (responseBody /
 * data / statusCode) plus its cause chain. The matchers above run against this,
 * not bare `err.message` — a context-overflow 400's message is only
 * "Bad Request"; the token-count detail lives in `responseBody`.
 */
function errorHaystack(err: unknown, depth = 0): string {
  if (depth > 3 || err == null) return String(err ?? "");
  if (typeof err !== "object") return String(err);
  const e = err as Record<string, unknown>;
  const parts: string[] = [];
  if (typeof e.message === "string") parts.push(e.message);
  if (typeof e.responseBody === "string") parts.push(e.responseBody);
  if (typeof e.data === "string") parts.push(e.data);
  else if (e.data && typeof e.data === "object") {
    try {
      parts.push(JSON.stringify(e.data));
    } catch {
      /* non-serializable */
    }
  }
  if (typeof e.statusCode === "number") parts.push(`status ${e.statusCode}`);
  if (e.cause != null && e.cause !== err) parts.push(errorHaystack(e.cause, depth + 1));
  return parts.join(" | ");
}

/** First non-empty line of an error haystack, trimmed for one-line logs and
 *  error messages. ASCII-only ("...") so it's safe in customer-facing copy. */
function firstErrorLine(hay: string): string {
  const line =
    hay
      .split("\n")
      .map((l) => l.trim())
      .find((l) => l.length > 0) ?? hay;
  return line.length > 200 ? `${line.slice(0, 200)}...` : line;
}

/** Default wait when the provider doesn't tell us how long to back off.
 *  Per-minute TPM buckets refill smoothly across the window — 30s typically
 *  frees enough capacity to fit one more call. 60s was the safe upper bound,
 *  but compounded badly across parallel batches (3 retries × 60s × N batches). */
const DEFAULT_BACKOFF_MS = 30_000;
const JITTER_FRACTION = 0.2; // ±20%

/** Base backoff for transient upstream/transport errors (timeouts, dropped
 *  connections, non-JSON gateway bodies). Far shorter than the rate-limit
 *  default — these clear in seconds, not a TPM-window — and grows
 *  exponentially per attempt, capped at TRANSIENT_BACKOFF_MAX_MS. */
const TRANSIENT_BACKOFF_MS = 2_000;
const TRANSIENT_BACKOFF_MAX_MS = 15_000;

/** Apply ±20% jitter around the base. Critical when N callers all 429 at the
 *  same instant — without jitter they'd all wake at exactly the same moment
 *  and re-trip the limit in lockstep. */
function jitter(baseMs: number): number {
  return Math.round(baseMs * (1 + (Math.random() - 0.5) * 2 * JITTER_FRACTION));
}

/**
 * Retry an LLM call on rate-limit errors (HTTP 429 / quota / TPM saturation).
 * Where the provider tells us how long to wait (OpenAI's "try again in Xs",
 * any Retry-After header echoed into the body), we honor that exactly;
 * otherwise we default to `DEFAULT_BACKOFF_MS` with ±20% jitter.
 * Non-rate-limit errors fall through immediately so the Vercel AI SDK's own
 * retry logic handles them.
 *
 * When `signal` is provided and fires during a backoff sleep, the sleep
 * is interrupted with an AbortError so a user-cancelled scan doesn't have
 * to wait out the window before exiting.
 *
 * NOTE: The previous version of this regex only matched `/tokens per min/i`
 * and `/tpm/i`, which silently NEVER fired on Vertex MaaS — Vertex 429s say
 * "Too Many Requests" with no "tpm"/"tokens per minute" wording. Calls that
 * tripped Vertex's fair-share TPM ceiling would burn 3 quick retries inside
 * the Vercel SDK (~7s exponential backoff) and give up, instead of waiting
 * out the window here. Broadened the matcher to catch those.
 */
async function withTpmRetry<T>(
  fn: () => Promise<T>,
  signal?: AbortSignal,
  maxAttempts = 4,
): Promise<T> {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    if (signal?.aborted) throw signal.reason ?? new Error("aborted");
    try {
      return await fn();
    } catch (err) {
      const hay = errorHaystack(err);
      // Context overflow is deterministic — re-sending the same oversized
      // request can't succeed. Surface a clear, non-retryable error instead of
      // the opaque "Bad Request" the provider returns.
      if (isContextLengthError(hay)) {
        throw new Error(`context length exceeded: ${firstErrorLine(hay)}`, { cause: err });
      }
      const rateLimited = isRateLimitError(hay);
      const transient = !rateLimited && isTransientUpstreamError(hay);
      if ((!rateLimited && !transient) || attempt >= maxAttempts) throw err;
      let waitMs: number;
      if (rateLimited) {
        // Honor a server-supplied delay precisely. Only jitter the blind default.
        const parsed = parseRetryAfterMs(hay);
        waitMs = parsed ?? jitter(DEFAULT_BACKOFF_MS);
        console.warn(
          `[withTpmRetry] rate-limit on attempt ${attempt}/${maxAttempts}, sleeping ${waitMs}ms (retryAfterParsed=${parsed != null})`,
        );
      } else {
        // Transient upstream/transport flake: short exponential backoff.
        const base = Math.min(TRANSIENT_BACKOFF_MS * 2 ** (attempt - 1), TRANSIENT_BACKOFF_MAX_MS);
        waitMs = jitter(base);
        console.warn(
          `[withTpmRetry] transient upstream error on attempt ${attempt}/${maxAttempts}, sleeping ${waitMs}ms: ${firstErrorLine(hay)}`,
        );
      }
      await abortableSleep(waitMs, signal);
    }
  }
  throw new Error("withTpmRetry: exhausted attempts");
}

/** setTimeout that resolves early when `signal` aborts. Rejects with the
 *  signal's reason on abort so the caller's try/catch sees an AbortError
 *  rather than a silent early-return from a still-pending backoff. */
function abortableSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason ?? new Error("aborted"));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      // `?.reason` is safe — this listener only fires when `signal`
      // exists (we gate the addEventListener below on `signal?.`),
      // but TS can't prove that across the closure boundary.
      reject(signal?.reason ?? new Error("aborted"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

type ProviderOptionsArg = {
  anthropic?: {
    thinking?: { type: "enabled" | "disabled"; budgetTokens?: number };
  };
  openai?: {
    reasoningEffort?: "low" | "medium" | "high";
  };
};

export interface VercelAgentDetectorOpts {
  providerKey?: "anthropic" | "openai" | "ollama";
  effort?: Effort;
  thinking?: Thinking;
  verbose?: boolean;
  /** Max tool-loop steps for the tool-enabled validateFinding path. Sourced
   *  from the `--validate-max-turns` CLI flag (same knob the claude detector
   *  uses); defaults to 50 when unset. */
  validateMaxTurns?: number;
  /** Model used to re-shape malformed final JSON from a tool-loop into the
   *  target schema (via strict `generateObject`). Defaults to the primary model
   *  when unset, so every provider recovers from a weak model's schema slip
   *  instead of dropping the whole batch. Ollama overrides it with its
   *  `structuredOutputs: true` config, which the tool-calling model can't use. */
  structuredModel?: LanguageModelV1;
}

// Directories skipped during recursive traversal
const SKIP_DIRS = new Set([
  "node_modules",
  "dist",
  "build",
  ".git",
  "vendor",
  "venv",
  ".venv",
  "__pycache__",
  ".next",
  ".nuxt",
]);

const GLOB_MAX_RESULTS = 500;
const GREP_MAX_MATCHES = 200;

/** Per-session cumulative cap on bytes returned by Read/Glob/Grep. The agent
 *  tool-loop transcript (mostly file contents) is what blows the model's
 *  context window: GLM-5's is 202,752 tokens, and we saw 207k-token overflows
 *  on large repos. ~400 KB of tool output is roughly 110-130k tokens of code,
 *  leaving headroom for the prompt, reasoning, and the JSON answer. Past the
 *  cap, further tool calls return a notice telling the model to finalize. */
const TOOL_OUTPUT_BUDGET_BYTES = 400_000;
/** Per-file cap so a single huge file can't dominate the budget in one Read.
 *  Truncated reads carry a notice pointing the model at Grep for specifics. */
const READ_FILE_OUTPUT_CAP_BYTES = 80_000;

/** Repairs allowed per LLM session. A model stuck in a malformed-tool-call
 *  loop would otherwise burn one repair call per turn for the whole turn
 *  budget. Past the cap the call is left broken and the batch degrades. */
const MAX_TOOL_CALL_REPAIRS = 5;

/**
 * Recover the tool the model MEANT to call from a mangled tool name.
 *
 * GLM-5 intermittently leaks its raw tool-call markup into the tool NAME
 * rather than the arguments, so `Grep` arrives as
 * `Grep<arg_value>pattern</arg_key><arg_value>get_owned_provider_...</arg_value>`
 * or `...</tool_call>Read`. The real name is always present as a substring, so
 * take the earliest one that occurs (leftmost wins: the name leads, the leaked
 * markup trails it).
 *
 * Returns null when nothing matches, which leaves the call unrepaired.
 */
export function resolveMangledToolName(mangled: string, available: string[]): string | null {
  if (available.includes(mangled)) return mangled;
  let best: { name: string; idx: number } | null = null;
  for (const name of available) {
    const idx = mangled.indexOf(name);
    if (idx < 0) continue;
    // Leftmost wins; on a tie prefer the longer name so `Read` can't shadow a
    // hypothetical `ReadMany`.
    if (best === null || idx < best.idx || (idx === best.idx && name.length > best.name.length)) {
      best = { name, idx };
    }
  }
  return best?.name ?? null;
}

/**
 * Detector backed by the Vercel AI SDK's `generateText` for hunt/walker
 * modes (with Read/Glob/Grep tool implementations) and `generateObject`
 * for file mode and validation. Works with any Vercel AI SDK provider —
 * OpenAI, Ollama, etc. — that supports function/tool calling.
 */
export class VercelAgentDetector implements Detector {
  readonly name: string;
  private readonly model: LanguageModelV1;
  private readonly structuredModel?: LanguageModelV1;
  private readonly providerKey?: "anthropic" | "openai" | "ollama";
  private readonly effort?: Effort;
  private readonly thinking?: Thinking;
  private readonly verbose: boolean;
  private readonly validateMaxTurns: number;
  /** Object-generation mode for `generateObject`. Bedrock's SDK only supports
   *  tool-mode; every other provider we drive supports json mode. */
  private readonly objectMode: "json" | "tool";
  private meter?: UsageMeter;

  constructor(name: string, model: LanguageModelV1, opts: VercelAgentDetectorOpts = {}) {
    this.name = name;
    this.model = model;
    // Default the reformat model to the primary one, so openai/bedrock/vertex
    // recover from unparseable tool-loop JSON the same way ollama does (ollama
    // passes a distinct structuredOutputs model explicitly).
    this.structuredModel = opts.structuredModel ?? model;
    // @ai-sdk/amazon-bedrock rejects json-mode object generation (it throws
    // UnsupportedFunctionalityError) and supports only tool-mode; drive Bedrock
    // through tool-mode and leave every other provider on json (unchanged).
    this.objectMode = name === "bedrock" ? "tool" : "json";
    this.providerKey = opts.providerKey ?? derivedProviderKey(name);
    this.effort = opts.effort;
    this.thinking = opts.thinking;
    this.verbose = opts.verbose ?? false;
    this.validateMaxTurns = opts.validateMaxTurns ?? 50;
  }

  attachUsageMeter(meter: UsageMeter): void {
    this.meter = meter;
  }

  /**
   * Run one LLM call through the TPM-retry wrapper, then record its token
   * usage into the attached meter (a no-op when no meter is attached). Every
   * `generateObject` / `generateText` call funnels through here so usage
   * capture lives in exactly one place.
   */
  private async metered<T>(run: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    const result = await withTpmRetry(run, signal);
    this.meter?.record(extractCallUsage(result), this.model.modelId);
    return result;
  }

  /**
   * Repair a malformed tool call instead of letting it kill the batch.
   *
   * WHY: a tool call the SDK can't parse throws out of `generateText`
   * (`AI_NoSuchToolError` / `AI_InvalidToolArgumentsError`), which fails the
   * batch, which sets `rt.failed`, which means the agent never gets its resume
   * sidecar — so the platform marks the WHOLE agent failed even though its
   * other batches found real issues. One bad turn should not cost an agent.
   * Prod scan 764dbd1d lost three agents this way.
   *
   * Two steps, cheapest first:
   *   1. Name. `NoSuchToolError` means the name itself is garbage; the real one
   *      is a substring (see `resolveMangledToolName`). Free.
   *   2. Arguments. Re-ask the model for arguments that satisfy the tool's own
   *      schema, given its broken attempt. One small call, capped per session.
   *
   * Returns null when neither step lands. The SDK then throws as before, so
   * this only ever adds recoveries.
   *
   * Returned per call site, not shared: the repair budget is per LLM session.
   */
  private toolCallRepair(label: string): ToolCallRepairFunction<ToolSet> {
    let repairs = 0;
    return async ({ toolCall, tools, error }) => {
      const names = Object.keys(tools);
      const toolName = NoSuchToolError.isInstance(error)
        ? resolveMangledToolName(toolCall.toolName, names)
        : toolCall.toolName;
      if (toolName === null || !names.includes(toolName)) return null;
      if (repairs >= MAX_TOOL_CALL_REPAIRS) {
        console.warn(`    ${label}: tool-call repair budget spent, leaving the call broken`);
        return null;
      }
      repairs++;
      const schema = (tools[toolName] as { parameters: z.ZodTypeAny }).parameters;
      try {
        const { object } = await generateObject({
          model: this.structuredModel ?? this.model,
          schema,
          mode: this.objectMode,
          prompt:
            `You called the tool \`${toolName}\` with arguments that do not match its schema.\n` +
            `Reply with corrected arguments for the SAME intent.\n\n` +
            `What you sent as the tool name:\n${toolCall.toolName}\n\n` +
            `What you sent as the arguments:\n${toolCall.args}\n\n` +
            `Schema error:\n${error.message}`,
        });
        console.warn(`    ${label}: repaired a malformed ${toolName} call`);
        return { ...toolCall, toolName, args: JSON.stringify(object) };
      } catch {
        // The repair call itself failed. Fall through to the original error
        // rather than masking it with a repair-time one.
        return null;
      }
    };
  }

  async recon(args: ReconArgs & { signal?: AbortSignal }): Promise<ReconResult> {
    const basePrompt = buildReconPrompt({
      instructions: args.instructions,
      fingerprintTags: args.fingerprintTags,
      excludePatterns: args.excludePatterns,
      includePatterns: args.includePatterns,
      maxFileSizeKb: args.maxFileSizeKb,
    });
    const prompt = `${basePrompt}\n\n${reconJsonInstruction()}`;
    try {
      const { text } = await this.metered(
        () =>
          generateText({
            model: this.model,
            prompt,
            tools: buildTools(
              resolve(args.rootDir),
              args.maxFileSizeKb,
              this.verbose,
              args.excludePatterns,
            ),
            maxSteps: args.maxTurns + 1,
            experimental_repairToolCall: this.toolCallRepair("recon"),
            providerOptions: this.providerOptionsArg(),
            abortSignal: args.signal,
          }),
        args.signal,
      );
      return await this.parseRecon(text, args.signal);
    } catch (err) {
      debugLog("VercelAgentDetector.recon", err);
      throw err;
    }
  }

  async suggestExcludes(
    args: SuggestExcludesArgs & { signal?: AbortSignal },
  ): Promise<SuggestExcludesResult> {
    // No-tools structured call: the directory tree is in the prompt, so
    // the model classifies folders directly (same shape as scoreFinding).
    try {
      const { object } = await this.metered(
        () =>
          generateObject({
            model: this.model,
            schema: SuggestExcludesResult,
            mode: this.objectMode,
            prompt: buildExcludePrompt(args),
            providerOptions: this.providerOptionsArg(),
            abortSignal: args.signal,
          }),
        args.signal,
      );
      return object;
    } catch (err) {
      debugLog("VercelAgentDetector.suggestExcludes", err);
      throw err;
    }
  }

  async createAgent(args: CreateAgentArgs & { signal?: AbortSignal }): Promise<AgentSpec> {
    const basePrompt = buildCreateAgentPrompt({
      instructions: args.instructions,
      reportName: args.reportName,
      reportContent: args.reportContent,
      excludePatterns: args.excludePatterns,
      includePatterns: args.includePatterns,
      maxFileSizeKb: args.maxFileSizeKb,
    });
    const prompt = `${basePrompt}\n\n${createAgentJsonInstruction()}`;
    try {
      const { text } = await this.metered(
        () =>
          generateText({
            model: this.model,
            prompt,
            tools: buildTools(
              resolve(args.rootDir),
              args.maxFileSizeKb,
              this.verbose,
              args.excludePatterns,
            ),
            maxSteps: args.maxTurns + 1,
            experimental_repairToolCall: this.toolCallRepair("createAgent"),
            providerOptions: this.providerOptionsArg(),
            abortSignal: args.signal,
          }),
        args.signal,
      );
      return await this.parseAgentSpec(text, args.signal);
    } catch (err) {
      debugLog("VercelAgentDetector.createAgent", err);
      throw err;
    }
  }

  async runAgent(args: RunAgentArgs & { signal?: AbortSignal }): Promise<Finding[]> {
    const base = buildAgentPrompt(args);
    const prompt = `${base}\n\n${jsonOutputInstruction(false)}`;
    const label = `runAgent:${args.agent.slug}`;
    const hunt = (budgetBytes: number, maxTurns: number) =>
      this.metered(
        () =>
          generateText({
            model: this.model,
            prompt,
            tools: buildTools(
              resolve(args.rootDir),
              args.maxFileSizeKb,
              this.verbose,
              args.excludePatterns,
              budgetBytes,
            ),
            maxSteps: maxTurns + 1,
            experimental_repairToolCall: this.toolCallRepair(label),
            providerOptions: this.providerOptionsArg(),
            abortSignal: args.signal,
          }),
        args.signal,
      );
    try {
      let gen: Awaited<ReturnType<typeof hunt>>;
      let effectiveTurns = args.maxTurns;
      try {
        gen = await hunt(TOOL_OUTPUT_BUDGET_BYTES, effectiveTurns);
      } catch (err) {
        // Context overflow: the accumulated tool transcript outgrew the window.
        // Re-sending it unchanged can't work, which is why withTpmRetry refuses
        // to retry — but a SMALLER hunt can. The transcript grows with both the
        // bytes read and the number of turns those bytes get re-sent across, so
        // halve each. Once only: a second overflow means the batch itself is too
        // big for this model, and that is a planning problem, not a retry one.
        if (!isContextLengthError(errorHaystack(err)) || args.signal?.aborted === true) throw err;
        console.warn(
          `    ${label}: context overflow; retrying this batch at half the read budget and turn cap`,
        );
        effectiveTurns = Math.floor(args.maxTurns / 2);
        gen = await hunt(Math.floor(TOOL_OUTPUT_BUDGET_BYTES / 2), effectiveTurns);
      }
      // The tool loop can burn its whole budget without ever emitting findings
      // JSON — typically the model degenerates into repeating one tool call.
      // The reformat fallback below turns that into a valid empty result, so
      // without this line a capped batch is indistinguishable from clean code.
      // Warn only: a capped batch still records 0 findings and the agent still
      // completes, so one bad batch never fails the scan.
      warnIfTurnCapped(args.agent.slug, gen, effectiveTurns);
      let result: DetectionResultType;
      try {
        result = await this.parseOrReformat(gen.text, false, args.signal);
      } catch (parseErr) {
        // Empty / unparseable final message. Emit a one-line diagnostic
        // (always, not gated on AGENTGG_DEBUG) so the logs show WHY: an empty
        // completion, a length cutoff, or reasoning that never produced
        // visible content. See logUnparseableGeneration.
        logUnparseableGeneration(`runAgent:${args.agent.slug}`, gen);
        // A content refusal lands here as prose instead of findings JSON. Treat
        // it as an empty result, not an agent failure: the batch yields 0
        // findings, the agent still completes, and the refusal doesn't crash
        // the agent or count against the scan's failure ratio. A non-refusal
        // parse failure (empty completion, length cutoff, garbage) still throws.
        if (looksLikeRefusal(gen.text)) {
          console.warn(
            `[runAgent:${args.agent.slug}] model refused to analyze this batch; recording 0 findings`,
          );
          return [];
        }
        throw parseErr;
      }
      const fallback = args.candidates[0]?.filePath ?? "(unknown)";
      return result.findings.map((f) => hydrateFinding(f, args.agent, f.filePath ?? fallback));
    } catch (err) {
      debugLog("VercelAgentDetector.runAgent", err);
      throw err;
    }
  }

  async checkPrecondition(
    args: PreconditionCheckArgs & { signal?: AbortSignal },
  ): Promise<PreconditionCheck> {
    try {
      const { object } = await this.metered(
        () =>
          generateObject({
            model: this.model,
            schema: PreconditionCheck,
            mode: this.objectMode,
            prompt: buildPreconditionPrompt(args),
            providerOptions: this.providerOptionsArg(),
            abortSignal: args.signal,
          }),
        args.signal,
      );
      return object;
    } catch (err) {
      debugLog("VercelAgentDetector.checkPrecondition", err);
      throw err;
    }
  }

  async validateFinding(args: {
    finding: Finding;
    fileContent: string;
    scope?: string;
    root?: string;
    excludePatterns?: string[];
    maxFileSizeKb?: number;
    signal?: AbortSignal;
  }) {
    try {
      // Single-shot path (no root): judge the embedded file content only.
      if (!args.root) {
        const { object } = await this.metered(
          () =>
            generateObject({
              model: this.model,
              schema: LlmValidation,
              mode: this.objectMode,
              prompt: buildValidatePrompt(args),
              providerOptions: this.providerOptionsArg(),
              abortSignal: args.signal,
            }),
          args.signal,
        );
        return asValidationField(object);
      }
      // Tool-enabled path: same generateText + tool-loop shape as hunt
      // (runAgent), so the validator can Read/Glob/Grep across files to
      // trace the exploit chain. Structured output is recovered from the
      // final message via parseValidation (with a structuredModel reformat
      // fallback), because this SDK can't combine tools with generateObject.
      // Same exclude / size knobs as the hunt so validation and detection
      // see the same file set.
      const prompt = `${buildValidatePrompt(args)}\n\n${validationJsonInstruction()}`;
      const gen = await this.metered(
        () =>
          generateText({
            model: this.model,
            prompt,
            tools: buildTools(
              resolve(args.root as string),
              args.maxFileSizeKb,
              this.verbose,
              args.excludePatterns ?? [],
            ),
            maxSteps: this.validateMaxTurns + 1,
            experimental_repairToolCall: this.toolCallRepair(`validate:${args.finding.id}`),
            providerOptions: this.providerOptionsArg(),
            abortSignal: args.signal,
          }),
        args.signal,
      );
      return await this.parseValidation(gen.text, args.finding.id, args.signal);
    } catch (err) {
      debugLog("VercelAgentDetector.validateFinding", err);
      throw err;
    }
  }

  async validateFindingByScope(args: { finding: Finding; scope: string; signal?: AbortSignal }) {
    try {
      const { object } = await this.metered(
        () =>
          generateObject({
            model: this.model,
            schema: LlmValidation,
            mode: this.objectMode,
            prompt: buildScopeValidatePrompt(args),
            providerOptions: this.providerOptionsArg(),
            abortSignal: args.signal,
          }),
        args.signal,
      );
      return asValidationField(object);
    } catch (err) {
      debugLog("VercelAgentDetector.validateFindingByScope", err);
      throw err;
    }
  }

  async scoreFinding(args: {
    finding: Finding;
    fileContent: string;
    recon?: ReconReport;
    signal?: AbortSignal;
  }): Promise<CvssScore> {
    try {
      const { object } = await this.metered(
        () =>
          generateObject({
            model: this.model,
            schema: LlmScore,
            mode: this.objectMode,
            prompt: buildScorePrompt(args),
            providerOptions: this.providerOptionsArg(),
            abortSignal: args.signal,
          }),
        args.signal,
      );
      return asCvssScore(object);
    } catch (err) {
      debugLog("VercelAgentDetector.scoreFinding", err);
      throw err;
    }
  }

  async dedupeFindings(args: {
    filePath: string;
    findings: Finding[];
    fileContent?: string;
    signal?: AbortSignal;
  }): Promise<LlmDedup["clusters"]> {
    try {
      const { object } = await this.metered(
        () =>
          generateObject({
            model: this.model,
            schema: LlmDedup,
            mode: this.objectMode,
            prompt: buildDedupePrompt(args),
            providerOptions: this.providerOptionsArg(),
            abortSignal: args.signal,
          }),
        args.signal,
      );
      return object.clusters;
    } catch (err) {
      debugLog("VercelAgentDetector.dedupeFindings", err);
      throw err;
    }
  }

  /** Parse findings from the tool-loop's final text. If extraction fails and a
   *  structuredModel is configured, re-asks that model (with JSON mode) to
   *  reformat the raw analysis into the required schema. The reformat call
   *  is also a real LLM request, so it carries the scan's abort signal too. */
  private async parseOrReformat(
    text: string,
    multiAgent: boolean,
    signal?: AbortSignal,
  ): Promise<DetectionResultType> {
    try {
      return DetectionResult.parse(extractJSON(text));
    } catch (extractErr) {
      if (!this.structuredModel) throw extractErr;
      const reformat = await generateObject({
        model: this.structuredModel,
        schema: DetectionResult,
        mode: this.objectMode,
        prompt: `The following is a completed security analysis. Extract all confirmed findings into structured JSON.\n\n${text}\n\n${jsonOutputInstruction(multiAgent)}`,
        abortSignal: signal,
      });
      this.meter?.record(extractCallUsage(reformat), this.structuredModel.modelId);
      return reformat.object;
    }
  }

  /** Parse a validation verdict from the tool-loop's final text. A content
   *  refusal (the model declining to validate) is recorded as an
   *  `uncertain`+`refused` outcome instead of being coerced through the
   *  structured reformat into a bogus verdict — so the refusal is tracked, not
   *  silently mislabeled. It does NOT fail the finding: it stays unvalidated.
   *  Non-refusal parse failures still reformat via structuredModel. */
  private async parseValidation(
    text: string,
    findingId: string,
    signal?: AbortSignal,
  ): Promise<{
    verdict: "confirmed" | "false-positive" | "out-of-scope" | "uncertain";
    reasoning: string;
    refused?: boolean;
  }> {
    try {
      return asValidationField(LlmValidation.parse(extractJSON(text)));
    } catch (extractErr) {
      if (looksLikeRefusal(text)) {
        console.warn(
          `[validate:${findingId}] model refused to validate; recording uncertain+refused`,
        );
        return {
          verdict: "uncertain",
          reasoning: "Model declined to validate this finding (refusal).",
          refused: true,
        };
      }
      if (!this.structuredModel) throw extractErr;
      const reformat = await generateObject({
        model: this.structuredModel,
        schema: LlmValidation,
        mode: this.objectMode,
        prompt: `The following is a completed validation of a security finding. Extract the verdict into structured JSON.\n\n${text}\n\n${validationJsonInstruction()}`,
        abortSignal: signal,
      });
      this.meter?.record(extractCallUsage(reformat), this.structuredModel.modelId);
      return asValidationField(reformat.object);
    }
  }

  /** Parse an AgentSpec from the tool-loop's final text, with a
   *  structuredModel reformat fallback (Ollama best-effort). */
  private async parseAgentSpec(text: string, signal?: AbortSignal): Promise<AgentSpec> {
    try {
      return AgentSpec.parse(extractJSON(text));
    } catch (extractErr) {
      if (!this.structuredModel) throw extractErr;
      const reformat = await generateObject({
        model: this.structuredModel,
        schema: AgentSpec,
        mode: this.objectMode,
        prompt: `The following is a completed analysis distilling a past security incident into an agentgg agent spec. Extract it into the AgentSpec JSON shape.\n\n${text}\n\n${createAgentJsonInstruction()}`,
        abortSignal: signal,
      });
      this.meter?.record(extractCallUsage(reformat), this.structuredModel.modelId);
      return reformat.object;
    }
  }

  /** Parse a ReconResult from the tool-loop's final text, with a
   *  structuredModel reformat fallback (Ollama best-effort). */
  private async parseRecon(text: string, signal?: AbortSignal): Promise<ReconResult> {
    try {
      return ReconResult.parse(extractJSON(text));
    } catch (extractErr) {
      if (!this.structuredModel) throw extractErr;
      const reformat = await generateObject({
        model: this.structuredModel,
        schema: ReconResult,
        mode: this.objectMode,
        prompt: `The following is a completed recon survey of a codebase. Extract it into structured JSON.\n\n${text}\n\n${reconJsonInstruction()}`,
        abortSignal: signal,
      });
      this.meter?.record(extractCallUsage(reformat), this.structuredModel.modelId);
      return reformat.object;
    }
  }

  private providerOptionsArg(): ProviderOptionsArg | undefined {
    if (!this.providerKey) return undefined;

    if (this.providerKey === "anthropic") {
      if (!this.thinking) return undefined;
      const type: "enabled" | "disabled" = this.thinking === "off" ? "disabled" : "enabled";
      return { anthropic: { thinking: { type } } };
    }

    if (this.providerKey === "openai") {
      if (!this.effort) return undefined;
      const reasoningEffort: "low" | "medium" | "high" =
        this.effort === "max" ? "high" : this.effort;
      return { openai: { reasoningEffort } };
    }

    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

/**
 * Grep's argument schema. `glob` and `path` are nullable-but-REQUIRED, and a
 * missing key is filled in as null, because the two providers pull in opposite
 * directions:
 *
 * - OpenAI reasoning models get `strict: true` function schemas by default in
 *   @ai-sdk/openai, and strict mode rejects the whole tool (HTTP 400) unless
 *   every key in `properties` is also in `required`. An `.optional()` field
 *   fails every request, so scoping has to be expressed as `string | null`.
 * - Non-strict providers omit the key instead: GLM-5 calls `Grep({pattern})`
 *   on its own, and a rejected call burns a turn and returns nothing. The
 *   preprocess defaults the absent keys rather than failing the call.
 *
 * `path` is an alias for `glob` because the model reaches for the sibling Read
 * tool's parameter name.
 */
export const GrepParameters = z.preprocess(
  (v) => (typeof v === "object" && v !== null ? { glob: null, path: null, ...v } : v),
  z.object({
    pattern: z.string().describe("Regular expression to search for"),
    glob: z
      .string()
      .nullable()
      .describe(
        "Glob restricting which files are searched, e.g. '**/*.ts'. Pass null to search all files.",
      ),
    path: z
      .string()
      .nullable()
      .describe(
        "File or directory path to search under, relative to the repository root. Alias for `glob`. Pass null to search all files.",
      ),
  }),
);

function buildTools(
  cwd: string,
  maxFileSizeKb: number | undefined,
  verbose: boolean,
  exclude: string[] = [],
  budgetBytes: number = TOOL_OUTPUT_BUDGET_BYTES,
) {
  const logTool = verbose
    ? (name: string, arg: string) => console.log(`    ${name} ${arg.slice(0, 100)}`)
    : () => undefined;

  // Per-session tool-output budget, shared across every tool call in this
  // generateText loop (buildTools is constructed once per LLM session) so the
  // running transcript can't outgrow the model's context window. A fresh
  // buildTools — and thus a fresh budget — is created on each retry.
  let bytesReturned = 0;
  const budgetExhausted = () => bytesReturned >= budgetBytes;
  const account = (out: string): string => {
    bytesReturned += out.length;
    return out;
  };

  return {
    Read: tool({
      description: "Read the contents of a file. Path must be relative to the repository root.",
      parameters: z.object({
        path: z.string().describe("File path relative to the repository root"),
      }),
      execute: async ({ path }) => {
        logTool("Read", path);
        if (budgetExhausted()) return budgetNotice(budgetBytes);
        return account(await readToolExecute(path, cwd, maxFileSizeKb, exclude));
      },
    }),
    Glob: tool({
      description:
        "Find files matching a glob pattern. Returns paths relative to the repository root.",
      parameters: z.object({
        pattern: z.string().describe("Glob pattern, e.g. '**/*.ts' or 'src/**/*.js'"),
      }),
      execute: async ({ pattern }) => {
        logTool("Glob", pattern);
        if (budgetExhausted()) return budgetNotice(budgetBytes);
        return account(await globToolExecute(pattern, cwd, exclude));
      },
    }),
    Grep: tool({
      description:
        "Search for a regex pattern across files. Returns matching lines as 'file:line: content'.",
      parameters: GrepParameters,
      execute: async ({ pattern, glob, path }) => {
        logTool("Grep", pattern);
        if (budgetExhausted()) return budgetNotice(budgetBytes);
        // A bare directory path is not a glob — `src/api` matches that one
        // entry, not the files under it — so widen it before handing it over.
        const scope = glob || (path ? toSearchGlob(path) : undefined);
        return account(await grepToolExecute(pattern, scope, cwd, exclude));
      },
    }),
  };
}

/**
 * Widen a `path` argument into a glob that matches the path itself AND anything
 * beneath it, so `Grep({path: "ghost/core"})` searches the directory rather than
 * matching nothing.
 *
 * The brace form is what makes this work without a stat: `walkAndMatch` only
 * ever tests FILE paths, so a bare directory name matches zero of them, and its
 * `matchBase` shortcut would additionally reinterpret a slash-less path as a
 * basename match against every file in the tree. Emitting a two-arm brace keeps
 * both readings correct and always contains a `/`, which disables matchBase.
 * Left alone when the caller already passed a glob.
 */
export function toSearchGlob(path: string): string {
  const trimmed = path.replace(/\/+$/, "");
  if (trimmed === "") return "**/*";
  if (/[*?[\]{}]/.test(trimmed)) return trimmed;
  return `{${trimmed},${trimmed}/**}`;
}

/** Returned by every tool once the per-session output budget is spent — an
 *  explicit instruction to stop reading and emit findings now, rather than a
 *  silent empty result the model might keep probing against. */
function budgetNotice(budgetBytes: number): string {
  return (
    `Error: per-session read budget reached (~${Math.round(budgetBytes / 1024)} KB). ` +
    `Do not read more files. Output your final findings JSON now, based on what you have already examined.`
  );
}

/** A path is excluded (treated as deleted) when it matches any exclude
 *  glob. Directory globs are also tested with a trailing `/**` stripped so
 *  the directory itself and its contents are both blocked. */
function isExcludedPath(rel: string, exclude: string[]): boolean {
  return exclude.some((p) => {
    if (minimatch(rel, p, { dot: true })) return true;
    const base = p.replace(/\/\*\*?$/, "").replace(/\/+$/, "");
    return base !== p && (rel === base || minimatch(rel, `${base}/**`, { dot: true }));
  });
}

async function readToolExecute(
  path: string,
  cwd: string,
  maxFileSizeKb: number | undefined,
  exclude: string[] = [],
): Promise<string> {
  try {
    const absolutePath = resolve(cwd, path);
    if (!isSafe(absolutePath, cwd)) {
      return "Error: Access denied. Path must be within the repository root.";
    }
    if (isExcludedPath(normalizeSep(relative(cwd, absolutePath)), exclude)) {
      return "Error: This path is excluded from the scan (treated as not present).";
    }
    if (maxFileSizeKb !== undefined) {
      const { stat } = await import("node:fs/promises");
      const s = await stat(absolutePath).catch(() => null);
      if (s && s.size > maxFileSizeKb * 1024) {
        return `Error: File exceeds size limit (${Math.round(s.size / 1024)}KB > ${maxFileSizeKb}KB). Skipped.`;
      }
    }
    const content = await readFile(absolutePath, "utf-8");
    if (content.length > READ_FILE_OUTPUT_CAP_BYTES) {
      return (
        `${content.slice(0, READ_FILE_OUTPUT_CAP_BYTES)}\n\n` +
        `... [truncated: file is ${Math.round(content.length / 1024)} KB; showing the first ` +
        `${Math.round(READ_FILE_OUTPUT_CAP_BYTES / 1024)} KB. Use Grep to locate specific lines.]`
      );
    }
    return content;
  } catch (err) {
    return `Error reading file: ${(err as Error).message}`;
  }
}

async function globToolExecute(
  pattern: string,
  cwd: string,
  exclude: string[] = [],
): Promise<string> {
  try {
    const results = await walkAndMatch(cwd, pattern, GLOB_MAX_RESULTS, exclude);
    if (results.length === 0) return "(no matches)";
    const out = results.join("\n");
    return results.length >= GLOB_MAX_RESULTS
      ? `${out}\n(truncated at ${GLOB_MAX_RESULTS} results)`
      : out;
  } catch (err) {
    return `Error: ${(err as Error).message}`;
  }
}

async function grepToolExecute(
  pattern: string,
  glob: string | undefined,
  cwd: string,
  exclude: string[] = [],
): Promise<string> {
  let regex: RegExp;
  try {
    regex = new RegExp(pattern);
  } catch {
    return `Error: Invalid regex pattern: ${pattern}`;
  }

  try {
    const files = await walkAndMatch(cwd, glob ?? "**/*", GLOB_MAX_RESULTS, exclude);
    const results: string[] = [];

    for (const file of files) {
      if (results.length >= GREP_MAX_MATCHES) break;
      try {
        const content = await readFile(join(cwd, file), "utf-8");
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          if (results.length >= GREP_MAX_MATCHES) break;
          if (regex.test(lines[i])) {
            results.push(`${file}:${i + 1}: ${lines[i].trimEnd()}`);
          }
        }
      } catch {
        // skip unreadable files
      }
    }

    if (results.length === 0) return "(no matches)";
    const out = results.join("\n");
    return results.length >= GREP_MAX_MATCHES
      ? `${out}\n(truncated at ${GREP_MAX_MATCHES} matches)`
      : out;
  } catch (err) {
    return `Error: ${(err as Error).message}`;
  }
}

async function walkAndMatch(
  rootDir: string,
  pattern: string,
  maxResults: number,
  exclude: string[] = [],
): Promise<string[]> {
  const results: string[] = [];

  async function walk(dir: string): Promise<void> {
    if (results.length >= maxResults) return;
    const entries = await readdir(dir, { withFileTypes: true }).catch(() => null);
    if (!entries) return;
    for (const entry of entries) {
      if (results.length >= maxResults) break;
      if (entry.name.startsWith(".") || SKIP_DIRS.has(entry.name)) continue;
      const fullPath = join(dir, entry.name);
      const relPath = normalizeSep(relative(rootDir, fullPath));
      // Excluded paths are treated as deleted — never descended or matched.
      if (isExcludedPath(relPath, exclude)) continue;
      if (entry.isDirectory()) {
        await walk(fullPath);
      } else {
        const matchOpts = { dot: true, matchBase: !pattern.includes("/") };
        if (minimatch(relPath, pattern, matchOpts)) {
          results.push(relPath);
        }
      }
    }
  }

  await walk(rootDir);
  return results;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isSafe(absolutePath: string, cwd: string): boolean {
  const a = normalizeSep(absolutePath).toLowerCase();
  const b = normalizeSep(cwd).toLowerCase();
  return a.startsWith(b);
}

function normalizeSep(p: string): string {
  return p.replace(/\\/g, "/");
}

function derivedProviderKey(name: string): "anthropic" | "openai" | "ollama" | undefined {
  if (name.startsWith("anthropic")) return "anthropic";
  if (name.startsWith("openai")) return "openai";
  if (name.startsWith("ollama")) return "ollama";
  return undefined;
}

function validationJsonInstruction(): string {
  return `## Output format

After tracing the finding across the code, output your verdict as a single JSON object matching EXACTLY this shape — no prose, no markdown fences, no trailing text:

{"verdict":"confirmed","reasoning":"Short reasoning citing a specific code element.","confidence":0.9}

\`verdict\` MUST be one of "confirmed", "false-positive", "out-of-scope", or "uncertain". \`confidence\` is a decimal 0.0–1.0 (not a percentage).`;
}

function jsonOutputInstruction(multiAgent: boolean): string {
  const agentSlugNote = multiAgent
    ? "Set `agentSlug` to the slug of the detection brief whose criteria the finding satisfies."
    : "Set `agentSlug` to `null` — the runtime stamps the calling agent's slug.";
  return `## Output format

After your investigation, output ALL findings as a single JSON object matching EXACTLY this shape — no prose, no markdown fences, no trailing text:

{"findings":[{"title":"Short title","vulnSlug":"vuln-class","agentSlug":null,"lineRange":[1,10],"filePath":"src/routes/users.ts","summary":"One sentence.","details":"Markdown analysis with file paths and line numbers.","poc":"Reproduction steps.","impact":"Who is affected and what they get.","references":[],"confidence":0.9}]}

IMPORTANT: Every \`filePath\` must be a real file path you actually read or located with tools during this session. Do NOT copy the example path above — replace it with the actual path from your investigation. If no findings, output exactly: {"findings":[]}

${agentSlugNote}`;
}

function createAgentJsonInstruction(): string {
  return `## Output format

After your investigation, output the agent spec as a single JSON object matching EXACTLY this shape — no prose, no markdown fences, no trailing text:

{"slug":"kebab-case-slug","name":"Short name","description":"One-line description of the anti-pattern.","noiseTier":"normal","references":["CWE-89"],"precondition":{"regex":{"extensions":["ts"],"files":[],"directories":[],"patterns":[]}},"where":{"extensions":["ts","tsx"],"filePatterns":[],"excludePatterns":["**/__tests__/**"],"preFilter":[{"regex":"\\\\.query\\\\s*\\\\(","label":"raw SQL call"}],"maxFilesPerBatch":5,"maxTurnsPerBatch":50},"prompt":"Markdown body of the agent's instructions."}

Every regex MUST be a valid JavaScript RegExp. The slug MUST match ^[a-z0-9][a-z0-9-]*$. Omit precondition entirely if the agent should always run; include the where object (at minimum with extensions).`;
}

function reconJsonInstruction(): string {
  return `## Output format

After your survey, output the brief as a single JSON object matching EXACTLY this shape — no prose, no markdown fences, no trailing text:

{"purpose":"What this project is and does, 1-3 sentences.","languages":["typescript"],"frameworks":["next.js"],"authModel":"How auth works, or null.","integrations":["postgres","stripe"],"notableDirs":["src/api"],"summary":"A few short paragraphs orienting a security reviewer."}

Keep every field short. Use [] for empty lists and null for an unknown authModel. Do NOT report vulnerabilities — this is orientation only.`;
}

function extractJSON(text: string): unknown {
  // 1. Fenced JSON block
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
  if (fenced) {
    try {
      return JSON.parse(fenced[1]);
    } catch {
      /* fall through */
    }
  }
  // 2. Last valid JSON object starting from each '{' — go backwards for the final answer
  const positions: number[] = [];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "{") positions.push(i);
  }
  for (let i = positions.length - 1; i >= 0; i--) {
    try {
      return JSON.parse(text.slice(positions[i]));
    } catch {
      /* fall through */
    }
  }
  // 3. Whole text
  try {
    return JSON.parse(text.trim());
  } catch {
    /* fall through */
  }

  throw new Error(
    `VercelAgentDetector: could not extract JSON findings from model response. ` +
      `First 400 chars: ${text.slice(0, 400)}`,
  );
}

async function debugLog(label: string, err: unknown): Promise<void> {
  if (!process.env.AGENTGG_DEBUG) return;
  const util = await import("node:util");
  console.error(`---- ${label} error ----`);
  console.error(util.inspect(err, { depth: 5, colors: false }));
  console.error("------------------------");
}

/**
 * Pull normalized token counts out of a Vercel AI SDK result. Reads the
 * documented `usage` shape ({ promptTokens, completionTokens }) and the
 * provider metadata's cache figure when present — OpenAI-compatible surfaces
 * (OpenRouter, OpenAI, Vertex MaaS) report it under
 * `providerMetadata.openai.cachedPromptTokens`. Bedrock and ollama never
 * report one and stay at 0.
 *
 * Cache is summed PER STEP, not read off the result: `usage` is cumulative
 * across a tool loop while `providerMetadata` is the final step's alone, so
 * the top-level figure is short by roughly the step count. Billing prices
 * cache hits ~5x cheaper than fresh input, so that gap over-charges.
 *
 * Defensive by design: any missing field degrades to 0 rather than throwing,
 * so a provider that omits usage never breaks a scan.
 */
export function extractCallUsage(result: unknown): CallUsage {
  const r = (result ?? {}) as {
    usage?: { promptTokens?: unknown; completionTokens?: unknown };
    steps?: unknown;
  };
  const inputTokens = numberish(r.usage?.promptTokens);
  const outputTokens = numberish(r.usage?.completionTokens);
  // `usage` is summed over every step of a tool loop, but `providerMetadata` on
  // the result is only the FINAL step's — so reading cache off the top level
  // under-counts it by roughly the step count. Walk the steps instead; a
  // generateObject result has none, and falls back to the top level.
  const steps = Array.isArray(r.steps) && r.steps.length > 0 ? r.steps : undefined;
  const cachedInputTokens =
    steps?.reduce((n: number, step) => n + cachedTokensOf(step), 0) ?? cachedTokensOf(r);
  return { inputTokens, outputTokens, cachedInputTokens };
}

/** Cache-hit tokens off one result-or-step. 0 for providers that omit them. */
function cachedTokensOf(node: unknown): number {
  const n = (node ?? {}) as {
    providerMetadata?: unknown;
    experimental_providerMetadata?: unknown;
  };
  const meta = (n.providerMetadata ?? n.experimental_providerMetadata) as
    | { openai?: { cachedPromptTokens?: unknown } }
    | undefined;
  return numberish(meta?.openai?.cachedPromptTokens);
}

/** A finite positive number, else 0. Token counts are never negative. */
function numberish(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) && v > 0 ? v : 0;
}

/**
 * Warn when a tool loop ended because it ran out of turns rather than because
 * the model was done. `generateText` is called with `maxSteps = maxTurns + 1`,
 * so `steps.length` reaching that ceiling means the cap cut the loop off.
 *
 * Always logs (not gated on AGENTGG_DEBUG) — a capped batch silently yields 0
 * findings, so this line is the only evidence in the run log. Never throws and
 * never changes the batch's outcome: exhaustion is a quality signal, not a
 * failure. Reads every field defensively so a provider that omits `steps`
 * degrades to no warning rather than breaking the scan.
 */
export function warnIfTurnCapped(slug: string, result: unknown, maxTurns: number): void {
  const steps = (result as { steps?: unknown[] })?.steps;
  if (!Array.isArray(steps) || steps.length < maxTurns + 1) return;
  const last = steps[steps.length - 1] as { toolCalls?: unknown[] } | undefined;
  const stillCalling = Array.isArray(last?.toolCalls) && last.toolCalls.length > 0;
  console.warn(
    `[runAgent:${slug}] hit the ${maxTurns}-turn cap (${steps.length} steps` +
      `${stillCalling ? ", still mid tool-call" : ""}): analysis was cut short, ` +
      `findings for this batch may be incomplete. Raise maxTurnsPerBatch or pass --max-turns.`,
  );
}

/**
 * Explain an empty/unparseable agent response in one log line. `finishReason`
 * is the discriminator we were missing:
 *
 *   - "length"            output budget consumed (often by reasoning tokens)
 *                         before any visible text was produced.
 *   - "stop", textChars=0, reasoningChars>0
 *                         model ended the turn writing only into the reasoning
 *                         channel — the answer never reached `content`, or this
 *                         provider/SDK version dropped a reasoning-only answer.
 *   - "stop", textChars=0, reasoningChars=0, completionTokens>0
 *                         tokens were emitted but neither text nor reasoning
 *                         surfaced — the provider mapped the answer somewhere
 *                         this SDK version doesn't read.
 *   - "tool-calls"        ended mid tool-loop (cross-check steps vs maxTurns).
 *
 * Always logs (not gated on AGENTGG_DEBUG) — capturing this in production is
 * the whole point. Reads every field defensively so a provider that omits one
 * degrades to a 0/"unknown" rather than throwing inside the error path.
 */
function logUnparseableGeneration(label: string, result: unknown): void {
  const r = (result ?? {}) as {
    text?: unknown;
    reasoning?: unknown;
    finishReason?: unknown;
    usage?: { promptTokens?: unknown; completionTokens?: unknown };
    steps?: Array<{ text?: unknown; finishReason?: unknown; toolCalls?: unknown[] }>;
  };
  const textChars = typeof r.text === "string" ? r.text.length : 0;
  const reasoningChars = typeof r.reasoning === "string" ? r.reasoning.length : 0;
  const finishReason = typeof r.finishReason === "string" ? r.finishReason : "unknown";
  const promptTokens = numberish(r.usage?.promptTokens);
  const completionTokens = numberish(r.usage?.completionTokens);
  const steps = Array.isArray(r.steps) ? r.steps : [];
  const last = steps[steps.length - 1];
  const lastFinish = last && typeof last.finishReason === "string" ? last.finishReason : "n/a";
  const lastToolCalls = last && Array.isArray(last.toolCalls) ? last.toolCalls.length : 0;
  const lastTextChars = last && typeof last.text === "string" ? last.text.length : 0;
  console.warn(
    `[${label}] unparseable model response: finishReason=${finishReason} ` +
      `textChars=${textChars} reasoningChars=${reasoningChars} ` +
      `promptTokens=${promptTokens} completionTokens=${completionTokens} ` +
      `steps=${steps.length} lastStep(finish=${lastFinish},toolCalls=${lastToolCalls},textChars=${lastTextChars})`,
  );
}
