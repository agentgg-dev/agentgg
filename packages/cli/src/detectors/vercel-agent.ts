import { readdir, readFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import type { CvssScore, Finding, ReconReport } from "@agentgg/core";
import {
  generateObject,
  generateText,
  type LanguageModelV1,
  NoObjectGeneratedError,
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
  repairFindingPath,
  type SuggestExcludesArgs,
  SuggestExcludesResult,
} from "../detect.js";
import { ExpectedDetectorError } from "../diagnostics.js";
import { logError, logInfo, logWarn } from "../log.js";
import { asCvssScore, buildScorePrompt, LlmScore } from "../scoring.js";
import type { CallUsage, UsageMeter } from "../usage-meter.js";
import {
  asValidationField,
  buildScopeValidatePrompt,
  buildValidatePrompt,
  LlmValidation,
  VALIDATION_CUT_SHORT,
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
        logWarn(
          `[withTpmRetry] rate-limit on attempt ${attempt}/${maxAttempts}, sleeping ${waitMs}ms (retryAfterParsed=${parsed != null})`,
        );
      } else {
        // Transient upstream/transport flake: short exponential backoff.
        const base = Math.min(TRANSIENT_BACKOFF_MS * 2 ** (attempt - 1), TRANSIENT_BACKOFF_MAX_MS);
        waitMs = jitter(base);
        logWarn(
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
  /** Running USD total for this process, owned by the provider layer. Only
   *  OpenRouter supplies one; it is forwarded to the usage meter on attach. */
  costSource?: () => number;
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

/** Which pass owns this tool loop. Selects the artifact the model is told to
 *  emit when the budget runs out, and when a call repeats. See ARTIFACT. */
export type ToolLoopPhase = "detect" | "validate" | "recon" | "create-agent";

/**
 * What each phase must output, worded to match that phase's own `## Output
 * format` instruction. A `Record` rather than a lookup with a default, so a new
 * phase fails to compile until someone names its artifact.
 *
 * Getting this wrong is not cosmetic: a validator told to emit "findings JSON"
 * has no such thing to produce, so the notice becomes an instruction it cannot
 * follow.
 */
const ARTIFACT: Record<ToolLoopPhase, string> = {
  detect: "findings JSON",
  validate: "verdict JSON",
  recon: "brief JSON",
  "create-agent": "agent spec JSON",
};

/** Env suffix per phase for the budget override below. */
const BUDGET_ENV_SUFFIX: Record<ToolLoopPhase, string> = {
  detect: "DETECT",
  validate: "VALIDATE",
  recon: "RECON",
  "create-agent": "CREATE_AGENT",
};

/**
 * Tool-output budget for one loop, in bytes.
 *
 * The right number differs per phase because what competes for the context
 * window differs. The BASE prompt is the other half of the equation, and
 * detection's is the heaviest: it embeds the full content of every candidate
 * file in the batch (up to `maxFilesPerBatch`, default 5). Validation embeds
 * one file plus the finding narrative and the scope doc; recon embeds neither.
 * So detection has the least room left over for tool output, not the most.
 *
 * The defaults are nonetheless all equal today, deliberately. Every measured
 * loop so far finished far under the cap, so there is no evidence about where
 * the real ceilings are, and guessing one low enough to matter risks
 * truncating genuine analysis on large repos. What ships here is the knob and
 * the measurement; the numbers should move once `tool output budget exhausted`
 * actually shows up in logs.
 *
 * Override in KB, per phase or globally, so a stage can be retuned without a
 * rebuild:
 *
 *   AGENTGG_TOOL_BUDGET_KB_VALIDATE=250
 *   AGENTGG_TOOL_BUDGET_KB=300          # any phase without its own
 *
 * An unusable value falls back to the default rather than throwing: the cap
 * guards against a context-overflow 400, which is a hard failure, so a typo in
 * an env var must not be able to disable it.
 */
export function toolOutputBudgetBytes(
  phase: ToolLoopPhase,
  env: NodeJS.ProcessEnv = process.env,
): number {
  const raw =
    env[`AGENTGG_TOOL_BUDGET_KB_${BUDGET_ENV_SUFFIX[phase]}`] ?? env.AGENTGG_TOOL_BUDGET_KB;
  const kb = raw == null ? Number.NaN : Number(raw);
  return Number.isFinite(kb) && kb > 0 ? Math.round(kb * 1024) : TOOL_OUTPUT_BUDGET_BYTES;
}
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
 * Detector backed by the Vercel AI SDK. `generateText` drives the
 * tool loops (recon and agent runs, with Read/Glob/Grep tool
 * implementations); `generateObject` produces the one-shot structured
 * answers. That distinction is about how the model is driven, not about
 * how an agent selects files. Works with any Vercel AI SDK provider —
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
  private readonly costSource?: () => number;
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
    this.costSource = opts.costSource;
  }

  attachUsageMeter(meter: UsageMeter): void {
    this.meter = meter;
    if (this.costSource) meter.trackCost(this.costSource);
  }

  /**
   * Run one LLM call through the TPM-retry wrapper, then record its token
   * usage into the attached meter (a no-op when no meter is attached). Every
   * `generateObject` / `generateText` call funnels through here, so this is
   * also the one place that sees a call's provider ids on both outcomes: the
   * generation ids of a result, and the request ids a failure left in its
   * error headers. `label` is required for the same reason `buildTools` needs
   * one: ten concurrent validators share one stdout.
   */
  private async metered<T>(
    run: () => Promise<T>,
    opts: { label: string; signal?: AbortSignal },
  ): Promise<T> {
    const { label, signal } = opts;
    let result: T;
    try {
      result = await withTpmRetry(run, signal);
    } catch (err) {
      // One re-sample on an unparseable structured response. No temperature is
      // pinned anywhere, so this draws a fresh completion instead of replaying
      // the broken one. It exists for the direct `generateObject` callers
      // (precondition, score, dedupe): they have no reformat fallback, so a
      // retry is their only recovery. Tool-loop `generateText` calls never
      // raise this error, so they are untouched.
      // Every other failure (credits exhausted, a 400, ECONNRESET) leaves here.
      // Log its provider ids first: a throw carries no `response.id`, so this
      // is the only chance to record what to search for in the provider's
      // dashboard afterwards.
      if (signal?.aborted || !NoObjectGeneratedError.isInstance(err)) {
        logFailedCallIds(label, err, signal);
        throw err;
      }
      // The failed attempt still burned tokens; bill them before retrying.
      this.meter?.record(extractCallUsage(err), this.model.modelId);
      logWarn(`[${label}] unparseable structured response; re-sampling once`);
      logFailedCallIds(label, err, signal);
      try {
        result = await withTpmRetry(run, signal);
      } catch (retryErr) {
        logFailedCallIds(label, retryErr, signal);
        throw retryErr;
      }
    }
    this.meter?.record(extractCallUsage(result), this.model.modelId);
    logGenerationIds(label, result);
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
        logWarn(`${label}: tool-call repair budget spent, leaving the call broken`);
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
        logWarn(`${label}: repaired a malformed ${toolName} call`);
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
            tools: buildTools({
              cwd: resolve(args.rootDir),
              maxFileSizeKb: args.maxFileSizeKb,
              verbose: this.verbose,
              exclude: args.excludePatterns,
              label: "recon",
              phase: "recon",
            }),
            maxSteps: args.maxTurns + 1,
            experimental_repairToolCall: this.toolCallRepair("recon"),
            providerOptions: this.providerOptionsArg(),
            abortSignal: args.signal,
          }),
        { label: "recon", signal: args.signal },
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
        { label: "suggest-excludes", signal: args.signal },
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
            tools: buildTools({
              cwd: resolve(args.rootDir),
              maxFileSizeKb: args.maxFileSizeKb,
              verbose: this.verbose,
              exclude: args.excludePatterns,
              label: "create-agent",
              phase: "create-agent",
            }),
            maxSteps: args.maxTurns + 1,
            experimental_repairToolCall: this.toolCallRepair("create-agent"),
            providerOptions: this.providerOptionsArg(),
            abortSignal: args.signal,
          }),
        { label: "create-agent", signal: args.signal },
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
    const runToolLoop = (budgetBytes: number, maxTurns: number) =>
      this.metered(
        () =>
          generateText({
            model: this.model,
            prompt,
            tools: buildTools({
              cwd: resolve(args.rootDir),
              maxFileSizeKb: args.maxFileSizeKb,
              verbose: this.verbose,
              exclude: args.excludePatterns,
              label,
              phase: "detect",
              budgetBytes,
            }),
            maxSteps: maxTurns + 1,
            experimental_repairToolCall: this.toolCallRepair(label),
            providerOptions: this.providerOptionsArg(),
            abortSignal: args.signal,
          }),
        { label, signal: args.signal },
      );
    try {
      let gen: Awaited<ReturnType<typeof runToolLoop>>;
      let effectiveTurns = args.maxTurns;
      try {
        gen = await runToolLoop(toolOutputBudgetBytes("detect"), effectiveTurns);
      } catch (err) {
        // Context overflow: the accumulated tool transcript outgrew the window.
        // Re-sending it unchanged can't work, which is why withTpmRetry refuses
        // to retry — but a SMALLER loop can. The transcript grows with both the
        // bytes read and the number of turns those bytes get re-sent across, so
        // halve each. Once only: a second overflow means the batch itself is too
        // big for this model, and that is a planning problem, not a retry one.
        if (!isContextLengthError(errorHaystack(err)) || args.signal?.aborted === true) throw err;
        logWarn(
          `${label}: context overflow; retrying this batch at half the read budget and turn cap`,
        );
        effectiveTurns = Math.floor(args.maxTurns / 2);
        gen = await runToolLoop(Math.floor(toolOutputBudgetBytes("detect") / 2), effectiveTurns);
      }
      // The tool loop can burn its whole budget without ever emitting findings
      // JSON — typically the model degenerates into repeating one tool call.
      // The reformat fallback below turns that into a valid empty result, so
      // without this line a capped batch is indistinguishable from clean code.
      // Warn only: a capped batch still records 0 findings and the agent still
      // completes, so one bad batch never fails the scan.
      warnIfTurnCapped(label, gen, effectiveTurns);
      // An empty completion is a FAILED batch, not a clean one. Left to
      // parseOrReformat below it becomes an empty findings list: the reformat
      // prompt carries only this text, so from a blank page the model dutifully
      // answers "no findings", and that all-clear is indistinguishable from
      // real code review. Seen 2026-08-11: the xss agent hit its turn cap,
      // wrote nothing, and the two real findings it had reported on the
      // previous run silently disappeared.
      //
      // Throwing is the documented contract for a non-refusal parse failure. It
      // sets `rt.failed` in scan.ts, which suppresses the agent sidecar so the
      // agent re-runs instead of recording a clean pass. Not scan-fatal: an
      // unrecognized Error is logged and the batch pool continues.
      if (!gen.text.trim()) {
        logUnparseableGeneration(label, gen);
        throw new ExpectedDetectorError(
          `${label}: the model ended its tool loop without writing an answer, so this batch produced no analysis. ` +
            `Failing the batch rather than recording 0 findings; raise --max-turns if it repeats.`,
        );
      }
      let result: DetectionResultType;
      try {
        result = await this.parseOrReformat(gen.text, false, label, args.signal);
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
          logWarn(
            `[runAgent:${args.agent.slug}] model refused to analyze this batch; recording 0 findings`,
          );
          return [];
        }
        throw parseErr;
      }
      const fallback = args.candidates[0]?.filePath ?? "(unknown)";
      return result.findings.map((f) =>
        hydrateFinding(repairFindingPath(f, args.rootDir, args.candidates), args.agent, fallback),
      );
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
        { label: `precondition:${args.agentName}`, signal: args.signal },
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
          { label: `validate:${args.finding.id}`, signal: args.signal },
        );
        return asValidationField(object);
      }
      // Tool-enabled path: same generateText + tool-loop shape as runAgent
      // (runAgent), so the validator can Read/Glob/Grep across files to
      // trace the exploit chain. Structured output is recovered from the
      // final message via parseValidation (with a structuredModel reformat
      // fallback), because this SDK can't combine tools with generateObject.
      // Same exclude / size knobs as the agent run so validation and detection
      // see the same file set.
      const label = `validate:${args.finding.id}`;
      const prompt = `${buildValidatePrompt(args)}\n\n${validationJsonInstruction()}`;
      const gen = await this.metered(
        () =>
          generateText({
            model: this.model,
            prompt,
            tools: buildTools({
              cwd: resolve(args.root as string),
              maxFileSizeKb: args.maxFileSizeKb,
              verbose: this.verbose,
              exclude: args.excludePatterns ?? [],
              label,
              phase: "validate",
            }),
            maxSteps: this.validateMaxTurns + 1,
            experimental_repairToolCall: this.toolCallRepair(label),
            providerOptions: this.providerOptionsArg(),
            abortSignal: args.signal,
          }),
        { label, signal: args.signal },
      );
      // Same failure shape as runAgent: a validator that spends every step on
      // tool calls leaves no step to answer in, so `gen.text` is empty and
      // parseValidation's reformat would invent a verdict from nothing. Without
      // these two lines that is completely silent: the finding shows a
      // confident-looking `uncertain` and no log says the loop was cut short.
      warnIfTurnCapped(label, gen, this.validateMaxTurns);
      if (!gen.text.trim()) logUnparseableGeneration(label, gen);
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
        { label: `validate-scope:${args.finding.id}`, signal: args.signal },
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
        { label: `score:${args.finding.id}`, signal: args.signal },
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
        { label: `dedupe:${args.filePath}`, signal: args.signal },
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
    label: string,
    signal?: AbortSignal,
  ): Promise<DetectionResultType> {
    try {
      return DetectionResult.parse(extractJSON(text));
    } catch (extractErr) {
      if (!this.structuredModel) throw extractErr;
      try {
        const reformat = await generateObject({
          model: this.structuredModel,
          schema: DetectionResult,
          mode: this.objectMode,
          prompt: `The following is a completed security analysis. Extract all confirmed findings into structured JSON.\n\n${forReformat(text)}\n\n${jsonOutputInstruction(multiAgent)}`,
          abortSignal: signal,
        });
        this.meter?.record(extractCallUsage(reformat), this.structuredModel.modelId);
        logGenerationIds(`${label}:reformat`, reformat);
        return reformat.object;
      } catch (reformatErr) {
        if (signal?.aborted) throw reformatErr;
        this.meter?.record(extractCallUsage(reformatErr), this.structuredModel.modelId);
        logFailedCallIds(`${label}:reformat`, reformatErr, signal);
        const recovered = recoverFromError(DetectionResult, reformatErr);
        if (!recovered) throw reformatErr;
        logWarn(
          `reformat failed; recovered ${recovered.findings.length} finding(s) from its raw text`,
        );
        return recovered;
      }
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
    // Nothing to parse and nothing to reformat. The reformat prompt below
    // carries ONLY this text, never the finding, so on an empty string the
    // model is asked to extract a verdict from a blank page. It complies:
    // picks `uncertain`, writes "No validation content or finding was provided
    // to analyze", and that lands on the finding as a real-looking judgement.
    // `uncertain` is still the right verdict (we genuinely do not know), but
    // the reasoning has to say the validator was cut short instead of
    // impersonating an analysis that never happened.
    if (!text.trim()) {
      logWarn(
        `[validate:${findingId}] validation was cut short: the model stopped before it ` +
          `returned a verdict, so this finding is recorded as uncertain and was not assessed`,
      );
      return { verdict: "uncertain", reasoning: VALIDATION_CUT_SHORT };
    }
    try {
      return asValidationField(LlmValidation.parse(extractJSON(text)));
    } catch (extractErr) {
      if (looksLikeRefusal(text)) {
        logWarn(`[validate:${findingId}] model refused to validate; recording uncertain+refused`);
        return {
          verdict: "uncertain",
          reasoning: "Model declined to validate this finding (refusal).",
          refused: true,
        };
      }
      if (!this.structuredModel) throw extractErr;
      try {
        const reformat = await generateObject({
          model: this.structuredModel,
          schema: LlmValidation,
          mode: this.objectMode,
          prompt: `The following is a completed validation of a security finding. Extract the verdict into structured JSON.\n\n${forReformat(text)}\n\n${validationJsonInstruction()}`,
          abortSignal: signal,
        });
        this.meter?.record(extractCallUsage(reformat), this.structuredModel.modelId);
        logGenerationIds(`validate:${findingId}:reformat`, reformat);
        return asValidationField(reformat.object);
      } catch (reformatErr) {
        if (signal?.aborted) throw reformatErr;
        this.meter?.record(extractCallUsage(reformatErr), this.structuredModel.modelId);
        logFailedCallIds(`validate:${findingId}:reformat`, reformatErr, signal);
        // Try the whole object first: it keeps the reasoning prose, which the
        // verdict-only salvage below cannot.
        const recovered = recoverFromError(LlmValidation, reformatErr);
        if (recovered) {
          logWarn(`[validate:${findingId}] reformat failed; recovered the verdict from its text`);
          return asValidationField(recovered);
        }
        // Last resort: the model reached a verdict and only broke the JSON
        // delimiters around it. Reading the verdict back beats dropping the
        // finding, but the reasoning prose is unrecoverable.
        const salvaged =
          salvageVerdict(text) ?? salvageVerdict((reformatErr as { text?: string })?.text ?? "");
        if (!salvaged) throw reformatErr;
        logWarn(`[validate:${findingId}] reformat failed; salvaged "${salvaged}" from raw text`);
        return {
          verdict: salvaged,
          reasoning: "Recovered from an unparseable model response; the reasoning text was lost.",
        };
      }
    }
  }

  /** Parse an AgentSpec from the tool-loop's final text, with a
   *  structuredModel reformat fallback (Ollama best-effort). */
  private async parseAgentSpec(text: string, signal?: AbortSignal): Promise<AgentSpec> {
    try {
      return AgentSpec.parse(extractJSON(text));
    } catch (extractErr) {
      if (!this.structuredModel) throw extractErr;
      try {
        const reformat = await generateObject({
          model: this.structuredModel,
          schema: AgentSpec,
          mode: this.objectMode,
          prompt: `The following is a completed analysis distilling a past security incident into an agentgg agent spec. Extract it into the AgentSpec JSON shape.\n\n${forReformat(text)}\n\n${createAgentJsonInstruction()}`,
          abortSignal: signal,
        });
        this.meter?.record(extractCallUsage(reformat), this.structuredModel.modelId);
        logGenerationIds("create-agent:reformat", reformat);
        return reformat.object;
      } catch (reformatErr) {
        if (signal?.aborted) throw reformatErr;
        this.meter?.record(extractCallUsage(reformatErr), this.structuredModel.modelId);
        logFailedCallIds("create-agent:reformat", reformatErr, signal);
        const recovered = recoverFromError(AgentSpec, reformatErr);
        if (!recovered) throw reformatErr;
        logWarn("reformat failed; recovered the agent spec from its raw text");
        return recovered;
      }
    }
  }

  /** Parse a ReconResult from the tool-loop's final text, with a
   *  structuredModel reformat fallback (Ollama best-effort). */
  private async parseRecon(text: string, signal?: AbortSignal): Promise<ReconResult> {
    try {
      return ReconResult.parse(extractJSON(text));
    } catch (extractErr) {
      if (!this.structuredModel) throw extractErr;
      try {
        const reformat = await generateObject({
          model: this.structuredModel,
          schema: ReconResult,
          mode: this.objectMode,
          prompt: `The following is a completed recon survey of a codebase. Extract it into structured JSON.\n\n${forReformat(text)}\n\n${reconJsonInstruction()}`,
          abortSignal: signal,
        });
        this.meter?.record(extractCallUsage(reformat), this.structuredModel.modelId);
        logGenerationIds("recon:reformat", reformat);
        return reformat.object;
      } catch (reformatErr) {
        if (signal?.aborted) throw reformatErr;
        this.meter?.record(extractCallUsage(reformatErr), this.structuredModel.modelId);
        logFailedCallIds("recon:reformat", reformatErr, signal);
        const recovered = recoverFromError(ReconResult, reformatErr);
        if (!recovered) throw reformatErr;
        logWarn("reformat failed; recovered the recon brief from its raw text");
        return recovered;
      }
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

/**
 * Everything one tool loop needs to build its tools. `label` names the loop
 * (`recon`, `create-agent`, `runAgent:<slug>`, `validate:<findingId>`) and
 * prefixes every tool log line, so concurrent loops stay attributable on a
 * shared stdout. `budgetBytes` overrides the default cap; the context-overflow
 * retry passes a halved one.
 */
interface ToolLoopOpts {
  cwd: string;
  maxFileSizeKb: number | undefined;
  verbose: boolean;
  exclude?: string[];
  label: string;
  /** Which pass owns this loop. Drives the wording of every notice below. */
  phase: ToolLoopPhase;
  budgetBytes?: number;
}

export function buildTools(opts: ToolLoopOpts) {
  const { cwd, maxFileSizeKb, verbose, label, phase } = opts;
  const exclude = opts.exclude ?? [];
  const budgetBytes = opts.budgetBytes ?? toolOutputBudgetBytes(phase);
  // Prefix every tool line with the loop that made the call. Ten concurrent
  // validators share one stdout, so an unlabelled line cannot be attributed.
  const logTool = verbose
    ? (name: string, arg: string) => console.log(`    [${label}] ${name} ${arg.slice(0, 100)}`)
    : () => undefined;

  // Per-session tool-output budget, shared across every tool call in this
  // generateText loop (buildTools is constructed once per LLM session) so the
  // running transcript can't outgrow the model's context window. A fresh
  // buildTools — and thus a fresh budget — is created on each retry.
  let bytesReturned = 0;
  // Warn once, on the tick the budget runs out. Until this line existed there
  // was no way to tell from the outside whether a stalled loop had hit the cap:
  // the tools just started returning the finalize notice silently, so "the
  // budget caused it" stayed a hypothesis. Once per loop, not per call, because
  // past the cap EVERY tool call trips it.
  let budgetWarned = false;
  const budgetExhausted = () => {
    if (bytesReturned < budgetBytes) return false;
    if (!budgetWarned) {
      budgetWarned = true;
      logWarn(
        `[${label}] tool output budget exhausted (${Math.round(bytesReturned / 1024)} KB returned, ` +
          `cap ~${Math.round(budgetBytes / 1024)} KB); further tool calls return the finalize notice`,
      );
    }
    return true;
  };
  const account = (out: string): string => {
    bytesReturned += out.length;
    return out;
  };

  // Repeated identical tool calls are the signature of a stalled loop: the
  // model re-issues the same search, gets the same bytes back, and never
  // advances. Observed 2026-08-10, when one validator ran the same Grep 41
  // times over nine minutes, spent its whole turn budget, and answered with
  // nothing. A repeat re-executes nothing and is not charged to the byte
  // budget, so the loop becomes cheap; the warn makes it visible.
  //
  // Keyed on what actually EXECUTES rather than the raw arguments: Grep's
  // `path` is an alias for `glob` and both resolve to one scope, so two
  // spellings of the same search collapse to a single signature.
  /** Field separator inside a tool-call signature. A NUL cannot appear in a path,
   *  a pattern, or a glob, so `Grep "a b"` cannot collide with `Grep "a"` scoped to
   *  `b`. Never printed raw: a NUL byte makes grep treat a whole log as binary and
   *  refuse to match it, so the warn below swaps it for a space. */
  const SIG_SEP = "\u0000";

  const callCounts = new Map<string, number>();
  const repeated = (toolName: string, signature: string): string | null => {
    const n = (callCounts.get(signature) ?? 0) + 1;
    callCounts.set(signature, n);
    if (n === 1) return null;
    // The signature keys on a NUL separator so a pattern containing a space
    // cannot collide with a scoped search. Never print it raw: a NUL byte makes
    // grep treat the whole log as binary and refuse to match it.
    logWarn(
      `[${label}] repeated ${toolName} call #${n}: ${signature.split(SIG_SEP).join(" ").slice(0, 120)}`,
    );
    return repeatNotice(toolName, phase);
  };

  return {
    Read: tool({
      description: "Read the contents of a file. Path must be relative to the repository root.",
      parameters: z.object({
        path: z.string().describe("File path relative to the repository root"),
      }),
      execute: async ({ path }) => {
        logTool("Read", path);
        if (budgetExhausted()) return budgetNotice(phase, budgetBytes);
        const dup = repeated("Read", `Read${SIG_SEP}${path}`);
        if (dup) return dup;
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
        if (budgetExhausted()) return budgetNotice(phase, budgetBytes);
        const dup = repeated("Glob", `Glob${SIG_SEP}${pattern}`);
        if (dup) return dup;
        return account(await globToolExecute(pattern, cwd, exclude));
      },
    }),
    Grep: tool({
      description:
        "Search for a regex pattern across files. Returns matching lines as 'file:line: content'.",
      parameters: GrepParameters,
      execute: async ({ pattern, glob, path }) => {
        logTool("Grep", pattern);
        if (budgetExhausted()) return budgetNotice(phase, budgetBytes);
        // A bare directory path is not a glob — `src/api` matches that one
        // entry, not the files under it — so widen it before handing it over.
        const scope = glob || (path ? toSearchGlob(path) : undefined);
        // Signed on the RESOLVED scope so `{path: "src"}` and the glob it
        // widens to count as the same call. NUL separates the fields because
        // it cannot appear in either, so `Grep "a b"` cannot collide with
        // `Grep "a"` scoped to `b`.
        const dup = repeated("Grep", `Grep${SIG_SEP}${pattern}${SIG_SEP}${scope ?? ""}`);
        if (dup) return dup;
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
/**
 * Returned instead of re-running a tool call this loop already made with
 * identical arguments. Says what happened, why repeating is pointless, and
 * names the two ways forward: a different query, or the answer.
 */
export function repeatNotice(toolName: string, phase: ToolLoopPhase): string {
  return (
    `You already ran this exact ${toolName} call in this loop, and its result is above. ` +
    `Repeating it returns nothing new. ` +
    `Either try a different query, or output your final ${ARTIFACT[phase]} now, ` +
    `based on what you have already examined.`
  );
}

/**
 * Returned by every tool once the loop's output budget is spent: an explicit
 * instruction to stop calling tools and answer, rather than a silent empty
 * result the model might keep probing against.
 *
 * Phase-specific because the previous single message told EVERY caller to
 * "output your final findings JSON", an instruction a validator, recon pass,
 * or agent-spec author cannot follow. It also said "do not read more files"
 * while the observed stall was repeated Grep calls, which are not file reads.
 * And it opened with "Error:", framing a normal budget limit as a fault. All
 * three are now fixed.
 */
export function budgetNotice(
  phase: ToolLoopPhase,
  budgetBytes: number = toolOutputBudgetBytes(phase),
): string {
  return (
    `Tool budget reached (~${Math.round(budgetBytes / 1024)} KB of tool output in this loop). ` +
    `Stop calling Read, Grep, and Glob. ` +
    `Output your final ${ARTIFACT[phase]} now, based on what you have already examined.`
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

{"findings":[{"title":"Short title","vulnSlug":"vuln-class","agentSlug":null,"lineRange":[1,10],"filePath":"src/routes/users.ts","summary":"One sentence.","details":"Markdown analysis with file paths and line numbers.","poc":"Reproduction steps.","impact":"Who is affected and what they get.","references":["CWE-89","OWASP A03:2021 Injection"],"confidence":0.9}]}

IMPORTANT: Every \`filePath\` must be a real file path you actually read or located with tools during this session. Do NOT copy the example path above — replace it with the actual path from your investigation. If no findings, output exactly: {"findings":[]}

IMPORTANT: \`references\` MUST carry at least one CWE ID for every finding, written as \`CWE-<number>\`. Add the matching OWASP Top 10 category when one applies, and any documentation URL you relied on. The example values above are placeholders — replace them with the identifiers for YOUR finding. Leave the array empty only when no CWE describes the issue.

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

/**
 * Last-chance recovery from a reformat call that threw.
 *
 * WHY: `generateObject` parses the response itself and throws on failure, so
 * its raw text never reaches `extractJSON` — even though that function already
 * handles every corruption we have observed (a stray `{"` prefix, the object
 * emitted twice, a delimiter dropped between fields). The tokens are already
 * paid for, so this recovers whole findings with their reasoning intact at no
 * extra cost. Returns null when nothing valid is in there, and the caller
 * rethrows.
 */
export function recoverFromError<S extends z.ZodTypeAny>(
  schema: S,
  err: unknown,
): z.output<S> | null {
  const text = (err as { text?: unknown })?.text;
  if (typeof text !== "string" || text.length === 0) return null;
  try {
    return schema.parse(extractJSON(text));
  } catch {
    return null;
  }
}

/**
 * Read a verdict out of text no JSON parser accepts.
 *
 * Matches `"verdict":"confirmed"` and the comma-for-colon variant a degenerate
 * model emits. Takes the LAST match on purpose: `validationJsonInstruction`
 * shows `{"verdict":"confirmed",…}` as its example, so a model that echoes the
 * output format would hand a first-match reader that example instead of its
 * answer, and the example is the worst-case wrong value. Returns null when no
 * verdict appears, which leaves the caller to rethrow.
 */
export function salvageVerdict(
  text: string,
): "confirmed" | "false-positive" | "out-of-scope" | "uncertain" | null {
  const pattern = /"verdict"\s*[:,]\s*"(confirmed|false-positive|out-of-scope|uncertain)"/g;
  let last: string | null = null;
  for (const m of text.matchAll(pattern)) last = m[1];
  return last as "confirmed" | "false-positive" | "out-of-scope" | "uncertain" | null;
}

/** Max raw model text embedded in a reformat prompt. */
const REFORMAT_TEXT_LIMIT = 4000;

/**
 * Trim the raw text a reformat prompt re-sends to the model.
 *
 * WHY: the reformat call asks the SAME model to repair its own broken output,
 * so a degenerate repetition loop is fed straight back in and repeats. One
 * clean copy of the answer reformats fine; forty broken ones do not. Cuts the
 * cycle at its second copy, then caps length. The head is kept because the
 * first copy is the model's real answer.
 */
export function forReformat(text: string): string {
  const collapsed = collapseRepeats(text);
  if (collapsed.length <= REFORMAT_TEXT_LIMIT) return collapsed;
  return `${collapsed.slice(0, REFORMAT_TEXT_LIMIT)}\n[truncated]`;
}

/** Cut at the second occurrence of the opening probe, so a repeated block
 *  survives exactly once. Returns the text unchanged when nothing repeats. */
function collapseRepeats(text: string): string {
  const probeLen = 120;
  if (text.length <= probeLen * 2) return text;
  const next = text.indexOf(text.slice(0, probeLen), probeLen);
  return next === -1 ? text : text.slice(0, next);
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
  logError(`---- ${label} error ----`);
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
/**
 * Provider-side request ids for one call. A tool loop bills one generation PER
 * STEP, so a 51-step loop has 51 ids. Report the first and last plus the count
 * rather than all of them. These are what make a provider dashboard lookup
 * possible; without them a bad call can only be found by scanning the activity
 * log by timestamp.
 *
 * Returns "" when the provider exposes no ids, so callers can append blind.
 */
function formatGenerationIds(result: unknown): string {
  return formatIdRange("genId", "genIds", collectGenerationIds(result), "calls");
}

/** The provider ids on a successful result: one per step for a tool loop,
 *  else the single top-level response id. Empty when none are exposed. */
function collectGenerationIds(result: unknown): string[] {
  const r = (result ?? {}) as {
    response?: { id?: unknown };
    steps?: Array<{ response?: { id?: unknown } }>;
  };
  const stepIds = (Array.isArray(r.steps) ? r.steps : [])
    .map((step) => step?.response?.id)
    .filter((id): id is string => typeof id === "string" && id.length > 0);
  if (stepIds.length > 0) return stepIds;
  return [r.response?.id].filter((id): id is string => typeof id === "string" && id.length > 0);
}

/** ` name=only` for one id, ` plural=first..last (N unit)` for many, "" for
 *  none. Leading space so callers can append to a log line blind. */
function formatIdRange(name: string, plural: string, ids: string[], unit: string): string {
  if (ids.length === 0) return "";
  if (ids.length === 1) return ` ${name}=${ids[0]}`;
  return ` ${plural}=${ids[0]}..${ids[ids.length - 1]} (${ids.length} ${unit})`;
}

/**
 * Response headers that carry a provider-side request id, in the order we
 * prefer them. `cf-ray` is last: it identifies the Cloudflare edge hop that
 * fronts OpenRouter, not the generation, so it only helps when the provider
 * gave us nothing better.
 */
const ERROR_ID_HEADERS = [
  "x-request-id", // OpenAI: `req_...`, the id its dashboard indexes. Measured.
  "request-id", // OpenRouter advertises it in expose-headers but never sent one.
  "x-amzn-requestid", // Bedrock sends it over HTTP; see $metadata below. Measured.
  "cf-ray", // Cloudflare edge trace. Last resort: it finds nothing in a dashboard.
] as const;

/**
 * Headers carrying a GENERATION id rather than a request id. OpenRouter sends
 * `X-Generation-Id` (same value as the body's `id`) on every call it actually
 * generated, which makes it the one id worth having on a failure: it resolves
 * in the provider dashboard, where a request id or a `cf-ray` does not.
 * Checked before the request-id headers so the better id wins when both exist.
 *
 * What each provider actually exposes, measured against the live APIs on
 * 2026-08-28 rather than assumed. Only these five reach this code; `anthropic`
 * routes to ClaudeAgentDetector and never calls `metered`.
 *
 *   openrouter  X-Generation-Id header + body `id`. No x-request-id, ever.
 *   openai      x-request-id (`req_...`). No generation id.
 *   bedrock     x-amzn-RequestId over HTTP, but the SDK surfaces it at
 *               `$metadata.requestId`, not in responseHeaders (see below).
 *   vertex      nothing at all. Its request ids live in Cloud Logging.
 *   ollama      local; there is no remote dashboard to look anything up in.
 */
const GENERATION_ID_HEADERS = ["x-generation-id"] as const;

type ErrorIds = { genIds: string[]; reqIds: Array<{ header: string; value: string }> };

/**
 * Provider-side ids for a call that FAILED. `formatGenerationIds` reads
 * `response.id`, which only exists on a result. A throw has none, so every
 * failure (credits exhausted, ECONNRESET, a 400) used to leave no id at all
 * and the request could not be found in the provider's dashboard afterwards.
 *
 * Three salvage routes, all best-effort and none guaranteed by any provider:
 * a generation id in a response header (OpenRouter's X-Generation-Id, the one
 * worth having because it resolves in the dashboard), a generation id in the
 * error body, and failing both, a request id from the headers. Prints a
 * generation id and a request id when both exist, "" when nothing does.
 */
export function formatErrorIds(err: unknown): string {
  const { genIds, reqIds } = collectErrorIds(err);
  const gen = formatIdRange("genId", "genIds", genIds, "calls");
  if (reqIds.length === 0) return gen;
  const first = reqIds[0] as { header: string; value: string };
  if (reqIds.length === 1) return `${gen} reqId=${first.value} (${first.header})`;
  const last = reqIds[reqIds.length - 1] as { header: string; value: string };
  return `${gen} reqIds=${first.value}..${last.value} (${reqIds.length} attempts via ${first.header})`;
}

/**
 * Walk an error for ids. The one we want is rarely on the error thrown: the
 * SDK's `RetryError` holds each attempt in `errors` (and repeats the final one
 * as `lastError`), and our own context-length rewrite wraps the original as
 * `cause`. Depth-limited and value-deduped, same defensive shape as
 * `errorHaystack`.
 */
function collectErrorIds(
  err: unknown,
  depth = 0,
  acc: ErrorIds = { genIds: [], reqIds: [] },
): ErrorIds {
  if (depth > 3 || err == null || typeof err !== "object") return acc;
  const e = err as Record<string, unknown>;
  if (e.responseHeaders != null && typeof e.responseHeaders === "object") {
    const headers = new Map(
      Object.entries(e.responseHeaders as Record<string, unknown>).map(([k, v]) => [
        k.toLowerCase(),
        v,
      ]),
    );
    for (const header of GENERATION_ID_HEADERS) {
      const value = headers.get(header);
      if (typeof value !== "string" || value.length === 0) continue;
      if (!acc.genIds.includes(value)) acc.genIds.push(value);
      break;
    }
    for (const header of ERROR_ID_HEADERS) {
      const value = headers.get(header);
      if (typeof value !== "string" || value.length === 0) continue;
      if (!acc.reqIds.some((r) => r.value === value)) acc.reqIds.push({ header, value });
      break;
    }
  }
  // AWS SDK v3 (Bedrock) never populates `responseHeaders`. It puts the id on
  // `$metadata.requestId` instead, so without this branch every Bedrock
  // failure reports no id at all.
  const meta = e.$metadata;
  if (meta != null && typeof meta === "object") {
    const reqId = (meta as { requestId?: unknown }).requestId;
    if (typeof reqId === "string" && reqId.length > 0) {
      if (!acc.reqIds.some((r) => r.value === reqId)) {
        acc.reqIds.push({ header: "$metadata.requestId", value: reqId });
      }
    }
  }
  const bodyId = generationIdFromBody(e.responseBody);
  if (bodyId && !acc.genIds.includes(bodyId)) acc.genIds.push(bodyId);
  for (const child of [e.cause, e.lastError]) {
    if (child != null && child !== err) collectErrorIds(child, depth + 1, acc);
  }
  if (Array.isArray(e.errors)) {
    for (const child of e.errors) {
      if (child !== err) collectErrorIds(child, depth + 1, acc);
    }
  }
  return acc;
}

/** The `id` field of a JSON error body, when there is one. Providers that
 *  bill a generation before failing report it here (OpenRouter `gen-...`). */
function generationIdFromBody(body: unknown): string | null {
  if (typeof body !== "string" || !body.includes('"id"')) return null;
  try {
    const parsed = JSON.parse(body) as { id?: unknown };
    return typeof parsed.id === "string" && parsed.id.length > 0 ? parsed.id : null;
  } catch {
    return null;
  }
}

/**
 * Report the ids of a failed call. Always logs (not gated on a flag): a
 * failure is exactly when someone will go looking for the request in the
 * provider's dashboard, and the id is the only way to find it. Silent when the
 * provider exposed no id, and silent on a user cancel. An aborted call is not a
 * provider failure, and ten concurrent ones would bury the real reason.
 */
export function logFailedCallIds(label: string, err: unknown, signal?: AbortSignal): void {
  if (signal?.aborted || isAbortLikeError(err)) return;
  const ids = formatErrorIds(err);
  if (!ids) return;
  logWarn(`[${label}] call failed:${ids}: ${firstErrorLine(errorHaystack(err))}`);
}

/** A cancelled call, by SDK convention (`AbortError`) or by message. False
 *  positives only cost us one diagnostic line, so match loosely. */
function isAbortLikeError(err: unknown): boolean {
  const e = err as { name?: unknown; message?: unknown } | null;
  if (e?.name === "AbortError" || e?.name === "TimeoutError") return true;
  return typeof e?.message === "string" && /\baborted?\b/i.test(e.message);
}

/**
 * Trace the ids of a SUCCESSFUL call. Off by default: a scan makes tens of
 * calls (49 in the smallest demo run, far more on a real repo) and one line
 * each would drown the log. Turn on with `AGENTGG_LOG_GENERATION_IDS=1` to
 * follow every call into the provider's dashboard, which is what you want when
 * reconciling our token accounting against a provider bill.
 *
 * INFO, not WARN: this reports a call that WORKED. Every other diagnostic in
 * this file marks something wrong, and emitting tens of `[WARN]` lines for
 * healthy calls would make the level meaningless exactly when someone is
 * reading the log closely. Stays on stderr so it cannot corrupt `--json`.
 */
export function logGenerationIds(
  label: string,
  result: unknown,
  env: NodeJS.ProcessEnv = process.env,
): void {
  const flag = env.AGENTGG_LOG_GENERATION_IDS;
  if (!flag || flag === "0" || flag.toLowerCase() === "false") return;
  const ids = formatGenerationIds(result);
  if (!ids) return;
  logInfo(`[${label}] call complete:${ids}`, "err");
}

export function warnIfTurnCapped(label: string, result: unknown, maxTurns: number): void {
  const steps = (result as { steps?: unknown[] })?.steps;
  if (!Array.isArray(steps) || steps.length < maxTurns + 1) return;
  const last = steps[steps.length - 1] as { toolCalls?: unknown[] } | undefined;
  const stillCalling = Array.isArray(last?.toolCalls) && last.toolCalls.length > 0;
  logWarn(
    `[${label}] hit the ${maxTurns}-turn cap (${steps.length} steps` +
      `${stillCalling ? ", still mid tool-call" : ""}): analysis was cut short, ` +
      `results for this tool loop may be incomplete. Raise maxTurnsPerBatch or pass --max-turns.` +
      `${formatGenerationIds(result)}`,
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
  logWarn(
    `[${label}] unparseable model response: finishReason=${finishReason} ` +
      `textChars=${textChars} reasoningChars=${reasoningChars} ` +
      `promptTokens=${promptTokens} completionTokens=${completionTokens} ` +
      `steps=${steps.length} lastStep(finish=${lastFinish},toolCalls=${lastToolCalls},textChars=${lastTextChars})` +
      `${formatGenerationIds(result)}`,
  );
}
