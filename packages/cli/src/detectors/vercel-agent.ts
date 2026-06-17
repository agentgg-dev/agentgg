import { readdir, readFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import type { CvssScore, Finding } from "@agentgg/core";
import { generateObject, generateText, type LanguageModelV1, tool } from "ai";
import { minimatch } from "minimatch";
import { z } from "zod";
import { AgentSpec } from "../agent-spec.js";
import { buildDedupePrompt, LlmDedup } from "../deduper.js";
import {
  buildAgentPrompt,
  buildCreateAgentPrompt,
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
} from "../detect.js";
import { asCvssScore, buildScorePrompt, LlmScore } from "../scoring.js";
import type { CallUsage, UsageMeter } from "../usage-meter.js";
import {
  asValidationField,
  buildScopeValidatePrompt,
  buildValidatePrompt,
  LlmValidation,
} from "../validator.js";

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

/** Default wait when the provider doesn't tell us how long to back off.
 *  Per-minute TPM buckets refill smoothly across the window — 30s typically
 *  frees enough capacity to fit one more call. 60s was the safe upper bound,
 *  but compounded badly across parallel batches (3 retries × 60s × N batches). */
const DEFAULT_BACKOFF_MS = 30_000;
const JITTER_FRACTION = 0.2; // ±20%

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
      const msg = err instanceof Error ? err.message : String(err);
      if (!isRateLimitError(msg) || attempt >= maxAttempts) throw err;
      // Honor a server-supplied delay precisely. Only jitter the blind default.
      const parsed = parseRetryAfterMs(msg);
      const waitMs = parsed ?? jitter(DEFAULT_BACKOFF_MS);
      console.warn(
        `[withTpmRetry] rate-limit on attempt ${attempt}/${maxAttempts}, sleeping ${waitMs}ms (retryAfterParsed=${parsed != null})`,
      );
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
  /** Fallback model used only for final JSON extraction when the tool-call model
   *  returns malformed JSON. Useful for Ollama where structuredOutputs conflicts
   *  with tool calling but is needed to get reliable JSON output. */
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
  private meter?: UsageMeter;

  constructor(name: string, model: LanguageModelV1, opts: VercelAgentDetectorOpts = {}) {
    this.name = name;
    this.model = model;
    this.structuredModel = opts.structuredModel;
    this.providerKey = opts.providerKey ?? derivedProviderKey(name);
    this.effort = opts.effort;
    this.thinking = opts.thinking;
    this.verbose = opts.verbose ?? false;
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
            providerOptions: this.providerOptionsArg(),
            abortSignal: args.signal,
          }),
        args.signal,
      );
      const result = await this.parseOrReformat(text, false, args.signal);
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
            mode: "json",
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
    signal?: AbortSignal;
  }) {
    try {
      const { object } = await this.metered(
        () =>
          generateObject({
            model: this.model,
            schema: LlmValidation,
            mode: "json",
            prompt: buildValidatePrompt(args),
            providerOptions: this.providerOptionsArg(),
            abortSignal: args.signal,
          }),
        args.signal,
      );
      return asValidationField(object);
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
            mode: "json",
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
    signal?: AbortSignal;
  }): Promise<CvssScore> {
    try {
      const { object } = await this.metered(
        () =>
          generateObject({
            model: this.model,
            schema: LlmScore,
            mode: "json",
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
            mode: "json",
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
        mode: "json",
        prompt: `The following is a completed security analysis. Extract all confirmed findings into structured JSON.\n\n${text}\n\n${jsonOutputInstruction(multiAgent)}`,
        abortSignal: signal,
      });
      this.meter?.record(extractCallUsage(reformat), this.structuredModel.modelId);
      return reformat.object;
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
        mode: "json",
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
        mode: "json",
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

function buildTools(
  cwd: string,
  maxFileSizeKb: number | undefined,
  verbose: boolean,
  exclude: string[] = [],
) {
  const logTool = verbose
    ? (name: string, arg: string) => console.log(`    ${name} ${arg.slice(0, 100)}`)
    : () => undefined;

  return {
    Read: tool({
      description: "Read the contents of a file. Path must be relative to the repository root.",
      parameters: z.object({
        path: z.string().describe("File path relative to the repository root"),
      }),
      execute: async ({ path }) => {
        logTool("Read", path);
        return readToolExecute(path, cwd, maxFileSizeKb, exclude);
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
        return globToolExecute(pattern, cwd, exclude);
      },
    }),
    Grep: tool({
      description:
        "Search for a regex pattern across files. Returns matching lines as 'file:line: content'.",
      parameters: z.object({
        pattern: z.string().describe("Regular expression to search for"),
        glob: z
          .string()
          .describe(
            "Glob to restrict which files are searched, e.g. '**/*.ts'. Pass an empty string to search all files.",
          ),
      }),
      execute: async ({ pattern, glob }) => {
        logTool("Grep", pattern);
        return grepToolExecute(pattern, glob || undefined, cwd, exclude);
      },
    }),
  };
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
    return await readFile(absolutePath, "utf-8");
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

{"slug":"kebab-case-slug","name":"Short name","description":"One-line description of the anti-pattern.","noiseTier":"normal","references":["CWE-89"],"precondition":{"regex":{"extensions":["ts"],"files":[],"directories":[],"patterns":[]}},"where":{"extensions":["ts","tsx"],"filePatterns":[],"excludePatterns":["**/__tests__/**"],"preFilter":[{"regex":"\\\\.query\\\\s*\\\\(","label":"raw SQL call"}],"maxFilesPerBatch":5,"maxTurnsPerBatch":30},"prompt":"Markdown body of the agent's instructions."}

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
 * documented `usage` shape ({ promptTokens, completionTokens })
 * and the provider metadata's cache figure when present — OpenAI-compatible
 * surfaces, including Vertex MaaS (GLM-5), report it under
 * `providerMetadata.openai.cachedPromptTokens`. Defensive by design: any
 * missing field degrades to 0 rather than throwing, so a provider that omits
 * usage never breaks a scan.
 */
export function extractCallUsage(result: unknown): CallUsage {
  const r = (result ?? {}) as {
    usage?: { promptTokens?: unknown; completionTokens?: unknown };
    providerMetadata?: unknown;
    experimental_providerMetadata?: unknown;
  };
  const inputTokens = numberish(r.usage?.promptTokens);
  const outputTokens = numberish(r.usage?.completionTokens);
  const meta = (r.providerMetadata ?? r.experimental_providerMetadata) as
    | { openai?: { cachedPromptTokens?: unknown } }
    | undefined;
  const cachedInputTokens = numberish(meta?.openai?.cachedPromptTokens);
  return { inputTokens, outputTokens, cachedInputTokens };
}

/** A finite positive number, else 0. Token counts are never negative. */
function numberish(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) && v > 0 ? v : 0;
}
