import { readFileSync } from "node:fs";
import type { UserConfig } from "@agentgg/core";
import { createOpenAI } from "@ai-sdk/openai";
import { input, password } from "@inquirer/prompts";
import type { Detector } from "../detect.js";
import { VercelAgentDetector } from "../detectors/index.js";
import { createDeadlineFetch } from "../request-deadline.js";
import {
  announceThrottle,
  createThrottledFetch,
  resolveTpmLimit,
  TpmBucket,
} from "../tpm-bucket.js";
import type { CollectCredentialsArgs, ProviderModule, ResolveOptions } from "./types.js";

const DEFAULT_MODEL = "z-ai/glm-5.2";
const DEFAULT_BASE_URL = "https://openrouter.ai/api/v1";

function csv(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * OpenRouter `provider` routing block. Three layers, later ones winning per
 * key: the routing saved in the user config (`agentgg config
 * --openrouter-routing`), the OPENROUTER_* env vars, then the scan-time
 * `--openrouter-routing` flag. Defaults are tuned for a code-analysis agent:
 * require the params we send (drops providers that would silently ignore
 * tool-calls) and route by price (a throughput sort walks up the price
 * curve). No quantization filter by default: which quantizations exist
 * depends on the model, and a filter no endpoint matches fails every call.
 * Save one with `agentgg config --openrouter-routing`. An explicit
 * OPENROUTER_PROVIDER_ORDER pins an allow-list and switches off open
 * fallback.
 *
 * OPENROUTER_IGNORE is the escape hatch for a provider whose serving stack
 * is broken for this model. It is a CSV of provider slugs and applies in
 * every branch, because a bad endpoint has to be excluded whether we are
 * sorting or pinning an order. Base slugs match all of a provider's
 * endpoints (`baseten` covers `baseten/fp8` and `baseten/fast`); use the
 * full slug to drop one variant.
 *
 * Why it exists: an endpoint can serve a model in a broken way that still
 * reports success, for example by returning the answer in the `reasoning`
 * channel and leaving `message.content` empty, which fails every structured
 * call. Nothing on our side repairs that, so a host has to be excludable by
 * config.
 */
export function buildProviderRouting(
  overrideJson?: string,
  saved?: Record<string, unknown>,
): Record<string, unknown> {
  const quant = csv(process.env.OPENROUTER_QUANTIZATIONS);
  const routing: Record<string, unknown> = { require_parameters: true, ...saved };
  if (quant.length > 0) routing.quantizations = quant;
  const ignore = csv(process.env.OPENROUTER_IGNORE);
  if (ignore.length > 0) routing.ignore = ignore;
  const order = csv(process.env.OPENROUTER_PROVIDER_ORDER);
  if (order.length > 0) {
    routing.order = order;
    routing.allow_fallbacks = process.env.OPENROUTER_ALLOW_FALLBACKS !== "0";
  }
  if (process.env.OPENROUTER_SORT) routing.sort = process.env.OPENROUTER_SORT;
  const prompt = process.env.OPENROUTER_MAX_PRICE_PROMPT;
  const completion = process.env.OPENROUTER_MAX_PRICE_COMPLETION;
  if (prompt || completion) {
    const maxPrice: Record<string, number> = {};
    if (prompt) maxPrice.prompt = Number(prompt);
    if (completion) maxPrice.completion = Number(completion);
    routing.max_price = maxPrice;
  }
  if (process.env.OPENROUTER_ZDR === "1") routing.zdr = true;

  // --openrouter-routing JSON is authoritative: its keys override the
  // env-derived defaults (require_parameters survives unless the JSON sets
  // it). A parse failure throws here, before any LLM call or spend.
  if (overrideJson != null && overrideJson.trim() !== "") {
    const override = parseRoutingOverride(readRoutingOverrideText(overrideJson));
    Object.assign(routing, override);
  }
  // `order`/`only` (pin providers) and `sort` are opposing intents: a pin
  // from any layer drops the sort, and only an unpinned block gets the
  // price default.
  if (routing.order != null || routing.only != null) delete routing.sort;
  else routing.sort ??= "price";
  return routing;
}

/**
 * Resolve the raw `--openrouter-routing` value to JSON text. A value that
 * starts with `{` is inline JSON; anything else is treated as a path to a
 * JSON file — so you can pass `routing.json` directly and skip shell-quoting
 * the JSON on Windows/PowerShell. A leading UTF-8 BOM (what PowerShell's
 * Set-Content writes) is stripped.
 */
export function readRoutingOverrideText(value: string): string {
  const trimmed = value.trim();
  if (trimmed.startsWith("{")) return value;
  let text: string;
  try {
    text = readFileSync(trimmed, "utf8");
  } catch (err) {
    throw new Error(
      `--openrouter-routing "${trimmed}" is neither inline JSON (must start with '{') nor a readable file: ${(err as Error).message}.`,
    );
  }
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

/**
 * Parse the raw `--openrouter-routing` value into a provider-block object.
 * Fails loud (never silently ignores) so a typo can't quietly ship the
 * default routing. Throws before any LLM call.
 */
export function parseRoutingOverride(json: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (err) {
    throw new Error(
      `--openrouter-routing is not valid JSON: ${(err as Error).message}. ` +
        `Expected an object, e.g. {"order":["baseten"],"quantizations":["fp8"]}.`,
    );
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    const got = parsed === null ? "null" : Array.isArray(parsed) ? "an array" : typeof parsed;
    throw new Error(
      `--openrouter-routing must be a JSON object (e.g. {"order":["baseten"]}), got ${got}.`,
    );
  }
  return parsed as Record<string, unknown>;
}

/**
 * Parse a value for the saved routing (`agentgg config --openrouter-routing`,
 * `agentgg init --openrouter-routing`): inline JSON, a JSON file path, or
 * `none` to clear it. Returns null for `none`.
 */
export function parseSavedRouting(value: string): Record<string, unknown> | null {
  if (value.trim().toLowerCase() === "none") return null;
  return parseRoutingOverride(readRoutingOverrideText(value));
}

/**
 * Running total of what OpenRouter charged, in USD.
 *
 * OpenRouter reports a per-call charge in `usage.cost`, but the AI SDK's
 * OpenAI-compatible client parses the OpenAI response shape and drops the
 * field. The fetch wrapper reads it off the raw response instead and folds it
 * in here. The meter is a plain running total, not a per-call value: nothing
 * has to match a cost to the call that produced it, so concurrent requests
 * cannot misattribute spend.
 */
export interface CostMeter {
  /** Fold one response's reported charge in. Anything else is ignored. */
  add(usd: unknown): void;
  /** USD charged for every call made through this fetch, this process. */
  totalUsd(): number;
}

export function createCostMeter(): CostMeter {
  let total = 0;
  return {
    add(usd: unknown): void {
      if (typeof usd === "number" && Number.isFinite(usd) && usd > 0) total += usd;
    },
    totalUsd: (): number => total,
  };
}

/**
 * Output cap for every OpenRouter completion.
 *
 * A model can spend a whole generation on reasoning the caller never sees, and
 * nothing else bounds it: `providerOptionsArg()` has no OpenRouter branch and
 * no `maxTokens` is set anywhere in the engine.
 *
 * The cap has to leave room for an ANSWER after a long think, so it sits far
 * above what an answer alone needs. Set it too low and a long think leaves the
 * model nothing to write with, which costs a whole batch.
 */
const DEFAULT_MAX_TOKENS = 64_000;

/**
 * Reasoning depth for every completion, as a share of `max_tokens`: the two
 * come out of one budget, so an unbounded think leaves nothing to answer with.
 * A model that defaults to its deepest effort keeps about 5% of the budget for
 * the answer, which a long answer does not fit in.
 *
 * `high` rather than a lower level because depth is the product: it still
 * allows far more thinking than a healthy call uses, and it quadruples what is
 * left to answer with. A phase whose work is mechanical asks for less itself.
 *
 * Effort, not `reasoning.max_tokens`: OpenRouter honors a token budget on
 * Anthropic and Gemini models only, and every other model ignores it.
 */
const DEFAULT_REASONING_EFFORT = "high";

/** The levels OpenRouter accepts. It maps one the model does not have onto the
 *  nearest one the model declares. */
const EFFORT_LEVELS = new Set(["minimal", "low", "medium", "high", "xhigh", "max"]);

/** A level from `env`, or the default when it is absent or junk. */
function reasoningEffort(raw: string | undefined): string {
  const level = raw?.trim().toLowerCase();
  return level && EFFORT_LEVELS.has(level) ? level : DEFAULT_REASONING_EFFORT;
}

/** A positive integer from `env`, or `fallback` when it is absent or junk. */
function tokenCap(raw: string | undefined, fallback: number): number {
  const n = Number(raw);
  return raw && Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

/**
 * Wrap fetch to merge the routing block into chat-completions bodies and
 * add OpenRouter's attribution headers. Mirrors vertex.ts's fetch
 * injection so we stay free of an extra SDK dependency.
 *
 * With a `cost` meter attached it also turns on OpenRouter's usage accounting
 * and records what each call was charged.
 */
export function createRoutingFetch(
  routing: Record<string, unknown>,
  inner: typeof fetch = fetch,
  cost?: CostMeter,
): typeof fetch {
  return async (url, init) => {
    const href = typeof url === "string" ? url : url.toString();
    const isCompletion = href.includes("/chat/completions");
    let nextInit = init;
    if (isCompletion && init?.body && typeof init.body === "string") {
      try {
        const body = JSON.parse(init.body) as Record<string, unknown>;
        if (body.provider == null) body.provider = routing;
        // Opt in to usage accounting so the response carries `usage.cost`.
        // Only when someone is listening: it changes the request we send.
        if (cost && body.usage == null) body.usage = { include: true };
        // Only when the caller set neither: an explicit cap is a deliberate
        // choice and must win over this floor.
        if (body.max_tokens == null) {
          body.max_tokens = tokenCap(process.env.OPENROUTER_MAX_TOKENS, DEFAULT_MAX_TOKENS);
        }
        // `reasoning_effort` is what the AI SDK emits for a per-call effort.
        // Either form from the caller wins, and a request may carry only one:
        // OpenRouter rejects an effort and a token budget together.
        if (body.reasoning == null && body.reasoning_effort == null) {
          const reasoningCap = tokenCap(process.env.OPENROUTER_REASONING_MAX_TOKENS, 0);
          body.reasoning =
            reasoningCap > 0
              ? { max_tokens: reasoningCap }
              : { effort: reasoningEffort(process.env.OPENROUTER_REASONING_EFFORT) };
        }
        nextInit = { ...init, body: JSON.stringify(body) };
      } catch {
        // Non-JSON body should never reach chat/completions; pass through.
      }
    }
    const headers = new Headers(nextInit?.headers);
    headers.set("HTTP-Referer", process.env.OPENROUTER_REFERER ?? "https://agentgg.dev");
    headers.set("X-Title", "AgentGG");
    const res = await inner(url, { ...nextInit, headers });
    if (cost && isCompletion) await recordResponseCost(cost, res);
    return res;
  };
}

/**
 * Read `usage.cost` off a completion response without consuming it — the SDK
 * parses the same body afterwards, so this reads a clone. Best-effort by
 * design: an error page, a streamed body, or a provider that reports no cost
 * simply leaves the total where it was.
 */
async function recordResponseCost(cost: CostMeter, res: Response): Promise<void> {
  // Never touch a streamed body: cloning and parsing it drains the stream, so
  // the caller would not see the response until the stream ended.
  if (res.headers.get("content-type")?.includes("event-stream")) return;
  try {
    const body = (await res.clone().json()) as { usage?: { cost?: unknown } };
    cost.add(body?.usage?.cost);
  } catch {
    // No parsable body: nothing to record.
  }
}

/**
 * Deadline for one OpenRouter request, headers and body together. Nothing else
 * ends a stalled request: no host promises to give up, and neither does fetch.
 * Sized well above the slowest answer a healthy call produces, so only a stalled
 * one is cut. Override per run with OPENROUTER_REQUEST_TIMEOUT_MS.
 */
const DEFAULT_REQUEST_TIMEOUT_MS = 30 * 60_000;

export function openRouterRequestTimeoutMs(
  raw = process.env.OPENROUTER_REQUEST_TIMEOUT_MS,
): number {
  return tokenCap(raw, DEFAULT_REQUEST_TIMEOUT_MS);
}

/** The fetch every OpenRouter call goes through. */
export function buildOpenRouterFetch(
  routing: Record<string, unknown>,
  cost?: CostMeter,
): typeof fetch {
  // Optional shared TPM throttle (same knob shape as openai.ts). Off by
  // default: OpenRouter's TPM headroom is provider-dependent, not a fixed
  // account cap we need to pace against.
  const orEnvVar = "AGENTGG_OPENROUTER_TPM";
  // Always pinned: OpenRouter's cap depends on the routed upstream provider,
  // so a single `x-ratelimit-limit-tokens` value is not a cap to adopt.
  const orLabels = { label: "openrouter", envVar: orEnvVar, pinned: true };
  const { limit: tpmLimit } = resolveTpmLimit(process.env[orEnvVar], 0, orLabels);
  let innerFetch: typeof fetch = fetch;
  if (tpmLimit > 0) {
    announceThrottle(orLabels, tpmLimit);
    innerFetch = createThrottledFetch(new TpmBucket(tpmLimit), orLabels);
  }
  // Inside the routing fetch so its cost read of the body is covered too.
  const deadlineFetch = createDeadlineFetch(innerFetch, openRouterRequestTimeoutMs());
  return createRoutingFetch(routing, deadlineFetch, cost);
}

function buildDetector(config: UserConfig, options: ResolveOptions): Detector {
  const apiKey =
    options.credentials?.openrouterApiKey ??
    config.openrouter?.apiKey ??
    process.env.OPENROUTER_API_KEY;
  if (!apiKey) {
    throw new Error(
      "OpenRouter provider requested but no API key available. Set $OPENROUTER_API_KEY or pass --api-key.",
    );
  }
  const modelName = options.model ?? config.openrouter?.model ?? DEFAULT_MODEL;
  const baseURL = process.env.OPENROUTER_BASE_URL ?? config.openrouter?.baseUrl ?? DEFAULT_BASE_URL;

  // One counter per detector: the fetch wrapper folds each response's charge
  // in, and the usage meter reads the running total at every checkpoint.
  const cost = createCostMeter();
  const routingFetch = buildOpenRouterFetch(
    buildProviderRouting(options.openrouterRouting, config.openrouter?.routing),
    cost,
  );

  const openrouter = createOpenAI({ apiKey, baseURL, fetch: routingFetch });

  return new VercelAgentDetector("openrouter", openrouter(modelName), {
    effort: options.effort,
    thinking: options.thinking,
    verbose: options.verbose,
    validateMaxTurns: options.validateMaxTurns,
    costSource: () => cost.totalUsd(),
  });
}

async function collectCredentials(args: CollectCredentialsArgs): Promise<UserConfig> {
  const { inputs, env, interactive } = args;
  let apiKey = inputs.apiKey?.trim() || env.OPENROUTER_API_KEY?.trim();
  if (!apiKey && interactive) {
    apiKey = (
      await password({ message: "Paste your OpenRouter API key (sk-or-v1-…):", mask: "*" })
    ).trim();
  }
  if (!apiKey) {
    throw new Error("No OpenRouter API key supplied (--api-key or $OPENROUTER_API_KEY required).");
  }
  const model = inputs.model ?? DEFAULT_MODEL;
  // Same values as `agentgg config --openrouter-routing`. Nothing entered
  // keeps the saved routing; `none` clears it.
  const saved = args.existing?.openrouter?.routing;
  let raw = inputs.openrouterRouting?.trim();
  if (raw === undefined && interactive) {
    raw = (
      await input({
        message: saved
          ? `OpenRouter routing as JSON or a file path, or none to clear. Current: ${JSON.stringify(saved)}. Leave empty to keep it:`
          : 'OpenRouter routing as JSON or a file path, for example {"quantizations":["fp8"]}. Leave empty for the default:',
        validate: (v) => {
          if (!v.trim()) return true;
          try {
            parseSavedRouting(v);
            return true;
          } catch (err) {
            return (err as Error).message;
          }
        },
      })
    ).trim();
  }
  const routing = raw ? parseSavedRouting(raw) : (saved ?? null);
  return {
    provider: "openrouter",
    openrouter: { apiKey, model, ...(routing ? { routing } : {}) },
    schemaVersion: 1,
  };
}

function maskValue(s: string): string {
  if (s.length <= 10) return "****";
  return `${s.slice(0, 10)}…${"*".repeat(4)}`;
}

export const openrouterModule: ProviderModule = {
  name: "openrouter",
  label: "OpenRouter",
  description: "OpenRouter-routed models (default: GLM-5.2)",
  defaultModel: DEFAULT_MODEL,
  acceptedFlags: ["api-key"],
  curatedModels: ["z-ai/glm-5.2", "z-ai/glm-5.2:nitro", "z-ai/glm-5"],
  buildDetector,
  collectCredentials,
  formatForList(cfg: UserConfig): string | null {
    if (!cfg.openrouter) return null;
    const model = cfg.openrouter.model ?? "(default)";
    const routing = cfg.openrouter.routing
      ? `  routing=${JSON.stringify(cfg.openrouter.routing)}`
      : "";
    return `openrouter  auth=API key  model=${model}${routing}`;
  },
  redact(cfg: UserConfig): UserConfig {
    if (!cfg.openrouter) return cfg;
    return { ...cfg, openrouter: { ...cfg.openrouter, apiKey: maskValue(cfg.openrouter.apiKey) } };
  },
};
