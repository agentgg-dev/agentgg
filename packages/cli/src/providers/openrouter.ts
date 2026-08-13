import { readFileSync } from "node:fs";
import type { UserConfig } from "@agentgg/core";
import { createOpenAI } from "@ai-sdk/openai";
import { password } from "@inquirer/prompts";
import type { Detector } from "../detect.js";
import { VercelAgentDetector } from "../detectors/index.js";
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
 * OpenRouter `provider` routing block, env-driven so ops can retune
 * without a CLI rebuild. Defaults are tuned for a code-analysis agent:
 * fp8 only (quality on coding/tool-use), require the params we send
 * (drops providers that would silently ignore tool-calls), and route by
 * throughput. An explicit OPENROUTER_PROVIDER_ORDER pins an allow-list
 * and switches off open fallback.
 *
 * OPENROUTER_IGNORE is the escape hatch for a provider whose serving stack
 * is broken for this model. It is a CSV of provider slugs and applies in
 * every branch, because a bad endpoint has to be excluded whether we are
 * sorting or pinning an order. Base slugs match all of a provider's
 * endpoints (`baseten` covers `baseten/fp8` and `baseten/fast`); use the
 * full slug to drop one variant.
 *
 * Why it exists: Novita's GLM-5.2 endpoint returns the model's JSON answer
 * in the `reasoning` channel and leaves `message.content` empty, so every
 * `generateObject` call against it fails with NoObjectGeneratedError while
 * reporting `finishReason: "stop"`. The model answers correctly; the
 * provider files it in the wrong field. That is unfixable from our side and
 * invisible until a scan dies, so it needs to be excludable by config.
 */
export function buildProviderRouting(overrideJson?: string): Record<string, unknown> {
  const quant = csv(process.env.OPENROUTER_QUANTIZATIONS);
  const routing: Record<string, unknown> = {
    quantizations: quant.length > 0 ? quant : ["fp8"],
    require_parameters: true,
  };
  const ignore = csv(process.env.OPENROUTER_IGNORE);
  if (ignore.length > 0) routing.ignore = ignore;
  const order = csv(process.env.OPENROUTER_PROVIDER_ORDER);
  if (order.length > 0) {
    routing.order = order;
    routing.allow_fallbacks = process.env.OPENROUTER_ALLOW_FALLBACKS !== "0";
  } else {
    routing.sort = process.env.OPENROUTER_SORT ?? "throughput";
  }
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
  // env-derived defaults (fp8 + require_parameters survive unless the JSON
  // sets them). A parse failure throws here, before any LLM call or spend.
  if (overrideJson != null && overrideJson.trim() !== "") {
    const override = parseRoutingOverride(readRoutingOverrideText(overrideJson));
    Object.assign(routing, override);
    // `order`/`only` (pin providers) and `sort` are opposing intents; when
    // the JSON pins providers, drop the env-default sort so they don't fight.
    if (routing.order != null || routing.only != null) delete routing.sort;
  }
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
 * Wrap fetch to merge the routing block into chat-completions bodies and
 * add OpenRouter's attribution headers. Mirrors vertex.ts's fetch
 * injection so we stay free of an extra SDK dependency.
 */
export function createRoutingFetch(
  routing: Record<string, unknown>,
  inner: typeof fetch = fetch,
): typeof fetch {
  return async (url, init) => {
    const href = typeof url === "string" ? url : url.toString();
    let nextInit = init;
    if (href.includes("/chat/completions") && init?.body && typeof init.body === "string") {
      try {
        const body = JSON.parse(init.body) as Record<string, unknown>;
        if (body.provider == null) body.provider = routing;
        nextInit = { ...init, body: JSON.stringify(body) };
      } catch {
        // Non-JSON body should never reach chat/completions; pass through.
      }
    }
    const headers = new Headers(nextInit?.headers);
    headers.set("HTTP-Referer", process.env.OPENROUTER_REFERER ?? "https://agentgg.dev");
    headers.set("X-Title", "AgentGG");
    return inner(url, { ...nextInit, headers });
  };
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
  const routingFetch = createRoutingFetch(
    buildProviderRouting(options.openrouterRouting),
    innerFetch,
  );

  const openrouter = createOpenAI({ apiKey, baseURL, fetch: routingFetch });

  return new VercelAgentDetector("openrouter", openrouter(modelName), {
    effort: options.effort,
    thinking: options.thinking,
    verbose: options.verbose,
    validateMaxTurns: options.validateMaxTurns,
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
  return { provider: "openrouter", openrouter: { apiKey, model }, schemaVersion: 1 };
}

function maskValue(s: string): string {
  if (s.length <= 10) return "****";
  return `${s.slice(0, 10)}…${"*".repeat(4)}`;
}

export const openrouterModule: ProviderModule = {
  name: "openrouter",
  label: "OpenRouter",
  description: "OpenRouter-routed open models (default: GLM-5.2, fp8)",
  defaultModel: DEFAULT_MODEL,
  acceptedFlags: ["api-key"],
  curatedModels: ["z-ai/glm-5.2", "z-ai/glm-5.2:nitro", "z-ai/glm-5"],
  buildDetector,
  collectCredentials,
  formatForList(cfg: UserConfig): string | null {
    if (!cfg.openrouter) return null;
    const model = cfg.openrouter.model ?? "(default)";
    return `openrouter  auth=API key  model=${model}`;
  },
  redact(cfg: UserConfig): UserConfig {
    if (!cfg.openrouter) return cfg;
    return { ...cfg, openrouter: { ...cfg.openrouter, apiKey: maskValue(cfg.openrouter.apiKey) } };
  },
};
