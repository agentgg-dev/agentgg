import type { UserConfig } from "@agentgg/core";
import { createOpenAI } from "@ai-sdk/openai";
import { password } from "@inquirer/prompts";
import type { Detector } from "../detect.js";
import { VercelAgentDetector } from "../detectors/index.js";
import { createThrottledFetch, TpmBucket } from "../tpm-bucket.js";
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
 */
export function buildProviderRouting(): Record<string, unknown> {
  const quant = csv(process.env.OPENROUTER_QUANTIZATIONS);
  const routing: Record<string, unknown> = {
    quantizations: quant.length > 0 ? quant : ["fp8"],
    require_parameters: true,
  };
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
  return routing;
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
  const tpmLimit = Number.parseInt(process.env.AGENTGG_OPENROUTER_TPM ?? "0", 10);
  const innerFetch = tpmLimit > 0 ? createThrottledFetch(new TpmBucket(tpmLimit)) : fetch;
  const routingFetch = createRoutingFetch(buildProviderRouting(), innerFetch);

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
