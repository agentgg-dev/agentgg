import type { Provider, UserConfig } from "@agentgg/core";
import { createAnthropic } from "@ai-sdk/anthropic";
import { createOpenAI } from "@ai-sdk/openai";
import { createOllama } from "ollama-ai-provider";
import type { Detector } from "./detect.js";
import { ClaudeAgentDetector, MultiProviderDetector } from "./detectors/index.js";

const FALLBACK_MODELS = {
  anthropic: "claude-sonnet-4-6",
  openai: "gpt-5",
  ollama: "llama3.1",
} as const;

/**
 * One-shot CLI credential overrides. Apply for the lifetime of a
 * single scan invocation; not persisted. Useful for CI runs where the
 * caller wants to avoid writing `~/.agentgg/config.json`.
 */
export interface CredentialOverrides {
  anthropicApiKey?: string;
  anthropicOauthToken?: string;
  openaiApiKey?: string;
  ollamaBaseUrl?: string;
}

export interface ResolveOptions {
  /** Force this provider for this run regardless of saved config. */
  provider?: string;
  /** Override the model used for detection. */
  model?: string;
  /** One-shot credentials supplied via CLI flag instead of saved config. */
  credentials?: CredentialOverrides;
  /** Stream tool-use messages to stdout during hunt-mode runs. */
  verbose?: boolean;
  /** Turn cap for each validator call. */
  validateMaxTurns?: number;
  /** SDK `effort` setting for all tool-using calls. */
  effort?: "low" | "medium" | "high" | "max";
  /** SDK `thinking` setting for all tool-using calls. */
  thinking?: "off" | "adaptive" | "enabled";
}

/**
 * Resolve the Detector for this scan run.
 *
 *   Provider resolution: `options.provider` (from --provider) wins;
 *   otherwise `config.provider` from `~/.agentgg/config.json`.
 *
 *   Credential resolution per provider:
 *     1. `options.credentials.*` (CLI --api-key / --oauth-token / --base-url)
 *     2. The corresponding block in `config`
 *
 * The same Detector handles both `mode: "file"` and `mode: "hunt"`
 * agents — the dispatch happens inside the agent's execution path
 * (Detector.detectFile vs Detector.hunt), not here.
 */
export function resolveDetector(
  config: UserConfig,
  options: ResolveOptions = {},
): Detector {
  const provider = (options.provider ?? config.provider) as Provider;

  switch (provider) {
    case "anthropic":
      return buildAnthropicDetector(config, options);
    case "openai":
      return buildOpenAIDetector(config, options);
    case "ollama":
      return buildOllamaDetector(config, options);
    default:
      throw new Error(`Unknown provider: ${provider}`);
  }
}

function buildAnthropicDetector(
  config: UserConfig,
  options: ResolveOptions,
): Detector {
  // Credentials: CLI flag wins, then saved config.
  const apiKey = options.credentials?.anthropicApiKey ?? config.anthropic?.apiKey;
  const oauthToken =
    options.credentials?.anthropicOauthToken ?? config.anthropic?.oauthToken;

  if (!apiKey && !oauthToken) {
    throw new Error(
      "Anthropic provider requested but no credentials available. Pass --api-key / --oauth-token or run `agentgg init --provider anthropic`.",
    );
  }
  if (apiKey && oauthToken) {
    throw new Error(
      "Anthropic credentials include both an API key and an OAuth token — pick one.",
    );
  }

  const modelName = options.model ?? config.anthropic?.model ?? FALLBACK_MODELS.anthropic;

  // OAuth-only path: claude-agent-sdk for both modes. Direct API
  // calls with an OAuth token get rate-limited by Anthropic.
  if (oauthToken && !apiKey) {
    return new ClaudeAgentDetector({
      oauthToken,
      model: modelName,
      verbose: options.verbose,
      validateMaxTurns: options.validateMaxTurns,
      effort: options.effort,
      thinking: options.thinking,
    });
  }

  // API-key path: hybrid Detector. Vercel SDK serves file-mode calls
  // (cheap structured output), claude-agent-sdk serves hunt-mode calls
  // (tool access). The agent's `mode` decides which method is invoked
  // upstream; we just provide both.
  if (apiKey) {
    const anthropic = createAnthropic({ apiKey });
    const fileDetector = new MultiProviderDetector("anthropic-api", anthropic(modelName));
    const huntDetector = new ClaudeAgentDetector({
      apiKey,
      model: modelName,
      verbose: options.verbose,
      validateMaxTurns: options.validateMaxTurns,
      effort: options.effort,
      thinking: options.thinking,
    });
    return {
      name: "anthropic-api",
      detectFile: (args) => fileDetector.detectFile(args),
      hunt: (args) => huntDetector.hunt(args),
      // Walker mode needs tool access; route through the agent SDK
      // just like hunt does.
      investigate: (args) => huntDetector.investigate(args),
      validateFinding: (args) => fileDetector.validateFinding(args),
    };
  }

  throw new Error("anthropic detector: no credentials");
}

function buildOpenAIDetector(
  config: UserConfig,
  options: ResolveOptions,
): Detector {
  const apiKey = options.credentials?.openaiApiKey ?? config.openai?.apiKey;
  if (!apiKey) {
    throw new Error(
      "OpenAI provider requested but no API key available. Pass --api-key or run `agentgg init --provider openai`.",
    );
  }
  const modelName = options.model ?? config.openai?.model ?? FALLBACK_MODELS.openai;
  const openai = createOpenAI({ apiKey });
  return new MultiProviderDetector("openai", openai(modelName));
}

function buildOllamaDetector(
  config: UserConfig,
  options: ResolveOptions,
): Detector {
  const baseUrl = options.credentials?.ollamaBaseUrl ?? config.ollama?.baseUrl;
  if (!baseUrl) {
    throw new Error(
      "Ollama provider requested but no base URL available. Pass --base-url or run `agentgg init --provider ollama`.",
    );
  }
  const modelName = options.model ?? config.ollama?.model ?? FALLBACK_MODELS.ollama;
  const ollama = createOllama({ baseURL: `${baseUrl}/api` });
  return new MultiProviderDetector("ollama", ollama(modelName, { structuredOutputs: true }));
}
