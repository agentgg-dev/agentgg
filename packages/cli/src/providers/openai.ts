import type { UserConfig } from "@agentgg/core";
import { createOpenAI } from "@ai-sdk/openai";
import { password } from "@inquirer/prompts";
import type { Detector } from "../detect.js";
import { VercelAgentDetector } from "../detectors/index.js";
import { createThrottledFetch, TpmBucket } from "../tpm-bucket.js";
import type { CollectCredentialsArgs, ProviderModule, ResolveOptions } from "./types.js";

const DEFAULT_MODEL = "gpt-5";

function buildDetector(config: UserConfig, options: ResolveOptions): Detector {
  const apiKey = options.credentials?.openaiApiKey ?? config.openai?.apiKey;
  if (!apiKey) {
    throw new Error(
      "OpenAI provider requested but no API key available. Pass --api-key or run `agentgg init --provider openai`.",
    );
  }
  const modelName = options.model ?? config.openai?.model ?? DEFAULT_MODEL;
  // Shared TPM bucket so concurrent workers cooperate on one rolling
  // 60-second token budget instead of independently slamming the cap.
  // Override via AGENTGG_OPENAI_TPM — default 30000 matches OpenAI Tier 1.
  const tpmLimit = Number.parseInt(process.env.AGENTGG_OPENAI_TPM ?? "30000", 10);
  const openai =
    tpmLimit > 0
      ? createOpenAI({ apiKey, fetch: createThrottledFetch(new TpmBucket(tpmLimit)) })
      : createOpenAI({ apiKey });
  return new VercelAgentDetector("openai", openai(modelName), {
    effort: options.effort,
    thinking: options.thinking,
    verbose: options.verbose,
  });
}

async function collectCredentials(args: CollectCredentialsArgs): Promise<UserConfig> {
  const { inputs, env, interactive } = args;
  let apiKey = inputs.apiKey?.trim();
  if (!apiKey) {
    const envApi = env.OPENAI_API_KEY?.trim();
    if (envApi) {
      apiKey = envApi;
    } else if (interactive) {
      apiKey = (await password({ message: "Paste your OpenAI API key (sk-…):", mask: "*" })).trim();
    } else {
      throw new Error("No OpenAI API key supplied (--api-key or $OPENAI_API_KEY required).");
    }
  }
  if (!apiKey) {
    throw new Error("openai provider selected but no API key provided");
  }
  const model = inputs.model ?? DEFAULT_MODEL;
  return {
    provider: "openai",
    openai: { apiKey, model },
    schemaVersion: 1,
  };
}

function maskValue(s: string): string {
  if (s.length <= 10) return "****";
  return `${s.slice(0, 10)}…${"*".repeat(4)}`;
}

export const openaiModule: ProviderModule = {
  name: "openai",
  label: "OpenAI / Codex",
  description: "OpenAI-billed GPT models",
  defaultModel: DEFAULT_MODEL,
  acceptedFlags: ["api-key"],
  curatedModels: ["gpt-5", "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "o1", "o3"],
  buildDetector,
  collectCredentials,
  formatForList(cfg: UserConfig): string | null {
    if (!cfg.openai) return null;
    const model = cfg.openai.model ?? "(default)";
    return `openai      auth=API key  model=${model}`;
  },
  redact(cfg: UserConfig): UserConfig {
    if (!cfg.openai) return cfg;
    return {
      ...cfg,
      openai: { ...cfg.openai, apiKey: maskValue(cfg.openai.apiKey) },
    };
  },
};
