import type { UserConfig } from "@agentgg/core";
import { input } from "@inquirer/prompts";
import { createOllama } from "ollama-ai-provider";
import type { Detector } from "../detect.js";
import { MultiProviderDetector, VercelAgentDetector } from "../detectors/index.js";
import type { CollectCredentialsArgs, ProviderModule, ResolveOptions } from "./types.js";

const DEFAULT_MODEL = "qwen2.5";
const DEFAULT_BASE_URL = "http://localhost:11434";

// Ollama's default num_ctx (2048) chokes the hunt loop — bump to a
// workable size for tool-calling and file-mode reads. See llm.ts
// history for the chat-template-leakage bug this prevents.
const NUM_CTX = 16384;

function buildDetector(config: UserConfig, options: ResolveOptions): Detector {
  const baseUrl = options.credentials?.ollamaBaseUrl ?? config.ollama?.baseUrl;
  if (!baseUrl) {
    throw new Error(
      "Ollama provider requested but no base URL available. Pass --base-url or run `agentgg init --provider ollama`.",
    );
  }
  const modelName = options.model ?? config.ollama?.model ?? DEFAULT_MODEL;
  const ollama = createOllama({ baseURL: `${baseUrl}/api` });
  // structuredOutputs:true is required for generateObject (file mode);
  // tool-calling sessions must NOT set it, or the model emits the
  // example JSON template verbatim instead of reasoning about tool results.
  const structuredModel = ollama(modelName, { structuredOutputs: true, numCtx: NUM_CTX });
  const toolModel = ollama(modelName, { numCtx: NUM_CTX });
  const baseOpts = { effort: options.effort, thinking: options.thinking };
  const fileDetector = new MultiProviderDetector("ollama", structuredModel, baseOpts);
  const agentDetector = new VercelAgentDetector("ollama", toolModel, {
    ...baseOpts,
    verbose: options.verbose,
    structuredModel,
  });
  return {
    name: "ollama",
    // Tool-using work (recon survey, agent runs) goes through the Vercel
    // tool-loop detector (best-effort JSON); tool-less work (precondition
    // gate, validate, score) uses generateObject for strict output.
    recon: (args) => agentDetector.recon(args),
    checkPrecondition: (args) => fileDetector.checkPrecondition(args),
    runAgent: (args) => agentDetector.runAgent(args),
    validateFinding: (args) => fileDetector.validateFinding(args),
    validateFindingByScope: (args) => fileDetector.validateFindingByScope(args),
    scoreFinding: (args) => fileDetector.scoreFinding(args),
    dedupeFindings: (args) => fileDetector.dedupeFindings(args),
  };
}

async function collectCredentials(args: CollectCredentialsArgs): Promise<UserConfig> {
  const { inputs, env, interactive } = args;
  let baseUrl = inputs.baseUrl?.trim();
  if (!baseUrl) {
    if (interactive) {
      baseUrl = (
        await input({
          message: "Ollama base URL:",
          default: env.OLLAMA_BASE_URL ?? DEFAULT_BASE_URL,
        })
      ).trim();
    } else {
      baseUrl = env.OLLAMA_BASE_URL ?? DEFAULT_BASE_URL;
    }
  }
  if (!baseUrl) {
    throw new Error("ollama provider selected but no base URL provided");
  }
  const model = inputs.model ?? DEFAULT_MODEL;
  return {
    provider: "ollama",
    ollama: { baseUrl, model },
    schemaVersion: 1,
  };
}

async function listModels(args: {
  config: Partial<UserConfig>;
  env: NodeJS.ProcessEnv;
}): Promise<string[]> {
  const baseUrl = args.config.ollama?.baseUrl ?? args.env.OLLAMA_BASE_URL ?? DEFAULT_BASE_URL;
  try {
    const res = await fetch(`${baseUrl}/api/tags`);
    if (!res.ok) return [];
    const data = (await res.json()) as { models?: Array<{ name: string }> };
    return (data.models ?? []).map((m) => m.name).sort();
  } catch {
    return [];
  }
}

export const ollamaModule: ProviderModule = {
  name: "ollama",
  label: "Ollama (local, free, private)",
  description: "Self-hosted models via an Ollama server",
  defaultModel: DEFAULT_MODEL,
  acceptedFlags: ["base-url"],
  buildDetector,
  collectCredentials,
  listModels,
  formatForList(cfg: UserConfig): string | null {
    if (!cfg.ollama) return null;
    const model = cfg.ollama.model ?? "(default)";
    return `ollama      baseUrl=${cfg.ollama.baseUrl}  model=${model}`;
  },
  redact(cfg: UserConfig): UserConfig {
    return cfg; // Ollama has no secrets to mask.
  },
};
