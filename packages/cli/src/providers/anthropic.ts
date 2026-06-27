import type { UserConfig } from "@agentgg/core";
import { password } from "@inquirer/prompts";
import type { Detector } from "../detect.js";
import { ClaudeAgentDetector } from "../detectors/index.js";
import type { CollectCredentialsArgs, ProviderModule, ResolveOptions } from "./types.js";

const DEFAULT_MODEL = "claude-sonnet-4-6";

/** OAuth token prefix used by Claude Code. Distinct from regular sk-ant-api keys. */
export function isAnthropicOauthToken(s: string): boolean {
  return s.trim().startsWith("sk-ant-oat");
}

function buildDetector(config: UserConfig, options: ResolveOptions): Detector {
  const apiKey = options.credentials?.anthropicApiKey ?? config.anthropic?.apiKey;
  const oauthToken = options.credentials?.anthropicOauthToken ?? config.anthropic?.oauthToken;

  if (!apiKey && !oauthToken) {
    throw new Error(
      "Anthropic provider requested but no credentials available. Pass --api-key / --oauth-token or run `agentgg init --provider anthropic`.",
    );
  }
  if (apiKey && oauthToken) {
    throw new Error("Anthropic credentials include both an API key and an OAuth token — pick one.");
  }

  const modelName = options.model ?? config.anthropic?.model ?? DEFAULT_MODEL;

  // Both auth types route through claude-agent-sdk for all five Detector
  // methods. Direct API calls via the Vercel SDK aren't viable here: OAuth
  // tokens hitting the API directly get rate-limited, and the Vercel SDK's
  // Anthropic provider rejects `mode: "json"` for structured output.
  return new ClaudeAgentDetector({
    apiKey,
    oauthToken,
    model: modelName,
    verbose: options.verbose,
    validateMaxTurns: options.validateMaxTurns,
    effort: options.effort,
    thinking: options.thinking,
  });
}

async function collectCredentials(args: CollectCredentialsArgs): Promise<UserConfig> {
  const { inputs, env, interactive } = args;
  let apiKey = inputs.apiKey?.trim();
  let oauthToken = inputs.oauthToken?.trim();

  // Auto-route a misplaced OAuth token (someone pasting `sk-ant-oat…`
  // into the API-key prompt) to the right field.
  if (apiKey && isAnthropicOauthToken(apiKey)) {
    oauthToken = oauthToken ?? apiKey;
    apiKey = undefined;
  }

  if (!apiKey && !oauthToken) {
    const envApi = env.ANTHROPIC_API_KEY?.trim();
    const envOauth = env.CLAUDE_CODE_OAUTH_TOKEN?.trim();
    if (envOauth) {
      oauthToken = envOauth;
    } else if (envApi) {
      apiKey = envApi;
    } else if (interactive) {
      const raw = await password({
        message:
          "Paste your Anthropic credential (sk-ant-api… for API key, sk-ant-oat… for OAuth):",
        mask: "*",
      });
      if (isAnthropicOauthToken(raw)) {
        oauthToken = raw;
        console.log("  → Detected: Claude Code OAuth token");
      } else {
        apiKey = raw;
        console.log("  → Detected: Anthropic API key");
      }
    } else {
      throw new Error(
        "No Anthropic credential supplied (--api-key, --oauth-token, $ANTHROPIC_API_KEY, or $CLAUDE_CODE_OAUTH_TOKEN required).",
      );
    }
  }

  if (apiKey && oauthToken) {
    throw new Error("Anthropic credentials include both an API key and an OAuth token — pick one.");
  }

  const model = inputs.model ?? DEFAULT_MODEL;
  return {
    provider: "anthropic",
    anthropic: { apiKey, oauthToken, model },
    schemaVersion: 1,
  };
}

function maskValue(s: string): string {
  if (s.length <= 10) return "****";
  return `${s.slice(0, 10)}…${"*".repeat(4)}`;
}

/**
 * Live model list from the Anthropic Models API (`GET /v1/models`,
 * newest-first). Lets `agentgg init` surface models released after this
 * build without us hand-editing `curatedModels`. Returns [] on any
 * failure (offline, bad key, OAuth not accepted) so the picker falls
 * back to the curated list.
 */
async function listModels(args: {
  config: Partial<UserConfig>;
  env: NodeJS.ProcessEnv;
}): Promise<string[]> {
  const apiKey = args.config.anthropic?.apiKey ?? args.env.ANTHROPIC_API_KEY?.trim();
  const oauthToken = args.config.anthropic?.oauthToken ?? args.env.CLAUDE_CODE_OAUTH_TOKEN?.trim();
  if (!apiKey && !oauthToken) return [];

  const headers: Record<string, string> = { "anthropic-version": "2023-06-01" };
  if (oauthToken) {
    // OAuth tokens authenticate via the Authorization header + the oauth
    // beta flag, not x-api-key. A one-shot list call won't hit the
    // direct-API rate limits the scan path routes around.
    headers.Authorization = `Bearer ${oauthToken}`;
    headers["anthropic-beta"] = "oauth-2025-04-20";
  } else if (apiKey) {
    headers["x-api-key"] = apiKey;
  }

  try {
    const res = await fetch("https://api.anthropic.com/v1/models?limit=100", { headers });
    if (!res.ok) return [];
    const body = (await res.json()) as { data?: Array<{ id?: string }> };
    // API returns newest-first; preserve that order for the picker.
    return (body.data ?? []).map((m) => m.id).filter((id): id is string => Boolean(id));
  } catch {
    return [];
  }
}

export const anthropicModule: ProviderModule = {
  name: "anthropic",
  label: "Claude (Anthropic — API key or OAuth)",
  description: "Anthropic-billed Claude via API key or Claude Pro/Max OAuth",
  defaultModel: DEFAULT_MODEL,
  acceptedFlags: ["api-key", "oauth-token"],
  curatedModels: [
    "claude-opus-4-7",
    "claude-opus-4-6",
    "claude-sonnet-4-6",
    "claude-opus-4-5",
    "claude-sonnet-4-5",
    "claude-haiku-4-5-20251001",
  ],
  listModels,
  buildDetector,
  collectCredentials,
  formatForList(cfg: UserConfig): string | null {
    if (!cfg.anthropic) return null;
    const auth = cfg.anthropic.oauthToken ? "OAuth token" : "API key";
    const model = cfg.anthropic.model ?? "(default)";
    return `anthropic   auth=${auth}  model=${model}`;
  },
  redact(cfg: UserConfig): UserConfig {
    if (!cfg.anthropic) return cfg;
    return {
      ...cfg,
      anthropic: {
        ...cfg.anthropic,
        ...(cfg.anthropic.apiKey ? { apiKey: maskValue(cfg.anthropic.apiKey) } : {}),
        ...(cfg.anthropic.oauthToken ? { oauthToken: maskValue(cfg.anthropic.oauthToken) } : {}),
      },
    };
  },
};
