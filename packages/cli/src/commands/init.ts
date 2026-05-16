import type { Command } from "commander";
import { input, password, select, confirm } from "@inquirer/prompts";
import {
  type Provider,
  type UserConfig,
  loadUserConfig,
  saveUserConfig,
} from "@agentgg/core";

export const DEFAULT_MODELS = {
  anthropic: "claude-sonnet-4-6",
  openai: "gpt-5",
  ollama: "qwen2.5",
} as const;

const DEFAULT_OLLAMA_URL = "http://localhost:11434";

// Models known to reliably handle tool-calling for hunt/walker mode.
// General rule: ≥14B parameters. Below that, instruction following is
// too inconsistent for multi-step agentic investigation — use file
// mode only with smaller models.
const OLLAMA_HUNT_CAPABLE = [
  "qwen2.5:14b", "qwen2.5:32b", "qwen2.5:72b",
  "qwen2.5-coder:14b", "qwen2.5-coder:32b",
  "llama3.1:70b", "llama3.3:70b",
  "deepseek-r1:14b", "deepseek-r1:32b", "deepseek-r1:70b", "deepseek-r1:671b",
  "gemma3:12b", "gemma3:27b",
  "phi4",
  "mistral-large",
  "command-r-plus",
];

function isHuntCapable(model: string): boolean {
  const lower = model.toLowerCase();
  return OLLAMA_HUNT_CAPABLE.some(
    (cap) => lower === cap || lower.startsWith(`${cap}:`) || lower.startsWith(`${cap}-`),
  );
}

// ------- live model-list fetchers -------

const ANTHROPIC_CURATED = [
  "claude-opus-4-7",
  "claude-opus-4-6",
  "claude-sonnet-4-6",
  "claude-opus-4-5",
  "claude-sonnet-4-5",
  "claude-haiku-4-5-20251001",
];
const OPENAI_CURATED = ["gpt-5", "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "o1", "o3"];

async function fetchOllamaModels(baseUrl: string): Promise<string[]> {
  try {
    const res = await fetch(`${baseUrl}/api/tags`);
    if (!res.ok) return [];
    const data = (await res.json()) as { models?: Array<{ name: string }> };
    return (data.models ?? []).map((m) => m.name).sort();
  } catch {
    return [];
  }
}

async function collectModel(provider: Provider, initInput: InitInput): Promise<string> {
  const defaultModel = DEFAULT_MODELS[provider];

  if (provider === "ollama") {
    const installed = await fetchOllamaModels(initInput.ollamaUrl ?? DEFAULT_OLLAMA_URL);
    if (installed.length === 0) {
      // Ollama not running or no models pulled yet — free-text fallback
      return input({ message: "Default model:", default: defaultModel });
    }
    console.log(
      "\nNote: hunt and walker agents need strong tool-calling and instruction\n" +
      "following. Models ≥14B are recommended (qwen2.5:32b, llama3.1:70b,\n" +
      "deepseek-r1:14b…). Smaller models are reliable for file-mode only.\n",
    );
    const capable = installed.filter(isHuntCapable);
    const rest = installed.filter((m) => !isHuntCapable(m));
    const choices = [
      ...capable.map((m) => ({ name: `${m}  ← recommended (all modes)`, value: m })),
      ...rest.map((m) => ({
        name: capable.length > 0 ? `${m}  (file mode only)` : `${m}  ⚠ file mode only`,
        value: m,
      })),
      { name: "Other (enter manually)", value: "__custom__" },
    ];
    const selected = await select<string>({ message: "Default model:", choices });
    if (selected === "__custom__") {
      return input({ message: "Model name:", default: defaultModel });
    }
    return selected;
  }

  const models = provider === "anthropic" ? ANTHROPIC_CURATED : OPENAI_CURATED;
  const choices = [
    ...models.map((m) => ({ name: m, value: m })),
    { name: "Other (enter manually)", value: "__custom__" },
  ];
  const selected = await select<string>({ message: "Default model:", choices });
  if (selected === "__custom__") {
    return input({ message: "Model name:", default: defaultModel });
  }
  return selected;
}

/** OAuth token prefix used by Claude Code. Distinct from regular sk-ant-api keys. */
export function isAnthropicOauthToken(s: string): boolean {
  return s.trim().startsWith("sk-ant-oat");
}

/**
 * Plain inputs the wizard collects. Kept as a separate type so tests
 * can build a UserConfig without going through Inquirer.
 */
export interface InitInput {
  provider: Provider;
  anthropicKey?: string;
  anthropicOauthToken?: string;
  openaiKey?: string;
  ollamaUrl?: string;
  model?: string;
}

/**
 * Pure builder. Turns user inputs into a UserConfig "patch" — a single
 * provider block (with credentials). The caller merges this into any
 * existing config so other providers aren't wiped on re-init.
 *
 * Auto-routes a misplaced OAuth token (someone pasting `sk-ant-oat…`
 * into the API-key prompt) to the right field.
 */
export function buildUserConfig(input: InitInput): UserConfig {
  const model = input.model ?? DEFAULT_MODELS[input.provider];

  switch (input.provider) {
    case "anthropic": {
      let apiKey = input.anthropicKey?.trim();
      let oauthToken = input.anthropicOauthToken?.trim();
      if (apiKey && isAnthropicOauthToken(apiKey)) {
        oauthToken = oauthToken ?? apiKey;
        apiKey = undefined;
      }
      if (!apiKey && !oauthToken) {
        throw new Error(
          "anthropic provider selected but no API key or OAuth token provided",
        );
      }
      if (apiKey && oauthToken) {
        throw new Error(
          "anthropic provider got both an API key and an OAuth token — pick one",
        );
      }
      return {
        provider: "anthropic",
        anthropic: { apiKey, oauthToken, model },
        schemaVersion: 1,
      };
    }
    case "openai": {
      if (!input.openaiKey || !input.openaiKey.trim()) {
        throw new Error("openai provider selected but no API key provided");
      }
      return {
        provider: "openai",
        openai: { apiKey: input.openaiKey.trim(), model },
        schemaVersion: 1,
      };
    }
    case "ollama": {
      const baseUrl = (input.ollamaUrl ?? DEFAULT_OLLAMA_URL).trim();
      if (!baseUrl) {
        throw new Error("ollama provider selected but no base URL provided");
      }
      return {
        provider: "ollama",
        ollama: { baseUrl, model },
        schemaVersion: 1,
      };
    }
  }
}

/**
 * Merge a freshly-built single-provider config into an existing one.
 *
 * Behavior:
 *   - Keeps every provider block already present so adding a second
 *     provider doesn't wipe the first
 *   - Replaces the credential block for the provider being added
 *   - Updates the active `provider` to the one being added
 *
 * If `existing` is undefined, this is a passthrough.
 */
export function mergeUserConfig(
  fresh: UserConfig,
  existing: UserConfig | null,
): UserConfig {
  if (!existing) return fresh;
  return {
    ...existing,
    provider: fresh.provider,
    anthropic: fresh.anthropic ?? existing.anthropic,
    openai: fresh.openai ?? existing.openai,
    ollama: fresh.ollama ?? existing.ollama,
    schemaVersion: 1,
  };
}

export interface InitOpts {
  provider?: string;
  apiKey?: string;
  oauthToken?: string;
  baseUrl?: string;
  model?: string;
}

/**
 * Interactive (or fully-flagged) init.
 *
 * Behavior is auto-detected from what's supplied:
 *   - Nothing on the CLI → fully interactive wizard
 *   - Provider + credential supplied via flags/env → fully non-interactive
 *   - Partial (e.g. `--provider anthropic` with no credential) → prompts for what's missing
 *
 * Re-running init never wipes other providers.
 */
export async function runInit(
  opts: InitOpts = {},
  env: NodeJS.ProcessEnv = process.env,
): Promise<string> {
  const explicitProvider = opts.provider as Provider | undefined;
  const credentialCheck = hasCredentialFlag(opts, env);
  const nonInteractive = Boolean(explicitProvider) && credentialCheck(explicitProvider);

  if (!nonInteractive) console.log("Welcome to agentgg.\n");

  const existing = loadUserConfig(env);
  if (existing && !nonInteractive) {
    console.log(`Existing config found. Current default provider: ${existing.provider}.`);
    console.log(`  Configured: ${listConfiguredProviders(existing).join(", ")}`);
    console.log("");
  }

  const provider =
    explicitProvider ??
    (await select<Provider>({
      message: existing
        ? "Add or update which provider?"
        : "Which LLM provider would you like to use?",
      choices: [
        { name: "Claude (Anthropic — API key or OAuth)", value: "anthropic" },
        { name: "OpenAI / Codex", value: "openai" },
        { name: "Ollama (local, free, private)", value: "ollama" },
      ],
    }));

  const initInput: InitInput = { provider };

  if (provider === "anthropic") {
    await collectAnthropicCredential(initInput, opts, env, nonInteractive);
  } else if (provider === "openai") {
    initInput.openaiKey = await collectKey({
      flagValue: opts.apiKey,
      envVar: "OPENAI_API_KEY",
      env,
      nonInteractive,
      prompt: "Paste your OpenAI API key (sk-…):",
    });
  } else {
    initInput.ollamaUrl =
      opts.baseUrl ??
      (nonInteractive
        ? (env.OLLAMA_BASE_URL ?? DEFAULT_OLLAMA_URL)
        : await input({
            message: "Ollama base URL:",
            default: env.OLLAMA_BASE_URL ?? DEFAULT_OLLAMA_URL,
          }));
  }

  if (opts.model) {
    initInput.model = opts.model;
  } else if (!nonInteractive) {
    initInput.model = await collectModel(provider, initInput);
  }

  const fresh = buildUserConfig(initInput);
  const merged = mergeUserConfig(fresh, existing);
  const path = saveUserConfig(merged, env);

  console.log(`\n✓ Saved config to ${path}`);
  console.log(`  Default provider: ${merged.provider}`);
  console.log(`  Configured providers: ${listConfiguredProviders(merged).join(", ")}`);
  console.log(`\nNext: agentgg scan <path>`);
  return path;
}

/**
 * Returns a predicate: "given a chosen provider, can we get credentials
 * for it without prompting?" Checks the matching flag first, falls
 * through to relevant env vars.
 */
function hasCredentialFlag(
  opts: InitOpts,
  env: NodeJS.ProcessEnv,
): (provider: Provider | undefined) => boolean {
  return (provider) => {
    if (!provider) return false;
    if (provider === "anthropic") {
      return Boolean(
        opts.apiKey?.trim() ||
          opts.oauthToken?.trim() ||
          env.ANTHROPIC_API_KEY ||
          env.CLAUDE_CODE_OAUTH_TOKEN,
      );
    }
    if (provider === "openai") {
      return Boolean(opts.apiKey?.trim() || env.OPENAI_API_KEY);
    }
    if (provider === "ollama") {
      return true; // Default URL works out of the box.
    }
    return false;
  };
}

function listConfiguredProviders(cfg: UserConfig): string[] {
  const out: string[] = [];
  if (cfg.anthropic) {
    const auth = cfg.anthropic.oauthToken ? "oauth" : "api-key";
    out.push(`anthropic (${auth})`);
  }
  if (cfg.openai) out.push("openai");
  if (cfg.ollama) out.push(`ollama (${cfg.ollama.baseUrl})`);
  return out;
}

async function collectKey(args: {
  flagValue?: string;
  envVar: string;
  env: NodeJS.ProcessEnv;
  nonInteractive: boolean;
  prompt: string;
}): Promise<string> {
  if (args.flagValue && args.flagValue.trim()) return args.flagValue.trim();
  const envValue = args.env[args.envVar];
  if (args.nonInteractive) {
    if (envValue && envValue.trim()) return envValue.trim();
    throw new Error(
      `No API key supplied (--api-key flag, $${args.envVar}, or interactive prompt required).`,
    );
  }
  if (envValue && (await confirmReuseEnv(args.envVar))) return envValue;
  return password({ message: args.prompt, mask: "*" });
}

async function collectAnthropicCredential(
  initInput: InitInput,
  opts: InitOpts,
  env: NodeJS.ProcessEnv,
  nonInteractive: boolean,
): Promise<void> {
  // Flag-direct paths win first.
  if (opts.oauthToken && opts.oauthToken.trim()) {
    initInput.anthropicOauthToken = opts.oauthToken.trim();
    return;
  }
  if (opts.apiKey && opts.apiKey.trim()) {
    const v = opts.apiKey.trim();
    if (isAnthropicOauthToken(v)) initInput.anthropicOauthToken = v;
    else initInput.anthropicKey = v;
    return;
  }

  // Env vars next.
  const envApi = env.ANTHROPIC_API_KEY;
  const envOauth = env.CLAUDE_CODE_OAUTH_TOKEN;

  if (nonInteractive) {
    if (envOauth) {
      initInput.anthropicOauthToken = envOauth;
      return;
    }
    if (envApi) {
      initInput.anthropicKey = envApi;
      return;
    }
    throw new Error(
      "No Anthropic credential supplied (--api-key, --oauth-token, $ANTHROPIC_API_KEY, or $CLAUDE_CODE_OAUTH_TOKEN required).",
    );
  }

  if (envOauth && (await confirmReuseEnv("CLAUDE_CODE_OAUTH_TOKEN"))) {
    initInput.anthropicOauthToken = envOauth;
    console.log("  → Using Claude Code OAuth token (Claude Pro/Max subscription)");
    return;
  }
  if (envApi && (await confirmReuseEnv("ANTHROPIC_API_KEY"))) {
    initInput.anthropicKey = envApi;
    console.log("  → Using Anthropic API key");
    return;
  }

  const raw = await password({
    message:
      "Paste your Anthropic credential (sk-ant-api… for API key, sk-ant-oat… for OAuth):",
    mask: "*",
  });
  if (isAnthropicOauthToken(raw)) {
    initInput.anthropicOauthToken = raw;
    console.log("  → Detected: Claude Code OAuth token");
  } else {
    initInput.anthropicKey = raw;
    console.log("  → Detected: Anthropic API key");
  }
}

async function confirmReuseEnv(varName: string): Promise<boolean> {
  return confirm({
    message: `Reuse existing $${varName} from your environment?`,
    default: true,
  });
}

export function registerInitCommand(program: Command): void {
  program
    .command("init")
    .description(
      "first-run setup wizard, or non-interactive provider add. Pass enough flags (--provider + credential) to skip prompts entirely.",
    )
    .option(
      "--provider <name>",
      "Provider to configure: anthropic | openai | ollama",
    )
    .option(
      "--api-key <key>",
      "API key for the chosen provider (sk-ant-api… / sk-…). For Anthropic, also accepts an sk-ant-oat… OAuth token.",
    )
    .option(
      "--oauth-token <token>",
      "Anthropic OAuth token (sk-ant-oat…). Same effect as passing it via --api-key.",
    )
    .option(
      "--base-url <url>",
      "Ollama base URL (default http://localhost:11434)",
    )
    .option("--model <name>", "Default model for the chosen provider")
    .action(async (opts: InitOpts) => {
      try {
        await runInit(opts);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg.includes("force closed") || msg.includes("User force closed")) {
          console.log("\nInit cancelled.");
          process.exit(130);
        }
        console.error(`init failed: ${msg}`);
        process.exit(1);
      }
    });
}
