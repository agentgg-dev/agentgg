import { loadUserConfig, type Provider, saveUserConfig, type UserConfig } from "@agentgg/core";
import { input, select } from "@inquirer/prompts";
import type { Command } from "commander";
import { isAnthropicOauthToken } from "../providers/anthropic.js";
import {
  allProviderModules,
  getProviderModule,
  type InitInputs,
  listConfiguredProviders,
} from "../providers/index.js";

// Re-exported for back-compat with the old test surface. New code should
// reach for `getProviderModule(...).defaultModel` instead.
export const DEFAULT_MODELS = Object.fromEntries(
  allProviderModules().map((m) => [m.name, m.defaultModel]),
) as Record<Provider, string>;

export { isAnthropicOauthToken };

/**
 * Legacy pure builder. Same shape the old init.ts exposed for tests:
 * takes the plain user inputs and returns a single-provider UserConfig
 * fragment, with no prompts, env-var reads, or async work. New code
 * uses `getProviderModule(name).collectCredentials({...})` instead.
 */
export interface InitInput {
  provider: Provider;
  anthropicKey?: string;
  anthropicOauthToken?: string;
  openaiKey?: string;
  ollamaUrl?: string;
  vertexProject?: string;
  model?: string;
}

const DEFAULT_OLLAMA_URL = "http://localhost:11434";

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
        throw new Error("anthropic provider selected but no API key or OAuth token provided");
      }
      if (apiKey && oauthToken) {
        throw new Error("anthropic provider got both an API key and an OAuth token — pick one");
      }
      return {
        provider: "anthropic",
        anthropic: { apiKey, oauthToken, model },
        schemaVersion: 1,
      };
    }
    case "openai": {
      if (!input.openaiKey?.trim()) {
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
      return {
        provider: "ollama",
        ollama: { baseUrl, model },
        schemaVersion: 1,
      };
    }
    case "bedrock": {
      // Tests don't exercise this branch yet; the wizard (collectCredentials)
      // is the supported path for bedrock setup. Kept for completeness so
      // the switch is exhaustive.
      return {
        provider: "bedrock",
        bedrock: { model },
        schemaVersion: 1,
      };
    }
    case "vertex": {
      const project = input.vertexProject?.trim();
      if (!project) {
        throw new Error("vertex provider selected but no GCP project provided");
      }
      return {
        provider: "vertex",
        vertex: { project, model },
        schemaVersion: 1,
      };
    }
  }
}

// Models known to reliably handle tool-calling for Ollama hunt/walker
// mode. General rule: ≥14B parameters. Below that, instruction following
// is too inconsistent for multi-step agentic investigation. Lives here
// (not on the ollama module) because it's purely a wizard-UX hint.
const OLLAMA_HUNT_CAPABLE = [
  "qwen2.5:14b",
  "qwen2.5:32b",
  "qwen2.5:72b",
  "qwen2.5-coder:14b",
  "qwen2.5-coder:32b",
  "llama3.1:70b",
  "llama3.3:70b",
  "deepseek-r1:14b",
  "deepseek-r1:32b",
  "deepseek-r1:70b",
  "deepseek-r1:671b",
  "gemma3:12b",
  "gemma3:27b",
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

/** Pick a model interactively. Uses the module's listModels() when available, falls back to curatedModels. */
async function pickModel(
  provider: Provider,
  inputs: InitInputs,
  env: NodeJS.ProcessEnv,
): Promise<string> {
  const mod = getProviderModule(provider);
  const defaultModel = mod.defaultModel;

  // Provider exposes a live model list (Ollama): use it with a
  // hunt-capability annotation specific to Ollama.
  if (mod.listModels) {
    // Build a partial UserConfig from the credentials we've collected so
    // far so listModels can use the right base URL etc.
    const partial: Partial<UserConfig> = inputs.baseUrl
      ? { ollama: { baseUrl: inputs.baseUrl, model: defaultModel } }
      : {};
    const installed = await mod.listModels({ config: partial, env });
    if (installed.length === 0) {
      return input({ message: "Default model:", default: defaultModel });
    }
    if (provider === "ollama") {
      console.log(
        "\nNote: agents are tool-using (Read/Glob/Grep), so they need strong\n" +
          "tool-calling and instruction following. Models ≥14B are recommended\n" +
          "(qwen2.5:32b, llama3.1:70b, deepseek-r1:14b…). Smaller models are less\n" +
          "reliable at driving the tool loop.\n",
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
    // Non-Ollama provider with listModels: present a plain choice list.
    const choices = [
      ...installed.map((m) => ({ name: m, value: m })),
      { name: "Other (enter manually)", value: "__custom__" },
    ];
    const selected = await select<string>({ message: "Default model:", choices });
    if (selected === "__custom__") {
      return input({ message: "Model name:", default: defaultModel });
    }
    return selected;
  }

  const curated = mod.curatedModels ?? [];
  if (curated.length === 0) {
    return input({ message: "Default model:", default: defaultModel });
  }
  const choices = [
    ...curated.map((m) => ({ name: m, value: m })),
    { name: "Other (enter manually)", value: "__custom__" },
  ];
  const selected = await select<string>({ message: "Default model:", choices });
  if (selected === "__custom__") {
    return input({ message: "Model name:", default: defaultModel });
  }
  return selected;
}

export interface InitOpts {
  provider?: string;
  apiKey?: string;
  oauthToken?: string;
  baseUrl?: string;
  region?: string;
  awsAccessKeyId?: string;
  awsSecretAccessKey?: string;
  awsSessionToken?: string;
  project?: string;
  model?: string;
}

/**
 * Merge a freshly-built single-provider config into an existing one.
 * Walks the registry so every provider's block is preserved on re-init.
 *
 *   - Keeps every provider block already present
 *   - Replaces the credential block for the provider being added
 *   - Updates the active `provider` to the one being added
 */
export function mergeUserConfig(fresh: UserConfig, existing: UserConfig | null): UserConfig {
  if (!existing) return fresh;
  const merged: UserConfig = { ...existing, provider: fresh.provider, schemaVersion: 1 };
  for (const mod of allProviderModules()) {
    const key = mod.name as keyof UserConfig;
    // Each provider's block lives at UserConfig[name]; if `fresh`
    // populated it (i.e. this is the active provider), use that;
    // otherwise keep whatever was already saved.
    (merged as Record<string, unknown>)[key] =
      (fresh as Record<string, unknown>)[key] ?? (existing as Record<string, unknown>)[key];
  }
  return merged;
}

/**
 * Interactive (or fully-flagged) init.
 *
 * Behavior is auto-detected from what's supplied:
 *   - Nothing on the CLI → fully interactive wizard
 *   - Provider + credential supplied via flags/env → fully non-interactive
 *   - Partial → prompts for what's missing
 *
 * Re-running init never wipes other providers.
 */
export async function runInit(
  opts: InitOpts = {},
  env: NodeJS.ProcessEnv = process.env,
): Promise<string> {
  const explicitProvider = opts.provider as Provider | undefined;
  const nonInteractive =
    Boolean(explicitProvider) && hasCredentialContext(explicitProvider, opts, env);

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
      choices: allProviderModules().map((m) => ({ name: m.label, value: m.name })),
    }));

  // Map the flat InitOpts onto the structured InitInputs the module
  // expects. The module decides which fields are meaningful for it.
  const inputs: InitInputs = {
    apiKey: opts.apiKey,
    oauthToken: opts.oauthToken,
    baseUrl: opts.baseUrl,
    region: opts.region,
    awsAccessKeyId: opts.awsAccessKeyId,
    awsSecretAccessKey: opts.awsSecretAccessKey,
    awsSessionToken: opts.awsSessionToken,
    project: opts.project,
    model: opts.model,
  };

  if (!opts.model && !nonInteractive) {
    inputs.model = await pickModel(provider, inputs, env);
  }

  const mod = getProviderModule(provider);
  const fresh = await mod.collectCredentials({
    inputs,
    env,
    interactive: !nonInteractive,
  });
  const merged = mergeUserConfig(fresh, existing);
  const path = saveUserConfig(merged, env);

  console.log(`\n✓ Saved config to ${path}`);
  console.log(`  Default provider: ${merged.provider}`);
  console.log(`  Configured providers: ${listConfiguredProviders(merged).join(", ")}`);
  console.log(`\nNext: agentgg scan <path>`);
  return path;
}

/**
 * "Given this provider, can we resolve credentials without prompting?"
 * Used to decide whether to enter non-interactive mode. Each provider's
 * `collectCredentials` does the real check; this is just a heuristic
 * for whether to skip the welcome banner / pre-flight prompts.
 */
function hasCredentialContext(
  provider: Provider | undefined,
  opts: InitOpts,
  env: NodeJS.ProcessEnv,
): boolean {
  if (!provider) return false;
  switch (provider) {
    case "anthropic":
      return Boolean(
        opts.apiKey?.trim() ||
          opts.oauthToken?.trim() ||
          env.ANTHROPIC_API_KEY ||
          env.CLAUDE_CODE_OAUTH_TOKEN,
      );
    case "openai":
      return Boolean(opts.apiKey?.trim() || env.OPENAI_API_KEY);
    case "ollama":
      // Default URL works out of the box.
      return true;
    case "bedrock":
      // AWS chain (env / SSO / profile / IAM) is the default. Any of
      // these being set, or an explicit --region, means we can avoid
      // the welcome banner. If nothing is set we'll surface a clear
      // error later when buildDetector runs.
      return Boolean(
        opts.region?.trim() ||
          opts.awsAccessKeyId?.trim() ||
          env.AWS_REGION ||
          env.AWS_DEFAULT_REGION ||
          env.AWS_ACCESS_KEY_ID ||
          env.AWS_PROFILE,
      );
    case "vertex":
      // Vertex needs a project ID + Google ADC. Project ID can come
      // from --project, $GOOGLE_CLOUD_PROJECT, or $GCLOUD_PROJECT.
      // ADC presence we don't check here — if it's missing,
      // buildDetector surfaces a clear error at scan time.
      return Boolean(opts.project?.trim() || env.GOOGLE_CLOUD_PROJECT || env.GCLOUD_PROJECT);
  }
}

export function registerInitCommand(program: Command): void {
  program
    .command("init")
    .description(
      "first-run setup wizard, or non-interactive provider add. Pass enough flags (--provider + credential) to skip prompts entirely.",
    )
    .option(
      "--provider <name>",
      "Provider to configure: anthropic | openai | ollama | bedrock | vertex",
    )
    .option(
      "--api-key <key>",
      "API key for the chosen provider (sk-ant-api… / sk-…). For Anthropic, also accepts an sk-ant-oat… OAuth token.",
    )
    .option(
      "--oauth-token <token>",
      "Anthropic OAuth token (sk-ant-oat…). Same effect as passing it via --api-key.",
    )
    .option("--base-url <url>", "Ollama base URL (default http://localhost:11434)")
    .option(
      "--region <name>",
      "AWS region for Bedrock (e.g. us-east-1). Falls back to $AWS_REGION / $AWS_DEFAULT_REGION at scan time if unset.",
    )
    .option(
      "--aws-access-key-id <id>",
      "(Bedrock) explicit AWS access key ID. Optional — defaults to the AWS credential chain (env / profile / IAM role / SSO).",
    )
    .option(
      "--aws-secret-access-key <key>",
      "(Bedrock) explicit AWS secret access key. Must be set together with --aws-access-key-id.",
    )
    .option("--aws-session-token <token>", "(Bedrock) STS session token (optional).")
    .option(
      "--project <id>",
      "(Vertex) GCP project ID hosting the Vertex AI Model Garden endpoint. Falls back to $GOOGLE_CLOUD_PROJECT / $GCLOUD_PROJECT at scan time if unset.",
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
