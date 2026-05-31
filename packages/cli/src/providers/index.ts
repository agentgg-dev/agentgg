import type { Provider, UserConfig } from "@agentgg/core";
import { anthropicModule } from "./anthropic.js";
import { bedrockModule } from "./bedrock.js";
import { ollamaModule } from "./ollama.js";
import { openaiModule } from "./openai.js";
import type { ProviderFlag, ProviderModule } from "./types.js";
import { vertexModule } from "./vertex.js";

export {
  buildCredentialsFromOpts,
  type ScanFlagOpts,
  validateProviderFlags,
} from "./cli-flags.js";
export type {
  CollectCredentialsArgs,
  CredentialOverrides,
  InitInputs,
  ProviderFlag,
  ProviderModule,
  ResolveOptions,
} from "./types.js";

/**
 * The single registration point. Adding a new provider = one new
 * module file + one entry here + a Provider enum entry + a UserConfig
 * block in core/types.ts. No edits to llm.ts / init.ts / config.ts /
 * scan.ts required.
 */
const MODULES: Record<Provider, ProviderModule> = {
  anthropic: anthropicModule,
  openai: openaiModule,
  ollama: ollamaModule,
  bedrock: bedrockModule,
  vertex: vertexModule,
};

export function getProviderModule(name: Provider): ProviderModule {
  const mod = MODULES[name];
  if (!mod) throw new Error(`Unknown provider: ${name}`);
  return mod;
}

/** All registered modules in registration order. */
export function allProviderModules(): ProviderModule[] {
  return Object.values(MODULES);
}

/**
 * Map a flag-key (the ProviderFlag string) to the user-facing CLI
 * flag string. Used only for error messages — the flag definitions
 * themselves live on the commander command.
 */
export function flagDisplayName(flag: ProviderFlag): string {
  return `--${flag}`;
}

/**
 * Build a per-provider summary line from the saved config. Used by
 * `agentgg config` and the init wizard's "Configured: …" line.
 */
export function listConfiguredProviders(cfg: UserConfig): string[] {
  return allProviderModules()
    .map((m) => m.formatForList(cfg))
    .filter((line): line is string => line !== null);
}
