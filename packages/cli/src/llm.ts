import type { Provider, UserConfig } from "@agentgg/core";
import { loadUserConfig } from "@agentgg/core";
import type { Detector } from "./detect.js";
import { allProviderModules, getProviderModule } from "./providers/index.js";

// Re-export the public API shapes so existing call sites in scan.ts /
// revalidate.ts keep working unchanged.
export type {
  CredentialOverrides,
  ProviderFlag,
  ProviderModule,
  ResolveOptions,
} from "./providers/index.js";
export {
  allProviderModules,
  flagDisplayName,
  getProviderModule,
  listConfiguredProviders,
} from "./providers/index.js";

import type { ResolveOptions } from "./providers/index.js";

/**
 * Load `~/.agentgg/config.json`, or synthesize a minimal config from
 * the `--provider` flag when the file does not exist.
 *
 * Lets scan / revalidate / score run in CI without requiring a prior
 * `agentgg init` — credentials are supplied per-invocation via
 * `--api-key` / `--oauth-token` / `--base-url` / `--region` and resolved
 * against this stub by the provider module's `buildDetector`.
 *
 * Throws when no config exists AND no `--provider` was passed — at that
 * point there is genuinely no way to know which provider to build.
 */
export function loadOrSynthesizeConfig(
  env: NodeJS.ProcessEnv,
  providerFlag: string | undefined,
): UserConfig {
  const config = loadUserConfig(env);
  if (config) return config;
  if (!providerFlag) {
    const names = allProviderModules()
      .map((m) => m.name)
      .join(" | ");
    throw new Error(
      `No agentgg config found. Either run \`agentgg init\` to save a default provider, or pass \`--provider <${names}>\` together with the relevant credential flag (--api-key / --oauth-token / --base-url / --region).`,
    );
  }
  return { provider: providerFlag as Provider, schemaVersion: 1 } satisfies UserConfig;
}

/**
 * Resolve the Detector for this scan run.
 *
 *   Provider resolution: `options.provider` (from --provider) wins;
 *   otherwise `config.provider` from `~/.agentgg/config.json`.
 *
 *   Credential resolution per provider:
 *     1. `options.credentials.*` (CLI flags)
 *     2. The corresponding block in `config`
 *     3. Provider-specific env vars / cloud default credential chain
 *
 * The same Detector handles file / walker / hunt agents — the dispatch
 * happens inside the agent's execution path, not here.
 */
export function resolveDetector(config: UserConfig, options: ResolveOptions = {}): Detector {
  const providerName = (options.provider ?? config.provider) as Provider;
  const mod = getProviderModule(providerName);
  return mod.buildDetector(config, options);
}
