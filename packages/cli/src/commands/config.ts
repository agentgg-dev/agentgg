import {
  getConfigPath,
  loadUserConfig,
  type Provider,
  saveUserConfig,
  type UserConfig,
} from "@agentgg/core";
import type { Command } from "commander";
import { allProviderModules, listConfiguredProviders } from "../providers/index.js";

/**
 * Format the saved config for stdout. Returns a string so the same
 * helper drives both `--json` mode and the friendly text view, and so
 * it's straightforward to test.
 */
export function formatConfig(cfg: UserConfig | null, configPath: string, json: boolean): string {
  if (json) {
    return JSON.stringify({ configPath, config: cfg ? redactSecrets(cfg) : null }, null, 2);
  }
  const lines: string[] = [];
  lines.push(`Config file: ${configPath}`);
  if (!cfg) {
    lines.push("");
    lines.push("No config saved. Run `agentgg init` to create one.");
    return lines.join("\n");
  }
  lines.push("");
  lines.push(`Default provider: ${cfg.provider}`);
  lines.push("");
  lines.push("Configured providers:");
  const configured = listConfiguredProviders(cfg);
  if (configured.length === 0) {
    lines.push("  (none — re-run `agentgg init`)");
  } else {
    for (const line of configured) lines.push(`  ${line}`);
  }
  return lines.join("\n");
}

/**
 * Mask sensitive fields before printing them out. Routes through every
 * registered provider module so a new provider's secrets are masked
 * without touching this file.
 */
function redactSecrets(cfg: UserConfig): UserConfig {
  let out = cfg;
  for (const mod of allProviderModules()) {
    out = mod.redact(out);
  }
  return out;
}

const VALID_PROVIDERS = new Set<string>(allProviderModules().map((m) => m.name));

function applyModelUpdate(cfg: UserConfig, provider: Provider, model: string): UserConfig {
  // Each provider's block lives at UserConfig[name]. We dynamically
  // index so adding a new provider doesn't require a new switch arm.
  const key = provider as keyof UserConfig;
  const existing = (cfg as Record<string, unknown>)[key] as Record<string, unknown> | undefined;
  if (!existing) {
    throw new Error(
      `${provider} is not configured — run \`agentgg init --provider ${provider}\` first.`,
    );
  }
  return {
    ...cfg,
    [key]: { ...existing, model },
  } as UserConfig;
}

export function registerConfigCommand(program: Command): void {
  const providerList = allProviderModules()
    .map((m) => m.name)
    .join(" | ");
  program
    .command("config")
    .description("show or update the saved agentgg config (provider, model, mode defaults)")
    .option("--json", "emit JSON instead of a human-readable summary")
    .option(
      "--provider <name>",
      `switch the default provider (must already be configured via init): ${providerList}`,
    )
    .option("--model <name>", "update the model for the specified --provider (requires --provider)")
    .action((opts: { json?: boolean; provider?: string; model?: string }) => {
      const env = process.env;
      const configPath = getConfigPath(env);

      if (opts.provider || opts.model) {
        if (opts.model && !opts.provider) {
          console.error(
            "--model requires --provider. Example: agentgg config --provider ollama --model llama3.1:8b",
          );
          process.exit(1);
        }

        let cfg = loadUserConfig(env);
        if (!cfg) {
          console.error("No config found. Run `agentgg init` first.");
          process.exit(1);
        }

        if (opts.provider) {
          if (!VALID_PROVIDERS.has(opts.provider)) {
            console.error(
              `Unknown provider "${opts.provider}". Must be one of: ${[...VALID_PROVIDERS].join(", ")}`,
            );
            process.exit(1);
          }
          const p = opts.provider as Provider;
          const key = p as keyof UserConfig;
          if (!(cfg as Record<string, unknown>)[key]) {
            console.error(`${p} is not configured — run \`agentgg init --provider ${p}\` first.`);
            process.exit(1);
          }
          cfg = { ...cfg, provider: p };
        }

        if (opts.model) {
          try {
            cfg = applyModelUpdate(cfg, cfg.provider, opts.model);
          } catch (err) {
            console.error((err as Error).message);
            process.exit(1);
          }
        }

        saveUserConfig(cfg, env);
        console.log(`✓ Updated ${configPath}`);
        if (opts.provider) console.log(`  Default provider → ${cfg.provider}`);
        if (opts.model) console.log(`  Model (${cfg.provider}) → ${opts.model}`);
        return;
      }

      const cfg = loadUserConfig(env);
      console.log(formatConfig(cfg, configPath, Boolean(opts.json)));
    });
}

// Re-exported for use by the init wizard (provider listing line).
export { listConfiguredProviders } from "../providers/index.js";
