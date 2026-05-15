import type { Command } from "commander";
import { type Provider, type UserConfig, getConfigPath, loadUserConfig, saveUserConfig } from "@agentgg/core";

/**
 * Format the saved config for stdout. Returns a string so the same
 * helper drives both `--json` mode and the friendly text view, and so
 * it's straightforward to test.
 */
export function formatConfig(
  cfg: UserConfig | null,
  configPath: string,
  json: boolean,
): string {
  if (json) {
    return JSON.stringify(
      { configPath, config: cfg ? redactSecrets(cfg) : null },
      null,
      2,
    );
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
  if (cfg.anthropic) {
    const auth = cfg.anthropic.oauthToken ? "OAuth token" : "API key";
    const model = cfg.anthropic.model ?? "(default)";
    lines.push(`  anthropic   auth=${auth}  model=${model}`);
  }
  if (cfg.openai) {
    const model = cfg.openai.model ?? "(default)";
    lines.push(`  openai      auth=API key  model=${model}`);
  }
  if (cfg.ollama) {
    const model = cfg.ollama.model ?? "(default)";
    lines.push(`  ollama      baseUrl=${cfg.ollama.baseUrl}  model=${model}`);
  }
  if (!cfg.anthropic && !cfg.openai && !cfg.ollama) {
    lines.push("  (none — re-run `agentgg init`)");
  }
  return lines.join("\n");
}

/**
 * Mask sensitive fields before printing them out. Used by `--json`
 * mode so users can pipe to clipboard or scripts without leaking
 * credentials.
 */
function redactSecrets(cfg: UserConfig): UserConfig {
  return {
    ...cfg,
    anthropic: cfg.anthropic
      ? {
          ...cfg.anthropic,
          ...(cfg.anthropic.apiKey ? { apiKey: maskValue(cfg.anthropic.apiKey) } : {}),
          ...(cfg.anthropic.oauthToken
            ? { oauthToken: maskValue(cfg.anthropic.oauthToken) }
            : {}),
        }
      : undefined,
    openai: cfg.openai ? { ...cfg.openai, apiKey: maskValue(cfg.openai.apiKey) } : undefined,
  };
}

function maskValue(s: string): string {
  if (s.length <= 10) return "****";
  return `${s.slice(0, 10)}…${"*".repeat(4)}`;
}

const VALID_PROVIDERS = new Set<string>(["anthropic", "openai", "ollama"]);

function applyModelUpdate(cfg: UserConfig, provider: Provider, model: string): UserConfig {
  switch (provider) {
    case "anthropic":
      if (!cfg.anthropic) throw new Error("anthropic is not configured — run `agentgg init --provider anthropic` first.");
      return { ...cfg, anthropic: { ...cfg.anthropic, model } };
    case "openai":
      if (!cfg.openai) throw new Error("openai is not configured — run `agentgg init --provider openai` first.");
      return { ...cfg, openai: { ...cfg.openai, model } };
    case "ollama":
      if (!cfg.ollama) throw new Error("ollama is not configured — run `agentgg init --provider ollama` first.");
      return { ...cfg, ollama: { ...cfg.ollama, model } };
  }
}

export function registerConfigCommand(program: Command): void {
  program
    .command("config")
    .description("show or update the saved agentgg config (provider, model, mode defaults)")
    .option("--json", "emit JSON instead of a human-readable summary")
    .option(
      "--provider <name>",
      "switch the default provider (must already be configured via init): anthropic | openai | ollama",
    )
    .option("--model <name>", "update the model for the specified --provider (requires --provider)")
    .action((opts: { json?: boolean; provider?: string; model?: string }) => {
      const env = process.env;
      const configPath = getConfigPath(env);

      if (opts.provider || opts.model) {
        if (opts.model && !opts.provider) {
          console.error("--model requires --provider. Example: agentgg config --provider ollama --model llama3.1:8b");
          process.exit(1);
        }

        let cfg = loadUserConfig(env);
        if (!cfg) {
          console.error("No config found. Run `agentgg init` first.");
          process.exit(1);
        }

        if (opts.provider) {
          if (!VALID_PROVIDERS.has(opts.provider)) {
            console.error(`Unknown provider "${opts.provider}". Must be one of: anthropic, openai, ollama`);
            process.exit(1);
          }
          const p = opts.provider as Provider;
          if (p === "anthropic" && !cfg.anthropic) {
            console.error("anthropic is not configured — run `agentgg init --provider anthropic` first.");
            process.exit(1);
          }
          if (p === "openai" && !cfg.openai) {
            console.error("openai is not configured — run `agentgg init --provider openai` first.");
            process.exit(1);
          }
          if (p === "ollama" && !cfg.ollama) {
            console.error("ollama is not configured — run `agentgg init --provider ollama` first.");
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
