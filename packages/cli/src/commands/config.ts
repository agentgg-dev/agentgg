import type { Command } from "commander";
import { type UserConfig, getConfigPath, loadUserConfig } from "@agentgg/core";

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

export function registerConfigCommand(program: Command): void {
  program
    .command("config")
    .description("show the saved agentgg config (provider, model, mode defaults)")
    .option("--json", "emit JSON instead of a human-readable summary")
    .action((opts: { json?: boolean }) => {
      const env = process.env;
      const configPath = getConfigPath(env);
      const cfg = loadUserConfig(env);
      console.log(formatConfig(cfg, configPath, Boolean(opts.json)));
    });
}
