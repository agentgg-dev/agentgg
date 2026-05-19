import type { UserConfig } from "@agentgg/core";
import { describe, expect, it } from "vitest";
import { formatConfig } from "../src/commands/config.js";

describe("formatConfig", () => {
  it("emits the config path even when there's no saved config", () => {
    const out = formatConfig(null, "/tmp/cfg.json", false);
    expect(out).toContain("/tmp/cfg.json");
    expect(out).toContain("No config saved");
  });

  it("lists every configured provider with its auth shape", () => {
    const cfg: UserConfig = {
      provider: "anthropic",
      anthropic: { apiKey: "sk-ant-api03-secret", model: "claude-sonnet-4-6" },
      ollama: { baseUrl: "http://localhost:11434", model: "llama3.1" },
      schemaVersion: 1,
    };
    const out = formatConfig(cfg, "/x/config.json", false);
    expect(out).toContain("Default provider: anthropic");
    expect(out).toContain("anthropic");
    expect(out).toContain("ollama");
    expect(out).toContain("http://localhost:11434");
  });

  it("does NOT include the raw secret in human output", () => {
    const cfg: UserConfig = {
      provider: "anthropic",
      anthropic: { apiKey: "sk-ant-api03-VERY-SECRET-VALUE" },
      schemaVersion: 1,
    };
    const out = formatConfig(cfg, "/x/cfg.json", false);
    expect(out).not.toContain("VERY-SECRET-VALUE");
  });

  it("masks secrets in --json mode (prefix only, not full value)", () => {
    const cfg: UserConfig = {
      provider: "anthropic",
      anthropic: { apiKey: "sk-ant-api03-VERY-SECRET-VALUE" },
      schemaVersion: 1,
    };
    const out = formatConfig(cfg, "/x/cfg.json", true);
    expect(out).not.toContain("VERY-SECRET-VALUE");
    expect(out).toContain("sk-ant-api");
  });

  it("--json output parses as JSON", () => {
    const cfg: UserConfig = {
      provider: "ollama",
      ollama: { baseUrl: "http://localhost:11434" },
      schemaVersion: 1,
    };
    const out = formatConfig(cfg, "/x/cfg.json", true);
    expect(() => JSON.parse(out)).not.toThrow();
    const parsed = JSON.parse(out);
    expect(parsed.configPath).toBe("/x/cfg.json");
    expect(parsed.config.provider).toBe("ollama");
  });
});
