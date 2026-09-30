import type { UserConfig } from "@agentgg/core";
import { describe, expect, it } from "vitest";
import { applyRoutingUpdate, formatConfig } from "../src/commands/config.js";
import { buildCredentialsFromOpts } from "../src/providers/cli-flags.js";

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

it("maps --api-key onto the openrouter credential slot", () => {
  const creds = buildCredentialsFromOpts({ apiKey: "sk-or-v1-x" });
  expect(creds.openrouterApiKey).toBe("sk-or-v1-x");
});

describe("applyRoutingUpdate", () => {
  const cfg: UserConfig = {
    provider: "openrouter",
    openrouter: { apiKey: "sk-or-v1-x", model: "z-ai/glm-5.2" },
    schemaVersion: 1,
  };

  it("saves and then clears the routing, keeping the rest of the block", () => {
    const saved = applyRoutingUpdate(cfg, { quantizations: ["fp8"] });
    expect(saved.openrouter).toEqual({
      apiKey: "sk-or-v1-x",
      model: "z-ai/glm-5.2",
      routing: { quantizations: ["fp8"] },
    });
    expect(applyRoutingUpdate(saved, null).openrouter).toEqual(cfg.openrouter);
  });

  it("refuses when OpenRouter is not configured", () => {
    const other: UserConfig = {
      provider: "ollama",
      ollama: { baseUrl: "http://localhost:11434" },
      schemaVersion: 1,
    };
    expect(() => applyRoutingUpdate(other, { sort: "price" })).toThrow(/not configured/);
  });
});
