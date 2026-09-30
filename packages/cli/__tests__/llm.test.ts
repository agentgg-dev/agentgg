import type { UserConfig } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resolveDetector } from "../src/llm.js";
import { getProviderModule } from "../src/providers/index.js";

// The key env vars are a credential source, so every test starts without them.
beforeEach(() => {
  for (const name of ["ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "OPENAI_API_KEY"]) {
    vi.stubEnv(name, "");
  }
});
afterEach(() => vi.unstubAllEnvs());

/**
 * These tests verify the routing logic in `resolveDetector` — which
 * Detector subclass is returned for each (provider, credential type)
 * combination. No Detector is invoked; no LLM calls, no `claude` binary
 * spawning.
 */
describe("resolveDetector", () => {
  it("returns 'anthropic-api' when an apiKey is configured", () => {
    const config: UserConfig = {
      provider: "anthropic",
      anthropic: { apiKey: "sk-ant-api03-x", model: "claude-sonnet-4-6" },
      schemaVersion: 1,
    };
    expect(resolveDetector(config).name).toBe("anthropic-api");
  });

  it("returns 'anthropic-oauth' when only oauthToken is configured", () => {
    const config: UserConfig = {
      provider: "anthropic",
      anthropic: { oauthToken: "sk-ant-oat01-x" },
      schemaVersion: 1,
    };
    expect(resolveDetector(config).name).toBe("anthropic-oauth");
  });

  it("returns 'openai' for the openai provider", () => {
    const config: UserConfig = {
      provider: "openai",
      openai: { apiKey: "sk-x", model: "gpt-5" },
      schemaVersion: 1,
    };
    expect(resolveDetector(config).name).toBe("openai");
  });

  it("returns 'ollama' for the ollama provider", () => {
    const config: UserConfig = {
      provider: "ollama",
      ollama: { baseUrl: "http://localhost:11434", model: "llama3.1" },
      schemaVersion: 1,
    };
    expect(resolveDetector(config).name).toBe("ollama");
  });

  it("--provider override re-routes from anthropic to openai", () => {
    const config: UserConfig = {
      provider: "anthropic",
      anthropic: { apiKey: "sk-ant-api03-x" },
      openai: { apiKey: "sk-x" },
      schemaVersion: 1,
    };
    expect(resolveDetector(config, { provider: "openai" }).name).toBe("openai");
  });

  it("throws when the selected provider has no credentials configured", () => {
    const config: UserConfig = {
      provider: "anthropic",
      anthropic: { apiKey: "sk-ant-api03-x" },
      schemaVersion: 1,
    };
    expect(() => resolveDetector(config, { provider: "openai" })).toThrow(/no API key available/);
  });

  it("throws on an unknown provider override", () => {
    const config: UserConfig = {
      provider: "anthropic",
      anthropic: { apiKey: "sk-ant-api03-x" },
      schemaVersion: 1,
    };
    expect(() => resolveDetector(config, { provider: "cohere" })).toThrow(/Unknown provider/);
  });
});

describe("resolveDetector (one-shot credential overrides)", () => {
  it("uses --api-key when no saved anthropic block exists", () => {
    const config: UserConfig = {
      provider: "openai",
      openai: { apiKey: "sk-x" },
      schemaVersion: 1,
    };
    const detector = resolveDetector(config, {
      provider: "anthropic",
      credentials: { anthropicApiKey: "sk-ant-api03-from-cli" },
    });
    expect(detector.name).toBe("anthropic-api");
  });

  it("uses --oauth-token when no saved anthropic block exists", () => {
    const config: UserConfig = {
      provider: "openai",
      openai: { apiKey: "sk-x" },
      schemaVersion: 1,
    };
    const detector = resolveDetector(config, {
      provider: "anthropic",
      credentials: { anthropicOauthToken: "sk-ant-oat01-from-cli" },
    });
    expect(detector.name).toBe("anthropic-oauth");
  });

  it("uses --base-url for ollama without saved config", () => {
    const config: UserConfig = {
      provider: "openai",
      openai: { apiKey: "sk-x" },
      schemaVersion: 1,
    };
    const detector = resolveDetector(config, {
      provider: "ollama",
      credentials: { ollamaBaseUrl: "http://10.0.0.5:11434" },
    });
    expect(detector.name).toBe("ollama");
  });

  it("falls back to $ANTHROPIC_API_KEY when neither flags nor config supply one", () => {
    vi.stubEnv("ANTHROPIC_API_KEY", "sk-ant-api03-from-env");
    const config: UserConfig = { provider: "openai", openai: { apiKey: "sk-x" }, schemaVersion: 1 };
    expect(resolveDetector(config, { provider: "anthropic" }).name).toBe("anthropic-api");
  });

  it("a saved anthropic block wins over the env, without mixing the two", () => {
    vi.stubEnv("ANTHROPIC_API_KEY", "sk-ant-api03-from-env");
    const config: UserConfig = {
      provider: "anthropic",
      anthropic: { oauthToken: "sk-ant-oat01-saved" },
      schemaVersion: 1,
    };
    expect(resolveDetector(config, { provider: "anthropic" }).name).toBe("anthropic-oauth");
  });

  it("falls back to $OPENAI_API_KEY when neither flags nor config supply one", () => {
    vi.stubEnv("OPENAI_API_KEY", "sk-from-env");
    const config: UserConfig = {
      provider: "anthropic",
      anthropic: { apiKey: "sk-ant-api03-x" },
      schemaVersion: 1,
    };
    expect(resolveDetector(config, { provider: "openai" }).name).toBe("openai");
  });

  it("rejects when neither CLI nor config supply credentials", () => {
    const config: UserConfig = {
      provider: "openai",
      openai: { apiKey: "sk-x" },
      schemaVersion: 1,
    };
    expect(() => resolveDetector(config, { provider: "anthropic" })).toThrow(
      /no credentials available/,
    );
  });
});

it("registers the openrouter provider module", () => {
  const mod = getProviderModule("openrouter");
  expect(mod.name).toBe("openrouter");
  expect(mod.defaultModel).toBe("z-ai/glm-5.2");
});
