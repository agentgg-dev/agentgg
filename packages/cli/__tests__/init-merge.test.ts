import { describe, expect, it } from "vitest";
import type { UserConfig } from "@agentgg/core";
import { buildUserConfig, mergeUserConfig } from "../src/commands/init.js";

describe("mergeUserConfig", () => {
  it("returns the fresh config when there is no existing one", () => {
    const fresh: UserConfig = {
      provider: "anthropic",
      anthropic: { apiKey: "sk-ant-x" },
      schemaVersion: 1,
    };
    expect(mergeUserConfig(fresh, null)).toEqual(fresh);
  });

  it("adds a new provider without wiping existing ones", () => {
    const existing: UserConfig = {
      provider: "anthropic",
      anthropic: { apiKey: "sk-ant-x" },
      schemaVersion: 1,
    };
    const fresh: UserConfig = {
      provider: "ollama",
      ollama: { baseUrl: "http://localhost:11434" },
      schemaVersion: 1,
    };
    const merged = mergeUserConfig(fresh, existing);
    expect(merged.provider).toBe("ollama");
    expect(merged.anthropic).toEqual({ apiKey: "sk-ant-x" });
    expect(merged.ollama).toEqual({ baseUrl: "http://localhost:11434" });
  });

  it("replaces credentials for the same provider when re-init'd", () => {
    const existing: UserConfig = {
      provider: "anthropic",
      anthropic: { apiKey: "sk-ant-old", model: "claude-opus-4" },
      schemaVersion: 1,
    };
    const fresh: UserConfig = {
      provider: "anthropic",
      anthropic: { apiKey: "sk-ant-new", model: "claude-sonnet-4-6" },
      schemaVersion: 1,
    };
    const merged = mergeUserConfig(fresh, existing);
    expect(merged.anthropic).toEqual({
      apiKey: "sk-ant-new",
      model: "claude-sonnet-4-6",
    });
  });

  it("updates the active provider when switching defaults", () => {
    const existing: UserConfig = {
      provider: "anthropic",
      anthropic: { apiKey: "sk-ant-x" },
      ollama: { baseUrl: "http://localhost:11434" },
      schemaVersion: 1,
    };
    const fresh: UserConfig = {
      provider: "ollama",
      ollama: { baseUrl: "http://localhost:11434" },
      schemaVersion: 1,
    };
    const merged = mergeUserConfig(fresh, existing);
    expect(merged.provider).toBe("ollama");
    expect(merged.anthropic).toEqual({ apiKey: "sk-ant-x" });
  });
});

describe("buildUserConfig", () => {
  it("produces an anthropic config from an apiKey", () => {
    const cfg = buildUserConfig({
      provider: "anthropic",
      anthropicKey: "sk-ant-api03-x",
    });
    expect(cfg.provider).toBe("anthropic");
    expect(cfg.anthropic?.apiKey).toBe("sk-ant-api03-x");
  });

  it("auto-routes an sk-ant-oat… key pasted into the anthropicKey field", () => {
    const cfg = buildUserConfig({
      provider: "anthropic",
      anthropicKey: "sk-ant-oat01-x",
    });
    expect(cfg.anthropic?.apiKey).toBeUndefined();
    expect(cfg.anthropic?.oauthToken).toBe("sk-ant-oat01-x");
  });

  it("throws when both apiKey and oauthToken are supplied", () => {
    expect(() =>
      buildUserConfig({
        provider: "anthropic",
        anthropicKey: "sk-ant-api03-x",
        anthropicOauthToken: "sk-ant-oat01-y",
      }),
    ).toThrow(/pick one/);
  });
});
