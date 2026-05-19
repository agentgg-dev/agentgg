import { describe, expect, it } from "vitest";
import { buildUserConfig, DEFAULT_MODELS, isAnthropicOauthToken } from "../src/commands/init.js";

describe("buildUserConfig", () => {
  describe("anthropic", () => {
    it("builds a valid config from an API key", () => {
      const cfg = buildUserConfig({
        provider: "anthropic",
        anthropicKey: "sk-ant-abc",
      });
      expect(cfg.provider).toBe("anthropic");
      expect(cfg.anthropic?.apiKey).toBe("sk-ant-abc");
      expect(cfg.anthropic?.model).toBe(DEFAULT_MODELS.anthropic);
      expect(cfg.schemaVersion).toBe(1);
    });

    it("honors a custom model override", () => {
      const cfg = buildUserConfig({
        provider: "anthropic",
        anthropicKey: "sk-ant-abc",
        model: "claude-haiku-4-5",
      });
      expect(cfg.anthropic?.model).toBe("claude-haiku-4-5");
    });

    it("trims whitespace from the API key", () => {
      const cfg = buildUserConfig({
        provider: "anthropic",
        anthropicKey: "   sk-ant-padded   ",
      });
      expect(cfg.anthropic?.apiKey).toBe("sk-ant-padded");
    });

    it("throws when no credential is supplied (neither apiKey nor oauthToken)", () => {
      expect(() => buildUserConfig({ provider: "anthropic" })).toThrow(/no API key or OAuth token/);
    });

    it("throws when the key is only whitespace", () => {
      expect(() => buildUserConfig({ provider: "anthropic", anthropicKey: "   " })).toThrow(
        /no API key or OAuth token/,
      );
    });

    it("builds a valid config from a Claude Code OAuth token", () => {
      const cfg = buildUserConfig({
        provider: "anthropic",
        anthropicOauthToken: "sk-ant-oat01-xyz",
      });
      expect(cfg.anthropic?.oauthToken).toBe("sk-ant-oat01-xyz");
      expect(cfg.anthropic?.apiKey).toBeUndefined();
    });

    it("auto-routes an OAuth-shaped token pasted into the apiKey field", () => {
      const cfg = buildUserConfig({
        provider: "anthropic",
        anthropicKey: "sk-ant-oat01-misplaced",
      });
      expect(cfg.anthropic?.oauthToken).toBe("sk-ant-oat01-misplaced");
      expect(cfg.anthropic?.apiKey).toBeUndefined();
    });

    it("throws when BOTH apiKey and oauthToken are supplied", () => {
      expect(() =>
        buildUserConfig({
          provider: "anthropic",
          anthropicKey: "sk-ant-api03-x",
          anthropicOauthToken: "sk-ant-oat01-y",
        }),
      ).toThrow(/pick one/);
    });

    it("trims whitespace from an OAuth token too", () => {
      const cfg = buildUserConfig({
        provider: "anthropic",
        anthropicOauthToken: "   sk-ant-oat01-padded   ",
      });
      expect(cfg.anthropic?.oauthToken).toBe("sk-ant-oat01-padded");
    });
  });

  describe("isAnthropicOauthToken", () => {
    it("returns true for tokens starting with sk-ant-oat", () => {
      expect(isAnthropicOauthToken("sk-ant-oat01-abcd")).toBe(true);
      expect(isAnthropicOauthToken("sk-ant-oat-anything")).toBe(true);
    });

    it("returns false for API keys", () => {
      expect(isAnthropicOauthToken("sk-ant-api03-abcd")).toBe(false);
      expect(isAnthropicOauthToken("sk-ant-foobar")).toBe(false);
    });

    it("ignores leading/trailing whitespace", () => {
      expect(isAnthropicOauthToken("   sk-ant-oat01-x   ")).toBe(true);
    });

    it("returns false for empty / garbage input", () => {
      expect(isAnthropicOauthToken("")).toBe(false);
      expect(isAnthropicOauthToken("garbage")).toBe(false);
    });
  });

  describe("openai", () => {
    it("builds a valid config from an API key", () => {
      const cfg = buildUserConfig({ provider: "openai", openaiKey: "sk-openai" });
      expect(cfg.provider).toBe("openai");
      expect(cfg.openai?.apiKey).toBe("sk-openai");
      expect(cfg.openai?.model).toBe(DEFAULT_MODELS.openai);
    });

    it("throws when no key is supplied", () => {
      expect(() => buildUserConfig({ provider: "openai" })).toThrow(/no API key/);
    });
  });

  describe("ollama", () => {
    it("uses the default base URL when none is supplied", () => {
      const cfg = buildUserConfig({ provider: "ollama" });
      expect(cfg.provider).toBe("ollama");
      expect(cfg.ollama?.baseUrl).toBe("http://localhost:11434");
      expect(cfg.ollama?.model).toBe(DEFAULT_MODELS.ollama);
    });

    it("accepts a custom base URL", () => {
      const cfg = buildUserConfig({
        provider: "ollama",
        ollamaUrl: "http://10.0.0.5:11434",
      });
      expect(cfg.ollama?.baseUrl).toBe("http://10.0.0.5:11434");
    });

    it("does not require an API key", () => {
      expect(() => buildUserConfig({ provider: "ollama" })).not.toThrow();
    });
  });
});
