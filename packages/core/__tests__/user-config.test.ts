import { existsSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { getConfigPath } from "../src/paths.js";
import type { UserConfig } from "../src/types.js";
import { loadUserConfig, saveUserConfig } from "../src/user-config.js";

let tempDir: string;
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  tempDir = mkdtempSync(join(tmpdir(), "agentgg-test-"));
  env = { AGENTGG_HOME: tempDir };
});

afterEach(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

describe("loadUserConfig", () => {
  it("returns null when the config file doesn't exist", () => {
    expect(loadUserConfig(env)).toBeNull();
  });

  it("loads a valid config from disk", () => {
    const cfg: UserConfig = {
      provider: "anthropic",
      anthropic: { apiKey: "sk-ant-test", model: "claude-sonnet-4-6" },
      schemaVersion: 1,
    };
    writeFileSync(getConfigPath(env), JSON.stringify(cfg), "utf8");
    const loaded = loadUserConfig(env);
    expect(loaded).not.toBeNull();
    expect(loaded?.provider).toBe("anthropic");
    expect(loaded?.anthropic?.apiKey).toBe("sk-ant-test");
  });

  it("throws on malformed JSON", () => {
    writeFileSync(getConfigPath(env), "not json {{{", "utf8");
    expect(() => loadUserConfig(env)).toThrow(/Failed to parse/);
  });

  it("throws when the config violates the schema", () => {
    writeFileSync(getConfigPath(env), JSON.stringify({ provider: "anthropic" }), "utf8");
    expect(() => loadUserConfig(env)).toThrow();
  });
});

describe("saveUserConfig", () => {
  it("writes a valid config and returns the path", () => {
    const cfg: UserConfig = {
      provider: "anthropic",
      anthropic: { apiKey: "sk-ant-write", model: "claude-sonnet-4-6" },
      schemaVersion: 1,
    };
    const path = saveUserConfig(cfg, env);
    expect(path).toBe(getConfigPath(env));
    expect(existsSync(path)).toBe(true);
  });

  it("round-trips: save then load returns the same shape", () => {
    const cfg: UserConfig = {
      provider: "ollama",
      ollama: { baseUrl: "http://localhost:11434", model: "llama3.1" },
      schemaVersion: 1,
    };
    saveUserConfig(cfg, env);
    const loaded = loadUserConfig(env);
    expect(loaded).toEqual(cfg);
  });

  it("creates the parent directory if missing", () => {
    const nested = join(tempDir, "deeply", "nested");
    const nestedEnv = { AGENTGG_HOME: nested };
    saveUserConfig(
      {
        provider: "anthropic",
        anthropic: { apiKey: "sk-x" },
        schemaVersion: 1,
      },
      nestedEnv,
    );
    expect(existsSync(getConfigPath(nestedEnv))).toBe(true);
  });

  it("refuses to save an invalid config (validates before write)", () => {
    expect(() =>
      saveUserConfig(
        // @ts-expect-error — intentionally invalid for this test
        { provider: "anthropic", schemaVersion: 1 },
        env,
      ),
    ).toThrow();
    expect(existsSync(getConfigPath(env))).toBe(false);
  });

  it.skipIf(process.platform === "win32")("writes the file with mode 0600 on POSIX", () => {
    const cfg: UserConfig = {
      provider: "anthropic",
      anthropic: { apiKey: "sk-x" },
      schemaVersion: 1,
    };
    saveUserConfig(cfg, env);
    const mode = statSync(getConfigPath(env)).mode & 0o777;
    expect(mode).toBe(0o600);
  });
});
