import { homedir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { getAgentsDir, getConfigPath, getDataDir } from "../src/paths.js";

describe("paths", () => {
  describe("getDataDir", () => {
    it("returns AGENTGG_HOME when set", () => {
      const env = { AGENTGG_HOME: "/tmp/agentgg-test" };
      expect(getDataDir(env)).toBe("/tmp/agentgg-test");
    });

    it("falls back to homedir() + .agentgg when AGENTGG_HOME is unset", () => {
      const env = {};
      expect(getDataDir(env)).toBe(join(homedir(), ".agentgg"));
    });

    it("ignores empty AGENTGG_HOME and falls back", () => {
      const env = { AGENTGG_HOME: "" };
      expect(getDataDir(env)).toBe(join(homedir(), ".agentgg"));
    });
  });

  describe("getConfigPath", () => {
    it("returns <dataDir>/config.json", () => {
      const env = { AGENTGG_HOME: "/tmp/agentgg-test" };
      expect(getConfigPath(env)).toBe(join("/tmp/agentgg-test", "config.json"));
    });
  });

  describe("getAgentsDir", () => {
    it("returns <dataDir>/agents", () => {
      const env = { AGENTGG_HOME: "/tmp/agentgg-test" };
      expect(getAgentsDir(env)).toBe(join("/tmp/agentgg-test", "agents"));
    });
  });
});
