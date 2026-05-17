import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadAgentsFromDir } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadAllAgents, validateOfficialAgents } from "../src/agent-catalog.js";

const VALID_MD = `---
slug: SLUG_PLACEHOLDER
name: Sample
description: A test agent.
version: 0.0.1
mode: file
noiseTier: normal
filePatterns:
  - "**/*.ts"
---

A prompt body long enough to satisfy the schema's minimum length floor.
`;

function md(slug: string): string {
  return VALID_MD.replace("SLUG_PLACEHOLDER", slug);
}

let agentggHome: string;
let env: NodeJS.ProcessEnv;
let officialDir: string;

beforeEach(() => {
  agentggHome = mkdtempSync(join(tmpdir(), "agentgg-home-"));
  env = { AGENTGG_HOME: agentggHome };
  officialDir = join(agentggHome, "agentgg-agents");
  mkdirSync(officialDir, { recursive: true });
});

afterEach(() => {
  rmSync(agentggHome, { recursive: true, force: true });
});

describe("validateOfficialAgents", () => {
  it("returns no violations on a clean tree", () => {
    writeFileSync(join(officialDir, "foo.md"), md("foo"));
    mkdirSync(join(officialDir, "sub"), { recursive: true });
    writeFileSync(join(officialDir, "sub", "bar.md"), md("bar"));
    const { agents } = loadAgentsFromDir(officialDir, { kind: "official" });
    expect(validateOfficialAgents(agents)).toEqual([]);
  });

  it("flags duplicate slugs across subdirs with both paths", () => {
    mkdirSync(join(officialDir, "a"), { recursive: true });
    mkdirSync(join(officialDir, "b"), { recursive: true });
    writeFileSync(join(officialDir, "a", "dup.md"), md("dup"));
    writeFileSync(join(officialDir, "b", "dup.md"), md("dup"));
    const { agents } = loadAgentsFromDir(officialDir, { kind: "official" });
    const violations = validateOfficialAgents(agents);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatch(/duplicate slug 'dup'/);
    expect(violations[0]).toMatch(/a[\\/]dup\.md/);
    expect(violations[0]).toMatch(/b[\\/]dup\.md/);
  });

  it("flags filename that does not match slug", () => {
    writeFileSync(join(officialDir, "wrong-name.md"), md("right-slug"));
    const { agents } = loadAgentsFromDir(officialDir, { kind: "official" });
    const violations = validateOfficialAgents(agents);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatch(
      /filename does not match slug: 'wrong-name\.md' should be 'right-slug\.md'/,
    );
  });

  it("accepts demo agents with the -demo suffix convention", () => {
    mkdirSync(join(officialDir, "openclaw"), { recursive: true });
    mkdirSync(join(officialDir, "demo-agents"), { recursive: true });
    writeFileSync(
      join(officialDir, "openclaw", "openclaw-audit.md"),
      md("openclaw-audit"),
    );
    writeFileSync(
      join(officialDir, "demo-agents", "openclaw-audit-demo.md"),
      md("openclaw-audit-demo"),
    );
    const { agents } = loadAgentsFromDir(officialDir, { kind: "official" });
    expect(validateOfficialAgents(agents)).toEqual([]);
  });
});

describe("loadAllAgents", () => {
  it("returns violations alongside agents and errors", () => {
    writeFileSync(join(officialDir, "wrong-name.md"), md("right-slug"));
    const result = loadAllAgents(env);
    expect(result.agents).toHaveLength(1);
    expect(result.errors).toEqual([]);
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0]).toMatch(/filename does not match slug/);
  });

  it("does not validate custom agents — shadowing and free filenames are allowed", () => {
    const customDir = join(agentggHome, "agents", "custom");
    mkdirSync(customDir, { recursive: true });
    writeFileSync(join(officialDir, "shared.md"), md("shared"));
    writeFileSync(join(customDir, "anything.md"), md("shared"));
    const result = loadAllAgents(env);
    expect(result.agents).toHaveLength(2);
    expect(result.violations).toEqual([]);
  });
});
