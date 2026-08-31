import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent, loadAgentsFromDir } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  defaultAgentDirs,
  lintOfficialAgents,
  loadAllAgents,
  warnOfficialAgents,
} from "../src/agent-catalog.js";

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

describe("lintOfficialAgents", () => {
  it("returns no violations on a clean tree", () => {
    writeFileSync(join(officialDir, "foo.md"), md("foo"));
    mkdirSync(join(officialDir, "sub"), { recursive: true });
    writeFileSync(join(officialDir, "sub", "bar.md"), md("bar"));
    const { agents } = loadAgentsFromDir(officialDir, { kind: "official" });
    expect(lintOfficialAgents(agents)).toEqual([]);
  });

  it("flags duplicate slugs across subdirs with both paths", () => {
    mkdirSync(join(officialDir, "a"), { recursive: true });
    mkdirSync(join(officialDir, "b"), { recursive: true });
    writeFileSync(join(officialDir, "a", "dup.md"), md("dup"));
    writeFileSync(join(officialDir, "b", "dup.md"), md("dup"));
    const { agents } = loadAgentsFromDir(officialDir, { kind: "official" });
    const violations = lintOfficialAgents(agents);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatch(/duplicate slug 'dup'/);
    expect(violations[0]).toMatch(/a[\\/]dup\.md/);
    expect(violations[0]).toMatch(/b[\\/]dup\.md/);
  });

  it("flags filename that does not match slug", () => {
    writeFileSync(join(officialDir, "wrong-name.md"), md("right-slug"));
    const { agents } = loadAgentsFromDir(officialDir, { kind: "official" });
    const violations = lintOfficialAgents(agents);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatch(
      /filename does not match slug: 'wrong-name\.md' should be 'right-slug\.md'/,
    );
  });

  it("accepts demo agents with the -demo suffix convention", () => {
    mkdirSync(join(officialDir, "openclaw"), { recursive: true });
    mkdirSync(join(officialDir, "demo-agents"), { recursive: true });
    writeFileSync(join(officialDir, "openclaw", "openclaw-audit.md"), md("openclaw-audit"));
    writeFileSync(
      join(officialDir, "demo-agents", "openclaw-audit-demo.md"),
      md("openclaw-audit-demo"),
    );
    const { agents } = loadAgentsFromDir(officialDir, { kind: "official" });
    expect(lintOfficialAgents(agents)).toEqual([]);
  });
});

describe("lintOfficialAgents — unrecognized preFilter forms", () => {
  const withPreFilter = (preFilter: unknown[]) =>
    [
      {
        slug: "t",
        source: { kind: "official", path: "/a/t.md" },
        where: { preFilter },
      },
    ] as unknown as Parameters<typeof lintOfficialAgents>[0];

  it("flags a form the CLI does not understand, so a typo is caught in CI", () => {
    const violations = lintOfficialAgents(withPreFilter([{ semgreprule: "http-endpoints" }]));
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatch(/not a form this agentgg understands/);
    expect(violations[0]).toMatch(/semgreprule/);
  });

  it("accepts the two known forms without complaint", () => {
    expect(
      lintOfficialAgents(withPreFilter([{ regex: "x" }, { semgrepRule: "http-endpoints" }])),
    ).toEqual([]);
  });
});

describe("defaultAgentDirs", () => {
  it("returns every category under agents/ except deep", () => {
    for (const d of ["injection", "auth", "deep"]) {
      mkdirSync(join(officialDir, "agents", d), { recursive: true });
    }
    const dirs = defaultAgentDirs(officialDir);
    expect(dirs.sort()).toEqual(
      [join(officialDir, "agents", "auth"), join(officialDir, "agents", "injection")].sort(),
    );
  });

  it("ignores loose files sitting directly under agents/", () => {
    mkdirSync(join(officialDir, "agents", "auth"), { recursive: true });
    writeFileSync(join(officialDir, "agents", "README.md"), "not an agent dir");
    expect(defaultAgentDirs(officialDir)).toEqual([join(officialDir, "agents", "auth")]);
  });

  it("falls back to the pre-restructure base/ layout", () => {
    mkdirSync(join(officialDir, "base", "injection"), { recursive: true });
    expect(defaultAgentDirs(officialDir)).toEqual([join(officialDir, "base")]);
  });

  it("prefers agents/ over base/ when both exist", () => {
    mkdirSync(join(officialDir, "agents", "auth"), { recursive: true });
    mkdirSync(join(officialDir, "base", "injection"), { recursive: true });
    expect(defaultAgentDirs(officialDir)).toEqual([join(officialDir, "agents", "auth")]);
  });

  it("returns nothing when neither layout is present", () => {
    expect(defaultAgentDirs(officialDir)).toEqual([]);
  });
});

describe("loadAllAgents", () => {
  it("does not run lint at runtime — broken official tree still loads", () => {
    // Filename mismatch is a hygiene violation, but scan must still
    // work. The agentgg-agents pre-commit hook is the gate.
    writeFileSync(join(officialDir, "wrong-name.md"), md("right-slug"));
    const result = loadAllAgents(env);
    expect(result.agents).toHaveLength(1);
    expect(result.errors).toEqual([]);
  });

  it("loads official and custom agents into one flat catalog", () => {
    const customDir = join(agentggHome, "agents", "custom");
    mkdirSync(customDir, { recursive: true });
    writeFileSync(join(officialDir, "shared.md"), md("shared"));
    writeFileSync(join(customDir, "anything.md"), md("shared"));
    const result = loadAllAgents(env);
    // Both load — official-vs-custom shadow is intentional, the user
    // gets to keep their tweaked copy alongside the upstream one.
    expect(result.agents).toHaveLength(2);
  });
});

describe("warnOfficialAgents", () => {
  function agentWith(slug: string, where: Record<string, unknown>) {
    return Agent.parse({
      slug,
      name: slug,
      description: "One line.",
      prompt: "body",
      where,
      source: { kind: "official", path: `/agents/${slug}.md` },
    });
  }

  it("warns when an agent declares no extensions and no filePatterns", () => {
    const warnings = warnOfficialAgents([agentWith("no-scope", {})]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("no-scope");
    expect(warnings[0]).toContain("whole repository");
  });

  it("says nothing extra when an agent with no file scope declares a turn budget", () => {
    // Declaring a budget is how any agent sets one, and it beats the default
    // whether that default is 50 or 150. Scoped agents do it routinely, so it
    // is not a defect and gets no warning of its own.
    const warnings = warnOfficialAgents([agentWith("no-scope", { maxTurnsPerBatch: 30 })]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("whole repository");
  });

  it("is silent for a scoped agent that declares a turn budget", () => {
    const warnings = warnOfficialAgents([
      agentWith("scoped", { extensions: ["ts"], maxTurnsPerBatch: 30 }),
    ]);
    expect(warnings).toEqual([]);
  });

  it("emits no em dash, so the warnings read as ordinary CLI copy", () => {
    const warnings = warnOfficialAgents([agentWith("no-scope", { maxTurnsPerBatch: 30 })]);
    for (const w of warnings) expect(w).not.toContain("\u2014");
  });

  it("is silent for an agent that declares extensions", () => {
    expect(warnOfficialAgents([agentWith("scoped", { extensions: ["ts"] })])).toEqual([]);
  });

  it("is silent for an agent that declares filePatterns", () => {
    expect(warnOfficialAgents([agentWith("scoped", { filePatterns: ["src/**"] })])).toEqual([]);
  });

  it("does not report the warning as a violation", () => {
    expect(lintOfficialAgents([agentWith("no-scope", {})])).toEqual([]);
  });
});
