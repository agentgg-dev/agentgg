import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  addAgents,
  getCustomAgentsDir,
  removeAgent,
} from "../src/agents-fs.js";

const VALID_MD = `---
slug: sample
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

function withSlug(md: string, slug: string): string {
  return md.replace("slug: sample", `slug: ${slug}`);
}

let agentggHome: string;
let env: NodeJS.ProcessEnv;
let scratch: string;

beforeEach(() => {
  agentggHome = mkdtempSync(join(tmpdir(), "agentgg-home-"));
  scratch = mkdtempSync(join(tmpdir(), "agentgg-scratch-"));
  env = { AGENTGG_HOME: agentggHome };
});

afterEach(() => {
  rmSync(agentggHome, { recursive: true, force: true });
  rmSync(scratch, { recursive: true, force: true });
});

describe("getCustomAgentsDir", () => {
  it("resolves under AGENTGG_HOME/agents/custom", () => {
    expect(getCustomAgentsDir(env)).toBe(
      join(agentggHome, "agents", "custom"),
    );
  });
});

describe("addAgents", () => {
  it("adds a single .md file using the slug as the destination filename", () => {
    const file = join(scratch, "whatever-name.md");
    writeFileSync(file, withSlug(VALID_MD, "my-detector"), "utf8");

    const result = addAgents(file, env);

    expect(result.added).toHaveLength(1);
    expect(result.added[0].slug).toBe("my-detector");
    expect(result.added[0].to).toBe(
      join(agentggHome, "agents", "custom", "my-detector.md"),
    );
    expect(existsSync(result.added[0].to)).toBe(true);
  });

  it("adds every .md inside a directory", () => {
    writeFileSync(join(scratch, "a.md"), withSlug(VALID_MD, "agent-a"), "utf8");
    writeFileSync(join(scratch, "b.md"), withSlug(VALID_MD, "agent-b"), "utf8");
    writeFileSync(join(scratch, "notes.txt"), "ignore me", "utf8");

    const result = addAgents(scratch, env);

    expect(result.added.map((a) => a.slug).sort()).toEqual(["agent-a", "agent-b"]);
    expect(result.skipped).toEqual([]);
  });

  it("skips invalid .md files instead of aborting the whole batch", () => {
    writeFileSync(join(scratch, "good.md"), withSlug(VALID_MD, "good"), "utf8");
    writeFileSync(join(scratch, "bad.md"), "not even frontmatter", "utf8");

    const result = addAgents(scratch, env);

    expect(result.added.map((a) => a.slug)).toEqual(["good"]);
    expect(result.skipped).toHaveLength(1);
    expect(result.skipped[0].from).toContain("bad.md");
  });

  it("refuses to overwrite an existing custom agent of the same slug", () => {
    const file = join(scratch, "a.md");
    writeFileSync(file, withSlug(VALID_MD, "dup"), "utf8");

    const first = addAgents(file, env);
    expect(first.added).toHaveLength(1);

    const second = addAgents(file, env);
    expect(second.added).toEqual([]);
    expect(second.skipped).toHaveLength(1);
    expect(second.skipped[0].reason).toMatch(/Already installed/);
  });

  it("throws when the source path doesn't exist", () => {
    expect(() => addAgents(join(scratch, "missing.md"), env)).toThrow(
      /No such file or directory/,
    );
  });

  it("rejects non-.md files when given as a single-file path", () => {
    const file = join(scratch, "notes.txt");
    writeFileSync(file, "x", "utf8");
    expect(() => addAgents(file, env)).toThrow(/Not a \.md file/);
  });

  it("throws when a directory has no .md files at all", () => {
    writeFileSync(join(scratch, "notes.txt"), "x", "utf8");
    expect(() => addAgents(scratch, env)).toThrow(/No \.md files/);
  });
});

describe("removeAgent", () => {
  it("removes a previously-added agent and returns the path", () => {
    writeFileSync(
      join(scratch, "a.md"),
      withSlug(VALID_MD, "to-remove"),
      "utf8",
    );
    addAgents(join(scratch, "a.md"), env);

    const customDir = getCustomAgentsDir(env);
    expect(readdirSync(customDir)).toContain("to-remove.md");

    const removed = removeAgent("to-remove", env);
    expect(removed).toBe(join(customDir, "to-remove.md"));
    expect(readdirSync(customDir)).not.toContain("to-remove.md");
  });

  it("throws when no custom agent has that slug", () => {
    expect(() => removeAgent("ghost-slug", env)).toThrow(/ghost-slug/);
  });

  it("finds an agent by frontmatter slug even when the filename differs", () => {
    // Simulate a user who hand-dropped a file with an off-convention
    // filename — the slug in the frontmatter is still the source of
    // truth. removeAgent walks the dir to find it.
    const customDir = getCustomAgentsDir(env);
    mkdirSync(customDir, { recursive: true });
    const weirdPath = join(customDir, "weird-name.md");
    writeFileSync(
      weirdPath,
      withSlug(VALID_MD, "slug-in-frontmatter"),
      "utf8",
    );

    const removed = removeAgent("slug-in-frontmatter", env);
    expect(removed).toBe(weirdPath);
  });
});
