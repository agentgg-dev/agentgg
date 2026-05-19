import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Agent } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { collectAllFiles, matchesAnyPattern, walkForAgents } from "../src/walker.js";

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "agentgg-walker-"));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function touch(rel: string, content = "x"): void {
  const full = join(tmp, rel);
  mkdirSync(join(full, ".."), { recursive: true });
  writeFileSync(full, content, "utf8");
}

function makeAgent(slug: string, filePatterns: string[]): Agent {
  return {
    slug,
    name: slug,
    description: "x",
    version: "0.0.1",
    mode: "file",
    noiseTier: "normal",
    filePatterns,
    languages: [],
    prefilter: [],
    references: [],
    prompt: "x",
  };
}

describe("matchesAnyPattern", () => {
  it("returns true when patterns are empty (treat as 'all files')", () => {
    expect(matchesAnyPattern("any/path.ts", [])).toBe(true);
  });

  it("matches against a single glob", () => {
    expect(matchesAnyPattern("src/foo.ts", ["**/*.ts"])).toBe(true);
    expect(matchesAnyPattern("src/foo.py", ["**/*.ts"])).toBe(false);
  });

  it("matches against any of several globs", () => {
    expect(matchesAnyPattern("src/a.py", ["**/*.ts", "**/*.py"])).toBe(true);
    expect(matchesAnyPattern("src/a.go", ["**/*.ts", "**/*.py"])).toBe(false);
  });

  it("supports brace expansion", () => {
    expect(matchesAnyPattern("a.ts", ["**/*.{ts,tsx,js}"])).toBe(true);
    expect(matchesAnyPattern("a.tsx", ["**/*.{ts,tsx,js}"])).toBe(true);
    expect(matchesAnyPattern("a.rb", ["**/*.{ts,tsx,js}"])).toBe(false);
  });
});

describe("collectAllFiles", () => {
  it("returns nothing for an empty dir", () => {
    expect(collectAllFiles(tmp)).toEqual([]);
  });

  it("returns POSIX-style relative paths", () => {
    touch("a/b/c.ts");
    const files = collectAllFiles(tmp);
    expect(files).toContain("a/b/c.ts");
  });

  it("skips default-ignored directories", () => {
    touch("src/keep.ts");
    touch("node_modules/foo/bad.ts");
    touch("dist/built.js");
    touch(".git/HEAD");
    const files = collectAllFiles(tmp);
    expect(files).toContain("src/keep.ts");
    expect(files).not.toContain("node_modules/foo/bad.ts");
    expect(files).not.toContain("dist/built.js");
    expect(files).not.toContain(".git/HEAD");
  });

  it("skips the scan-results output dir so re-runs don't loop", () => {
    touch("scan-results/findings/old.md");
    touch("src/real.ts");
    const files = collectAllFiles(tmp);
    expect(files).not.toContain("scan-results/findings/old.md");
    expect(files).toContain("src/real.ts");
  });
});

describe("walkForAgents", () => {
  it("returns one item per agent", () => {
    touch("a.ts");
    const work = walkForAgents(tmp, [makeAgent("x", ["**/*.ts"]), makeAgent("y", ["**/*.py"])]);
    expect(work).toHaveLength(2);
    expect(work.map((w) => w.agent.slug)).toEqual(["x", "y"]);
  });

  it("routes each file to the agents whose filePatterns match it", () => {
    touch("src/foo.ts");
    touch("src/bar.py");
    const work = walkForAgents(tmp, [
      makeAgent("ts-only", ["**/*.ts"]),
      makeAgent("py-only", ["**/*.py"]),
      makeAgent("all", []),
    ]);
    const get = (slug: string) => work.find((w) => w.agent.slug === slug)?.files ?? [];
    expect(get("ts-only")).toEqual(["src/foo.ts"]);
    expect(get("py-only")).toEqual(["src/bar.py"]);
    expect(get("all").sort()).toEqual(["src/bar.py", "src/foo.ts"]);
  });

  it("returns an empty file list when nothing matches", () => {
    touch("a.go");
    const work = walkForAgents(tmp, [makeAgent("ts", ["**/*.ts"])]);
    expect(work[0].files).toEqual([]);
  });
});
