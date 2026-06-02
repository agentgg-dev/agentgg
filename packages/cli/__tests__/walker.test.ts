import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Agent } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  collectAllFiles,
  DEFAULT_EXCLUDES,
  includedByWhere,
  walkForAgents,
} from "../src/walker.js";

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

// New unified `where` shape: `filePatterns` scopes files; an empty
// `extensions` + empty `filePatterns` means "all files."
function makeAgent(slug: string, filePatterns: string[]): Agent {
  return {
    slug,
    name: slug,
    description: "x",
    version: "0.0.1",
    noiseTier: "normal",
    where: {
      extensions: [],
      filePatterns,
      excludePatterns: [],
      useDefaultExcludes: true,
      preFilter: [],
      maxFilesPerBatch: 5,
      maxTurnsPerBatch: 30,
    },
    prompt: "x",
  };
}

describe("includedByWhere", () => {
  it("returns true when both extensions and filePatterns are empty (all files)", () => {
    expect(includedByWhere("any/path.ts", [], [])).toBe(true);
  });

  it("matches against a single filePattern glob", () => {
    expect(includedByWhere("src/foo.ts", [], ["**/*.ts"])).toBe(true);
    expect(includedByWhere("src/foo.py", [], ["**/*.ts"])).toBe(false);
  });

  it("matches against any of several filePattern globs", () => {
    expect(includedByWhere("src/a.py", [], ["**/*.ts", "**/*.py"])).toBe(true);
    expect(includedByWhere("src/a.go", [], ["**/*.ts", "**/*.py"])).toBe(false);
  });

  it("supports brace expansion", () => {
    expect(includedByWhere("a.ts", [], ["**/*.{ts,tsx,js}"])).toBe(true);
    expect(includedByWhere("a.tsx", [], ["**/*.{ts,tsx,js}"])).toBe(true);
    expect(includedByWhere("a.rb", [], ["**/*.{ts,tsx,js}"])).toBe(false);
  });

  it("matches by extension (nuclei-style) independent of filePatterns", () => {
    expect(includedByWhere("src/foo.ts", ["ts"], [])).toBe(true);
    expect(includedByWhere("src/foo.py", ["ts"], [])).toBe(false);
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

  it("skips excluded directories when handed the default exclude set", () => {
    touch("src/keep.ts");
    touch("node_modules/foo/bad.ts");
    touch("dist/built.js");
    touch(".git/HEAD");
    // The walker is policy-free: the caller opts into DEFAULT_EXCLUDES.
    const files = collectAllFiles(tmp, { excludePatterns: DEFAULT_EXCLUDES });
    expect(files).toContain("src/keep.ts");
    expect(files).not.toContain("node_modules/foo/bad.ts");
    expect(files).not.toContain("dist/built.js");
    expect(files).not.toContain(".git/HEAD");
  });

  it("skips the scan-results output dir so re-runs don't loop", () => {
    touch("scan-results/findings/old.md");
    touch("src/real.ts");
    const files = collectAllFiles(tmp, { excludePatterns: DEFAULT_EXCLUDES });
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

  it("routes each file to the agents whose where matches it", () => {
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
