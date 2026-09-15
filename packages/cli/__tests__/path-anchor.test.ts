import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Detector, ReconResult, SuggestExcludesResult } from "../src/detect.js";
import { runRecon } from "../src/recon.js";
import { runSmartExclude } from "../src/smart-exclude.js";

let root: string;
let outDir: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "agentgg-anchor-"));
  outDir = mkdtempSync(join(tmpdir(), "agentgg-anchor-out-"));
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
  rmSync(outDir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

function touch(...rels: string[]): void {
  for (const rel of rels) {
    const full = join(root, rel);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, "x", "utf8");
  }
}

// The fake stands in for the model only: it answers with fixed paths
// whatever the tree holds, like a model that dropped the wrapper folder.
async function smartExclude(globs: string[]): Promise<string[]> {
  const answer: SuggestExcludesResult = { excludes: globs.map((glob) => ({ glob, reason: "r" })) };
  const detector = { suggestExcludes: async () => answer } as unknown as Detector;
  const suggestions = await runSmartExclude({
    rootDir: root,
    detector,
    excludePatterns: [],
    includePatterns: [],
    maxFileSizeBytes: 1024 * 1024,
  });
  return suggestions.map((s) => s.glob);
}

async function reconNotableDirs(notableDirs: string[]): Promise<string[]> {
  const answer: ReconResult = {
    purpose: "p",
    languages: [],
    frameworks: [],
    authModel: null,
    integrations: [],
    notableDirs,
    summary: "s",
  };
  const detector = { recon: async () => answer } as unknown as Detector;
  const report = await runRecon({
    rootDir: root,
    outDir,
    detector,
    fingerprintTags: [],
    excludePatterns: [],
    includePatterns: [],
    maxFileSizeKb: 500,
    maxTurns: 1,
  });
  return report.notableDirs;
}

describe("runSmartExclude path anchoring", () => {
  it("prefixes globs with the one folder that wraps the repo", async () => {
    touch(
      "keystone/package.json",
      "keystone/docs/a.md",
      "keystone/packages/core/tests/t.ts",
      "keystone/packages/core/src/x.ts",
    );
    expect(
      await smartExclude(["docs", "packages/core/tests", "keystone/packages/core/src"]),
    ).toEqual(["keystone/docs", "keystone/packages/core/tests", "keystone/packages/core/src"]);
  });

  it("keeps globs that already match, even when a top-level folder also holds the path", async () => {
    touch("package.json", "docs/a.md", "web/docs/b.md", "src/x.ts");
    expect(await smartExclude(["docs", "**/*.md"])).toEqual(["docs", "**/*.md"]);
  });

  it("prefixes only when exactly one top-level folder holds the path", async () => {
    touch("web/docs/a.md", "web/src/x.ts", "api/docs/b.md", "api/examples/e.ts");
    expect(await smartExclude(["docs", "examples"])).toEqual(["docs", "api/examples"]);
  });

  it("keeps a glob that matches nothing under any folder", async () => {
    touch("keystone/src/x.ts");
    expect(await smartExclude(["**/__tests__", "tests/**"])).toEqual(["**/__tests__", "tests/**"]);
  });
});

describe("runRecon path anchoring", () => {
  it("prefixes notable dir paths with the one folder that wraps the repo", async () => {
    touch("keystone/packages/core/src/lib/express.ts", "keystone/packages/auth/src/index.ts");
    expect(
      await reconNotableDirs([
        "packages/core/src/lib/express.ts — Express server setup",
        "auth handlers under `packages/auth/src/`",
        "the @keystone-6/auth session package",
      ]),
    ).toEqual([
      "keystone/packages/core/src/lib/express.ts — Express server setup",
      "auth handlers under `keystone/packages/auth/src/`",
      "the @keystone-6/auth session package",
    ]);
  });

  it("keeps notable dir paths that exist, even when a top-level folder also holds them", async () => {
    touch("packages/core/src/lib/express.ts", "web/packages/core/src/lib/app.ts");
    expect(await reconNotableDirs(["packages/core/src/lib/ — server setup"])).toEqual([
      "packages/core/src/lib/ — server setup",
    ]);
  });
});
