/**
 * The tools show only what is inside the repository. A link can point
 * anywhere, so the tool walks skip links and Read checks the real path.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildTools } from "../src/detectors/vercel-agent.js";
import { linkDir, tryLinkFile } from "./fs-links.js";

let root: string;
let outside: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "agentgg-links-"));
  outside = mkdtempSync(join(tmpdir(), "agentgg-links-outside-"));
  writeFileSync(join(root, "a.ts"), "const a = 1;\n", "utf8");
  writeFileSync(join(outside, "secret.ts"), "const needle = 1;\n", "utf8");
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
  rmSync(outside, { recursive: true, force: true });
  vi.restoreAllMocks();
});

const tools = () => buildTools({ cwd: root, verbose: false, label: "test", phase: "detect" });

/** The SDK calls `execute(args, options)`; options is unused by these tools. */
// biome-ignore lint/suspicious/noExplicitAny: exercising the SDK's call shape
const run = (t: any, args: unknown) => t.execute(args, {} as any) as Promise<string>;

describe("Glob", () => {
  it("lists no link", async () => {
    linkDir(outside, join(root, "lib.ts"));
    expect(await run(tools().Glob, { pattern: "**/*.ts" })).toBe("a.ts");
  });
});

describe("Read", () => {
  it("refuses a path through a folder link that points outside the root", async () => {
    linkDir(outside, join(root, "shared"));
    const out = await run(tools().Read, { path: "shared/secret.ts", offset: null, limit: null });
    expect(out).toMatch(/Access denied/);
  });

  it("refuses a folder next to the root whose name starts with the root's name", async () => {
    const sibling = `${root}2`;
    mkdirSync(sibling);
    writeFileSync(join(sibling, "secret.ts"), "const needle = 1;\n", "utf8");
    try {
      const out = await run(tools().Read, {
        path: join(sibling, "secret.ts"),
        offset: null,
        limit: null,
      });
      expect(out).toMatch(/Access denied/);
    } finally {
      rmSync(sibling, { recursive: true, force: true });
    }
  });
});

describe("Grep", () => {
  it("does not search a file through a link", async (ctx) => {
    if (!tryLinkFile(join(outside, "secret.ts"), join(root, "notes.ts"))) ctx.skip();
    const out = await run(tools().Grep, { pattern: "needle", glob: "**/*.ts", path: null });
    expect(out).toBe("(no matches)");
  });
});
