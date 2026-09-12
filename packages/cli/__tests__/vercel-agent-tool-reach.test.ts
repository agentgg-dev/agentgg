/**
 * Read and Grep must reach the whole repository. Prod 2026-09-08: detect loops
 * repeated one call to the turn cap because Grep silently walked only the first
 * 500 matching files and Read returned only a file's first 80 KB with no way to
 * ask for more. Driven through the real tool objects, as the SDK calls them.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { zodSchema } from "ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildTools, grepToolExecute, ReadParameters } from "../src/detectors/vercel-agent.js";

let root: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "agentgg-reach-"));
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
  vi.restoreAllMocks();
});

function tools(maxFileSizeKb?: number) {
  return buildTools({
    cwd: root,
    maxFileSizeKb,
    verbose: false,
    label: "test",
    phase: "detect",
  });
}

/** The SDK calls `execute(args, options)`; options is unused by these tools. */
// biome-ignore lint/suspicious/noExplicitAny: exercising the SDK's call shape
const run = (t: any, args: unknown) => t.execute(args, {} as any) as Promise<string>;

const hitLines = (out: string) => out.split("\n").filter((l) => l.includes("needle"));

describe("Grep", () => {
  it("finds the match in every matching file when the repo has more than 500 files", async () => {
    // 100 of 700 files hold the needle. Walk order is up to the file system,
    // so a walk that stops at 500 files misses some of them on any platform.
    for (let i = 0; i < 700; i++) {
      const body = i % 7 === 0 ? `const needle${i} = 1;\n` : "const other = 1;\n";
      writeFileSync(join(root, `f${String(i).padStart(3, "0")}.ts`), body, "utf8");
    }
    const out = await run(tools().Grep, { pattern: "needle", glob: "**/*.ts", path: null });
    expect(hitLines(out)).toHaveLength(100);
  });

  describe("file limit", () => {
    it("says it stopped early when more files match than it will search", async () => {
      for (let i = 0; i < 11; i++) writeFileSync(join(root, `f${i}.ts`), "const x = 1;\n", "utf8");
      const out = await grepToolExecute("needle", "**/*.ts", root, { maxFiles: 10 });
      expect(out).not.toBe("(no matches)");
      expect(out).toMatch(/\b10\b/);
    });

    it("adds no notice when it searched every file", async () => {
      for (let i = 0; i < 11; i++) writeFileSync(join(root, `f${i}.ts`), "const x = 1;\n", "utf8");
      expect(await grepToolExecute("needle", "**/*.ts", root, { maxFiles: 11 })).toBe(
        "(no matches)",
      );
    });

    it("keeps the matches it found and puts the notice after them", async () => {
      for (let i = 0; i < 12; i++) {
        writeFileSync(join(root, `f${i}.ts`), "const needle = 1;\n", "utf8");
      }
      const out = await grepToolExecute("needle", "**/*.ts", root, { maxFiles: 10 });
      const lines = out.split("\n");
      expect(hitLines(out)).toHaveLength(10);
      expect(lines.at(-1)).not.toContain("needle");
      expect(lines.at(-1)).toMatch(/\b10\b/);
    });
  });

  describe("dot directories", () => {
    it("finds a file under .github, which the candidate walker already scans", async () => {
      mkdirSync(join(root, ".github", "workflows"), { recursive: true });
      writeFileSync(join(root, ".github/workflows/ci.yml"), "jobs:\n  needle: {}\n", "utf8");
      const t = tools();
      expect(await run(t.Glob, { pattern: "**/.github/workflows/*.yml" })).toContain(
        ".github/workflows/ci.yml",
      );
      expect(await run(t.Grep, { pattern: "needle", glob: "**/*.yml", path: null })).toContain(
        ".github/workflows/ci.yml",
      );
    });

    it("still skips .git", async () => {
      mkdirSync(join(root, ".git"), { recursive: true });
      writeFileSync(join(root, ".git/config"), "needle = 1\n", "utf8");
      expect(await run(tools().Grep, { pattern: "needle", glob: null, path: null })).toBe(
        "(no matches)",
      );
    });
  });

  describe("output size", () => {
    const grepAll = (t = tools()) => run(t.Grep, { pattern: "needle", glob: null, path: null });

    it("keeps a 500-character matching line, and cuts a longer one but keeps its location", async () => {
      const at500 = `needle${"a".repeat(494)}`;
      const at501 = `needle${"b".repeat(495)}`;
      writeFileSync(join(root, "w.ts"), `${at500}\n${at501}\n`, "utf8");
      const out = await grepAll();
      expect(out).toContain(`w.ts:1: ${at500}`);
      const second = out.split("\n").find((l) => l.startsWith("w.ts:2:"));
      expect(second).toBeDefined();
      expect(second).toContain("[cut from 501 characters]");
    });

    // A bare "[matching line omitted: 21402 characters]" tells the model a match
    // exists and gives it nothing to judge, so it re-runs the search or guesses.
    // Minified and generated code hit this on every match.
    it("shows the text around the match instead of only its length", async () => {
      const long = `${"x".repeat(4000)}needle${"y".repeat(4000)}`;
      writeFileSync(join(root, "min.js"), `${long}\n`, "utf8");

      const out = await grepAll();

      expect(out).toContain("needle");
      expect(out).toContain("cut from 8006 characters");
      expect(out.length).toBeLessThan(2000);
    });

    it("stops one result at 80 KB and says so", async () => {
      // 180 matches of 500 characters: about 92 KB, under the 200-match limit.
      const line = `needle${"c".repeat(494)}`;
      writeFileSync(join(root, "big.ts"), `${Array(180).fill(line).join("\n")}\n`, "utf8");
      const out = await grepAll();
      expect(out.length).toBeLessThanOrEqual(80_000 + 200);
      expect(hitLines(out).length).toBeLessThan(180);
      expect(out.split("\n").at(-1)?.startsWith("(")).toBe(true);
    });

    it("skips binary files", async () => {
      writeFileSync(join(root, "a.ts"), "const needle = 1;\n", "utf8");
      writeFileSync(
        join(root, "blob.bin"),
        Buffer.concat([Buffer.from([0, 1, 2, 0]), Buffer.from("needle"), Buffer.alloc(16)]),
      );
      const out = await grepAll();
      expect(out).toContain("a.ts:1:");
      expect(out).not.toContain("blob.bin");
    });
  });

  describe("files over the size limit", () => {
    const grepAll = (t: ReturnType<typeof tools>) =>
      run(t.Grep, { pattern: "needle", glob: null, path: null });
    const writeHuge = () =>
      writeFileSync(join(root, "huge.ts"), `const needle = 2;\n${"// pad\n".repeat(400)}`, "utf8");

    it("skips a file that Read refuses for size", async () => {
      writeFileSync(join(root, "small.ts"), "const needle = 1;\n", "utf8");
      writeHuge();
      const t = tools(1);
      expect(await run(t.Read, { path: "huge.ts" })).toMatch(/exceeds size limit/);
      const out = await grepAll(t);
      expect(out).toContain("small.ts:1:");
      expect(out).not.toContain("huge.ts");
    });

    it("explains an empty result with the number of large files it skipped", async () => {
      writeFileSync(join(root, "small.ts"), "const other = 1;\n", "utf8");
      writeHuge();
      const lines = (await grepAll(tools(1))).split("\n");
      expect(lines[0]).toBe("(no matches)");
      expect(lines.at(-1)?.startsWith("(")).toBe(true);
      expect(lines.at(-1)).toMatch(/\b1\b/);
    });

    it("adds no size note when it found matches", async () => {
      // Real repos keep a few large files; a note on every result is noise.
      writeFileSync(join(root, "small.ts"), "const needle = 1;\n", "utf8");
      writeHuge();
      expect(await grepAll(tools(1))).toBe("small.ts:1: const needle = 1;");
    });

    it("leaves a large binary file out of that count", async () => {
      writeFileSync(join(root, "small.ts"), "const other = 1;\n", "utf8");
      writeFileSync(
        join(root, "image.bin"),
        Buffer.concat([Buffer.alloc(2048), Buffer.from("needle")]),
      );
      expect(await grepAll(tools(1))).toBe("(no matches)");
    });
  });
});

describe("Read", () => {
  const LINES = 3000;
  /** About 180 KB: well past the 80 KB a single Read returns. */
  function writeBigFile(): string[] {
    const lines = Array.from(
      { length: LINES },
      (_, i) => `const line${i + 1} = "${"x".repeat(40)}";`,
    );
    writeFileSync(join(root, "Big.java"), `${lines.join("\n")}\n`, "utf8");
    return lines;
  }

  it("returns a small file unchanged when no range is given", async () => {
    writeFileSync(join(root, "a.ts"), "const alpha = 1;\nconst beta = 2;\n", "utf8");
    expect(await run(tools().Read, { path: "a.ts" })).toBe("const alpha = 1;\nconst beta = 2;\n");
  });

  it("returns the lines asked for, even past the first 80 KB", async () => {
    const lines = writeBigFile();
    const out = await run(tools().Read, { path: "Big.java", offset: 2900, limit: 3 });
    expect(out).toContain(lines[2899]);
    expect(out).toContain(lines[2901]);
    expect(out).not.toContain(lines[2898]);
    expect(out).not.toContain(lines[2902]);
  });

  it("gives an offset on a cut read that continues with no gap or overlap", async () => {
    writeBigFile();
    const t = tools();
    const seen = new Map<number, number>();
    let offset: number | null = null;
    for (let page = 0; page < 10; page++) {
      const out = await run(t.Read, { path: "Big.java", offset, limit: null });
      for (const m of out.matchAll(/const line(\d+) =/g)) {
        const n = Number(m[1]);
        seen.set(n, (seen.get(n) ?? 0) + 1);
      }
      const next = /offset[ =:]*(\d+)/.exec(out);
      if (!next) break;
      offset = Number(next[1]);
    }
    expect(seen.size).toBe(LINES);
    expect([...seen.values()].every((c) => c === 1)).toBe(true);
  });

  it("does not treat a read of a different part of the same file as a repeat", async () => {
    writeBigFile();
    const t = tools();
    await run(t.Read, { path: "Big.java", offset: 1, limit: 10 });
    const next = await run(t.Read, { path: "Big.java", offset: 11, limit: 10 });
    expect(next).toContain("const line11 =");
    const again = await run(t.Read, { path: "Big.java", offset: 11, limit: 10 });
    expect(again).toContain("already ran this exact");
  });

  it("moves past a single line longer than the cap", async () => {
    // Minified code: one line bigger than a whole page must not trap the model.
    writeFileSync(join(root, "min.js"), `${"x".repeat(100_000)}\nconst after = 1;\n`, "utf8");
    const t = tools();
    const first = await run(t.Read, { path: "min.js" });
    expect(/offset[ =:]*(\d+)/.exec(first)?.[1]).toBe("2");
    expect(await run(t.Read, { path: "min.js", offset: 2, limit: null })).toContain(
      "const after = 1;",
    );
  });

  it("says how long the file is when the offset is past the end", async () => {
    writeFileSync(join(root, "a.ts"), "one\ntwo\nthree\n", "utf8");
    const out = await run(tools().Read, { path: "a.ts", offset: 10, limit: null });
    expect(out).toContain("3 lines");
  });

  // "offset 1 is past the end of the file, which has 0 lines" reads like a
  // wrong path, so the model re-globs for a file it is already holding.
  it("says an empty file is empty rather than reporting a bad offset", async () => {
    writeFileSync(join(root, "empty.ts"), "", "utf8");

    const out = await run(tools().Read, { path: "empty.ts", offset: 1, limit: 20 });

    expect(out).toContain("empty");
    expect(out).not.toContain("past the end");
  });
});

describe("ReadParameters", () => {
  it("satisfies OpenAI strict mode: every property is required", () => {
    const schema = zodSchema(ReadParameters).jsonSchema as {
      properties: Record<string, unknown>;
      required: string[];
      additionalProperties: boolean;
    };
    expect([...schema.required].sort()).toEqual(Object.keys(schema.properties).sort());
    expect(schema.additionalProperties).toBe(false);
  });

  it("accepts a call that gives only a path", () => {
    // Non-strict providers (GLM-5) omit the key rather than sending null.
    expect(ReadParameters.parse({ path: "a.ts" })).toEqual({
      path: "a.ts",
      offset: null,
      limit: null,
    });
  });

  it("accepts whole numbers sent as text", () => {
    // Otherwise the call goes to repair, and a failed repair fails the batch.
    expect(ReadParameters.parse({ path: "a.ts", offset: "2900", limit: "3" })).toEqual({
      path: "a.ts",
      offset: 2900,
      limit: 3,
    });
  });

  it("still rejects text that is not a whole number", () => {
    expect(ReadParameters.safeParse({ path: "a.ts", offset: "abc", limit: null }).success).toBe(
      false,
    );
    expect(ReadParameters.safeParse({ path: "a.ts", offset: "2.5", limit: null }).success).toBe(
      false,
    );
  });

  it("shows the model the same schema for offset and limit", () => {
    const { properties } = zodSchema(ReadParameters).jsonSchema as {
      properties: Record<string, unknown>;
    };
    for (const key of ["offset", "limit"]) {
      expect(properties[key]).toMatchObject({ anyOf: [{ type: "integer" }, { type: "null" }] });
    }
  });
});
