/**
 * The tool call log. Prod passes no --verbose, so until now its logs held no
 * tool line at all: you saw repeat warnings and never the answers that caused
 * them, and a "(no matches)" loop looked normal. One ungated line per call now
 * carries the arguments the dedupe key sees plus a summary of the result.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildTools, sessionLabel, summarizeToolResult } from "../src/detectors/vercel-agent.js";

let root: string;
let logged: string[];

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "agentgg-toollog-"));
  logged = [];
  vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => {
    logged.push(a.map(String).join(" "));
  });
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
  vi.restoreAllMocks();
});

/** verbose:false — the prod shape. */
function tools() {
  return buildTools({
    cwd: root,
    maxFileSizeKb: undefined,
    verbose: false,
    label: "runAgent:demo",
    phase: "detect",
  });
}

// biome-ignore lint/suspicious/noExplicitAny: exercising the SDK's call shape
const run = (t: any, args: unknown) => t.execute(args, {} as any) as Promise<string>;
const line = (needle: string) => logged.find((l) => l.includes(needle));

describe("tool call log", () => {
  it("logs one line per call without --verbose, with the result", async () => {
    writeFileSync(join(root, "a.ts"), "const needle = 1;\n", "utf8");
    await run(tools().Grep, { pattern: "needle", glob: "**/*.ts", path: null });

    expect(logged).toHaveLength(1);
    expect(logged[0]).toContain("runAgent:demo");
    expect(logged[0]).toContain("needle");
    expect(logged[0]).toContain("1 matches");
  });

  it("logs the resolved scope Grep searched, which is what the repeat guard keys on", async () => {
    writeFileSync(join(root, "a.ts"), "const needle = 1;\n", "utf8");
    // `path` is an alias that widens into a glob; the log must show the glob.
    await run(tools().Grep, { pattern: "needle", glob: null, path: "src" });

    expect(line("needle")).toContain("{src,src/**}");
  });

  it("logs the range Read asked for, so paging cannot look like a repeat", async () => {
    writeFileSync(
      join(root, "big.ts"),
      `${Array.from({ length: 40 }, (_, i) => `l${i + 1}`).join("\n")}\n`,
      "utf8",
    );
    const t = tools();
    await run(t.Read, { path: "big.ts", offset: 11, limit: 10 });

    const entry = line("big.ts");
    expect(entry).toContain("offset=11");
    expect(entry).toContain("limit=10");
    expect(entry).toContain("lines 11-20 of 40");
  });

  it("says when a call was short-circuited instead of run", async () => {
    writeFileSync(join(root, "a.ts"), "const needle = 1;\n", "utf8");
    const t = tools();
    await run(t.Grep, { pattern: "needle", glob: null, path: null });
    await run(t.Grep, { pattern: "needle", glob: null, path: null });

    expect(logged).toHaveLength(2);
    expect(logged[1]).toContain("skipped: repeat");
  });
});

describe("summarizeToolResult", () => {
  it.each([
    ["Grep", "a.ts:1: x\nb.ts:9: y\nb.ts:12: z", "3 matches in 2 files"],
    ["Grep", "(no matches)", "0 matches"],
    [
      "Grep",
      "(no matches)\n(searched only the first 10 files; pass a narrower glob to search the rest)",
      "0 matches (searched only the first 10 files; pass a narrower glob to search the rest)",
    ],
    [
      "Grep",
      "a.ts:1: x\n(truncated at 200 matches)",
      "1 matches in 1 files (truncated at 200 matches)",
    ],
    ["Glob", "a.ts\nb.ts", "2 files"],
    ["Glob", "(no matches)", "0 files"],
    ["Read", "one\ntwo\n", "2 lines, 0 KB"],
    [
      "Read",
      "body\n\n... [showing lines 11-20 of 40 (file is 1 KB). To read more, call Read with offset 21.]",
      "lines 11-20 of 40",
    ],
    ["Read", "Error: File exceeds size limit (600KB > 500KB). Skipped.", "error"],
    [
      "Grep",
      "You already ran this exact Grep call in this loop, and its result is above. ",
      "skipped: repeat",
    ],
    [
      // A covered re-read is NOT an exact repeat, so it needs its own label;
      // without one the Read branch below reports it as a short page.
      "Read",
      "You already read lines 10-29 of a.java in this loop, and that content is above. ",
      "skipped: re-read",
    ],
  ])("summarizes a %s result", (name, out, expected) => {
    expect(summarizeToolResult(name, out)).toContain(expected);
  });
});

/**
 * Five concurrent batches of one agent all logged as `runAgent:<slug>`, so a
 * warning could not be tied to the session that raised it. Every per-cause
 * split in the 2026-09-12 handoff came from counts, not from one session.
 */
describe("session label", () => {
  it("gives two sessions of the same agent distinct labels", () => {
    const first = sessionLabel("runAgent:sql-injection");
    const second = sessionLabel("runAgent:sql-injection");

    expect(first).not.toBe(second);
  });

  it("keeps the agent slug readable and appends a session number", () => {
    expect(sessionLabel("runAgent:sql-injection")).toMatch(/^runAgent:sql-injection#\d+$/);
  });
});
