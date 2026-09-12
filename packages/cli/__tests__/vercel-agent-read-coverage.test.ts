/**
 * Range-aware Read repeat detection.
 *
 * The exact-signature guard keys on `(path, offset, limit)`, so every window of
 * a file is a distinct call and a re-read is invisible. In the failing session
 * of 2026-09-12 the model read `FilterToSqlHelper.java` 41 times: it paged
 * 690-1349, filled in 230-689, then crawled the region it already held in
 * 20-line windows. About 29 of 41 reads returned content it already had, yet
 * `stalls` stayed 0 and the loop ran to step 61.
 *
 * Coverage is per path, as merged line intervals. A read already inside them is
 * a repeat. A read that reaches past them is progress and must stay allowed.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildTools, readCoverage } from "../src/detectors/vercel-agent.js";

describe("read coverage", () => {
  it("covers nothing before the first read", () => {
    expect(readCoverage().covers("a.java", 1, 50)).toBe(false);
  });

  it("treats a window inside an earlier read as covered", () => {
    const c = readCoverage();
    c.add("a.java", 1, 100);

    expect(c.covers("a.java", 10, 20)).toBe(true);
  });

  it("treats a read that reaches past the covered end as progress", () => {
    const c = readCoverage();
    c.add("a.java", 1, 100);

    expect(c.covers("a.java", 90, 150)).toBe(false);
  });

  it("merges adjacent pages so a window spanning both counts as covered", () => {
    const c = readCoverage();
    c.add("a.java", 1, 100);
    c.add("a.java", 101, 200);

    expect(c.covers("a.java", 50, 150)).toBe(true);
  });

  it("does not merge across a gap", () => {
    const c = readCoverage();
    c.add("a.java", 1, 100);
    c.add("a.java", 200, 300);

    expect(c.covers("a.java", 150, 250)).toBe(false);
  });

  it("keeps paths separate", () => {
    const c = readCoverage();
    c.add("a.java", 1, 100);

    expect(c.covers("b.java", 10, 20)).toBe(false);
  });

  it("treats a whole-file request as covered only by a whole-file read", () => {
    const c = readCoverage();
    c.add("a.java", 1, 1349);

    // `limit: null` asks for everything from `offset` on; the end is unknown
    // until the read runs, so the caller passes Infinity.
    expect(c.covers("a.java", 1, Number.POSITIVE_INFINITY)).toBe(false);
    expect(c.covers("a.java", 730, 749)).toBe(true);
  });
});

describe("Read tool, range aware", () => {
  let root: string;
  let stalls: number;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "agentgg-readcov-"));
    stalls = 0;
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  const tools = () =>
    buildTools({
      cwd: root,
      maxFileSizeKb: undefined,
      verbose: false,
      label: "runAgent:demo#1",
      phase: "detect",
      onStall: () => {
        stalls++;
      },
    });

  /** `lines` numbered so an assertion can name the content of one window. */
  function writeFile(name: string, lines: number): void {
    const body = Array.from({ length: lines }, (_, i) => `line ${i + 1}`).join("\n");
    writeFileSync(join(root, name), `${body}\n`, "utf8");
  }

  // biome-ignore lint/suspicious/noExplicitAny: exercising the SDK's call shape
  const read = (t: any, args: unknown) => t.execute(args, {} as any) as Promise<string>;

  it("refuses a window the model already holds from a whole-file read", async () => {
    writeFile("a.java", 300);
    const t = tools();
    await read(t.Read, { path: "a.java", offset: null, limit: null });

    const again = await read(t.Read, { path: "a.java", offset: 100, limit: 20 });

    expect(again).not.toContain("line 105");
    expect(again).toContain("already");
  });

  it("still allows paging past the end of what it holds", async () => {
    writeFile("a.java", 300);
    const t = tools();
    await read(t.Read, { path: "a.java", offset: 1, limit: 100 });

    const next = await read(t.Read, { path: "a.java", offset: 101, limit: 100 });

    expect(next).toContain("line 150");
  });

  it("counts a covered re-read toward the stall that turns the tools off", async () => {
    writeFile("a.java", 300);
    const t = tools();
    await read(t.Read, { path: "a.java", offset: null, limit: null });

    await read(t.Read, { path: "a.java", offset: 10, limit: 20 });
    await read(t.Read, { path: "a.java", offset: 40, limit: 20 });
    await read(t.Read, { path: "a.java", offset: 70, limit: 20 });

    expect(stalls).toBeGreaterThan(0);
  });
});

/**
 * Where to go next after a covered read.
 *
 * In test 1 (2026-09-12) session #4 swept PostGISDialect.java in order, 1-50
 * through 550-599, and at 600 met a region it had read earlier while tracing
 * `escapeName`. The notice said "read a part of the file you have not seen" and
 * named none, so the model retried the same window three times, stalled, and
 * lost its tools mid-sweep. A block that names no way forward is a dead end.
 */
describe("read coverage, next unread line", () => {
  it("points past the covered region the read landed in", () => {
    const c = readCoverage();
    c.add("a.java", 600, 649);

    expect(c.nextUnread("a.java", 600)).toBe(650);
  });

  it("returns the asked-for line when it is not covered", () => {
    const c = readCoverage();
    c.add("a.java", 600, 649);

    expect(c.nextUnread("a.java", 700)).toBe(700);
  });

  it("skips a whole run of touching regions, not just the first", () => {
    const c = readCoverage();
    c.add("a.java", 600, 649);
    c.add("a.java", 650, 699);

    expect(c.nextUnread("a.java", 610)).toBe(700);
  });

  it("reports nothing left once the whole file is covered", () => {
    const c = readCoverage();
    c.add("a.java", 1, 1558, 1558);

    expect(c.nextUnread("a.java", 600)).toBeNull();
  });

  it("still points forward when the total is not known yet", () => {
    const c = readCoverage();
    c.add("a.java", 1, 100);

    expect(c.nextUnread("a.java", 50)).toBe(101);
  });
});

describe("covered-read notice names the way forward", () => {
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "agentgg-readnext-"));
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  function writeFile(name: string, lines: number): void {
    const body = Array.from({ length: lines }, (_, i) => `line ${i + 1}`).join("\n");
    writeFileSync(join(root, name), `${body}\n`, "utf8");
  }

  const tools = () =>
    buildTools({
      cwd: root,
      maxFileSizeKb: undefined,
      verbose: false,
      label: "runAgent:demo#1",
      phase: "detect",
    });

  // biome-ignore lint/suspicious/noExplicitAny: exercising the SDK's call shape
  const read = (t: any, args: unknown) => t.execute(args, {} as any) as Promise<string>;

  it("names the next unread line so an orderly sweep can resume", async () => {
    writeFile("a.java", 1558);
    const t = tools();
    // The trace that broke session #4: a scattered read first, then a sweep
    // that walks into it.
    await read(t.Read, { path: "a.java", offset: 600, limit: 50 });

    const blocked = await read(t.Read, { path: "a.java", offset: 610, limit: 40 });

    expect(blocked).toContain("650");
  });

  it("tells the model to stop reading once the whole file is covered", async () => {
    writeFile("a.java", 40);
    const t = tools();
    await read(t.Read, { path: "a.java", offset: null, limit: null });

    const blocked = await read(t.Read, { path: "a.java", offset: 10, limit: 5 });

    expect(blocked).toContain("whole file");
  });
});
