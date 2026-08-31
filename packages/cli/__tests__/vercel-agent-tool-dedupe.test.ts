/**
 * Tests for the repeated-tool-call guard in detectors/vercel-agent.ts.
 *
 * A stalled tool loop re-issues the same call forever: on 2026-08-10 a
 * validator ran `Grep authenticateAdminApi` 41 times over nine minutes, burned
 * its whole turn budget, and answered with nothing. Each repeat cost a real
 * search and real bytes off the loop's output budget, and nothing in the logs
 * said it was happening.
 *
 * A repeat now short-circuits: no execution, no bytes charged, an actionable
 * notice back, and a warn line per occurrence. This does not by itself end the
 * loop — the model can keep calling — but it makes each iteration nearly free
 * and, for the first time, visible.
 *
 * The notice comes in two tiers. One repeat is a slip, so it says "move on"
 * and deliberately does NOT offer to finalize: on turn 3 of a 200-turn agent
 * that offer is how a healthy session ends with an empty answer. Once the loop
 * looks stuck — one call three times, or five repeats across the loop — it
 * says to stop and answer, which is the exit the 2026-08-10 case needed.
 *
 * Driven through the real tool objects rather than a mock, so the signature
 * logic is exercised exactly as the SDK invokes it.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildTools, repeatNotice } from "../src/detectors/vercel-agent.js";

let root: string;
let warn: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "agentgg-dedupe-"));
  writeFileSync(join(root, "a.ts"), "const alpha = 1;\nconst beta = 2;\n", "utf8");
  writeFileSync(join(root, "b.ts"), "const alpha = 3;\n", "utf8");
  warn = vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
  vi.restoreAllMocks();
});

function tools(phase: "detect" | "validate" = "detect") {
  return buildTools({ cwd: root, verbose: false, label: "test", phase });
}

/** The SDK calls `execute(args, options)`; options is unused by these tools. */
// biome-ignore lint/suspicious/noExplicitAny: exercising the SDK's call shape
const run = (t: any, args: unknown) => t.execute(args, {} as any) as Promise<string>;

describe("repeated tool calls", () => {
  it("returns real output the first time", async () => {
    const t = tools();
    const out = await run(t.Grep, { pattern: "alpha", glob: null, path: null });
    expect(out).toContain("a.ts");
    expect(out).not.toContain("already ran this exact");
  });

  it("short-circuits an identical second call", async () => {
    const t = tools();
    const args = { pattern: "alpha", glob: null, path: null };
    await run(t.Grep, args);
    expect(await run(t.Grep, args)).toBe(repeatNotice("Grep", "detect"));
  });

  it("still runs a different query", async () => {
    const t = tools();
    await run(t.Grep, { pattern: "alpha", glob: null, path: null });
    const out = await run(t.Grep, { pattern: "beta", glob: null, path: null });
    expect(out).toContain("a.ts");
  });

  it("tracks Read and Glob independently of Grep", async () => {
    const t = tools();
    expect(await run(t.Read, { path: "a.ts" })).toContain("alpha");
    expect(await run(t.Read, { path: "a.ts" })).toBe(repeatNotice("Read", "detect"));
    // A Glob that happens to share the pattern string is a different call.
    expect(await run(t.Glob, { pattern: "*.ts" })).toContain("a.ts");
  });

  // Only the stalled notice names an artifact, because only it asks for one.
  it("names the caller's artifact in the stalled notice", async () => {
    const t = tools("validate");
    const args = { pattern: "alpha", glob: null, path: null };
    for (let i = 0; i < 2; i++) await run(t.Grep, args);
    expect(await run(t.Grep, args)).toContain("verdict JSON");
  });
});

describe("stall escalation", () => {
  const args = { pattern: "alpha", glob: null, path: null };

  // The first repeat is a slip. Telling that model to finalize is how a
  // healthy session ends with an empty answer, which is the failure the
  // repeat guard exists to prevent.
  it("tells the model to move on, not to finalize, on the first repeat", async () => {
    const t = tools();
    await run(t.Grep, args);
    const notice = await run(t.Grep, args);
    expect(notice).toContain("Move on");
    expect(notice).not.toContain("output your final");
  });

  it("tells the model to finalize once one call repeats three times", async () => {
    const t = tools();
    for (let i = 0; i < 2; i++) await run(t.Grep, args);
    const notice = await run(t.Grep, args);
    expect(notice).toContain("output your final findings JSON");
    expect(notice).toBe(repeatNotice("Grep", "detect", true));
  });

  // A model that cycles between calls never drives one signature to three,
  // so the per-call counter alone would never escalate.
  it("escalates on cycled calls that no single signature would catch", async () => {
    const t = tools();
    const cycle = [
      { pattern: "alpha", glob: null, path: null },
      { pattern: "beta", glob: null, path: null },
      { pattern: "gamma", glob: null, path: null },
      { pattern: "delta", glob: null, path: null },
      { pattern: "epsilon", glob: null, path: null },
    ];
    for (const c of cycle) await run(t.Grep, c); // 5 first calls, no repeats
    const notices: string[] = [];
    for (const c of cycle) notices.push(await run(t.Grep, c)); // 5 repeats, each n=2
    expect(notices[0]).toContain("Move on");
    expect(notices[4]).toContain("output your final");
  });

  it("marks the stalled tier in the warning line", async () => {
    const t = tools();
    for (let i = 0; i < 3; i++) await run(t.Grep, args);
    const lines = warn.mock.calls.map((c) => String(c[0]));
    expect(lines[0]).not.toContain("stalled");
    expect(lines[1]).toContain("(stalled; telling it to finalize)");
  });
});

describe("signature normalization", () => {
  // `path` is an alias for `glob`; both resolve to one scope before executing,
  // so the two spellings must collapse to a single signature. Otherwise a model
  // alternating between them loops forever undetected.
  it("treats a path and the glob it widens to as the same call", async () => {
    const t = tools();
    await run(t.Grep, { pattern: "alpha", glob: null, path: "." });
    const second = await run(t.Grep, { pattern: "alpha", glob: "{.,./**}", path: null });
    expect(second).toBe(repeatNotice("Grep", "detect"));
  });

  it("does not collapse different scopes", async () => {
    const t = tools();
    await run(t.Grep, { pattern: "alpha", glob: "a.ts", path: null });
    const second = await run(t.Grep, { pattern: "alpha", glob: "b.ts", path: null });
    expect(second).not.toContain("already ran this exact");
  });

  it("does not let a pattern containing a space collide with a scoped search", async () => {
    const t = tools();
    await run(t.Grep, { pattern: "alpha beta", glob: null, path: null });
    const second = await run(t.Grep, { pattern: "alpha", glob: "beta", path: null });
    expect(second).not.toContain("already ran this exact");
  });
});

describe("visibility and cost", () => {
  it("warns once per repeat, with a running count", async () => {
    const t = tools();
    const args = { pattern: "alpha", glob: null, path: null };
    for (let i = 0; i < 4; i++) await run(t.Grep, args);

    const lines = warn.mock.calls.map((c) => String(c[0]));
    expect(lines).toHaveLength(3); // calls 2, 3, 4
    expect(lines[0]).toContain("repeated Grep call #2");
    expect(lines[2]).toContain("repeated Grep call #4");
    expect(lines[0]).toContain("[test]");
  });

  it("does not charge repeats against the output budget", async () => {
    const t = tools();
    const args = { pattern: "alpha", glob: null, path: null };
    const first = await run(t.Grep, args);
    const repeat = await run(t.Grep, args);
    // The notice is a fixed short string; the real result is the costly one.
    expect(repeat.length).toBeLessThan(first.length + repeatNotice("Grep", "detect").length);
    expect(repeat).toBe(repeatNotice("Grep", "detect"));
  });
});
