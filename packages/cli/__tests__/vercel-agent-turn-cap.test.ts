/**
 * Tests for `warnIfTurnCapped` in detectors/vercel-agent.ts — the diagnostic
 * that catches a tool loop ending because it ran out of turns rather than
 * because the model finished.
 *
 * Why this exists: a capped session produces no JSON, the reformat fallback
 * turns that into a valid-looking result, and the session is recorded as a
 * clean success. Without this warning a model that degenerated into repeating
 * one Grep is indistinguishable from real work. Observed in prod on
 * `z-ai/glm-5.2` (scan e43ed580, 2026-08-08): 31 step-groups against a 30-turn
 * cap, 0 findings; the identical rerun found 6. Again on scan e537b214
 * (2026-08-10), this time in the VALIDATOR — 41 identical greps, no verdict,
 * and the reformat invented one. Hence the first arg being a caller-supplied
 * label rather than an agent slug: detection and validation both use this.
 *
 * `generateText` is called with `maxSteps = maxTurns + 1`, so the cap is hit
 * when `steps.length` reaches that ceiling. Warn-only by design. Pure-function
 * tests — no LLM calls.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { warnIfTurnCapped } from "../src/detectors/vercel-agent.js";

/** A generateText-shaped result with `n` steps, the last one mid tool-call. */
function resultWithSteps(n: number, lastToolCalls = 1) {
  const steps = Array.from({ length: n }, (_, i) => ({
    text: "",
    finishReason: "tool-calls",
    toolCalls: i === n - 1 ? Array.from({ length: lastToolCalls }, () => ({})) : [{}],
  }));
  return { steps };
}

/** Same, with a provider generation id stamped on each step's response. */
function resultWithGenIds(n: number) {
  const r = resultWithSteps(n) as {
    steps: Array<Record<string, unknown>>;
  };
  r.steps.forEach((step, i) => {
    step.response = { id: `gen-${i}` };
  });
  return r;
}

describe("warnIfTurnCapped", () => {
  let warn: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  });
  afterEach(() => {
    warn.mockRestore();
  });

  it("warns when the loop used every available step (maxTurns + 1)", () => {
    warnIfTurnCapped("runAgent:sql-injection", resultWithSteps(31), 30);
    expect(warn).toHaveBeenCalledOnce();
    const msg = String(warn.mock.calls[0]?.[0]);
    expect(msg).toContain("runAgent:sql-injection");
    expect(msg).toContain("30-turn cap");
    expect(msg).toContain("31 steps");
  });

  it("warns at a raised cap supplied via --max-turns", () => {
    warnIfTurnCapped("runAgent:xss", resultWithSteps(51), 50);
    expect(warn).toHaveBeenCalledOnce();
    expect(String(warn.mock.calls[0]?.[0])).toContain("50-turn cap");
  });

  it("labels a validator session by finding id, not agent slug", () => {
    warnIfTurnCapped("validate:197815be26e3", resultWithSteps(51), 50);
    expect(String(warn.mock.calls[0]?.[0])).toContain("validate:197815be26e3");
  });

  it("notes when the loop was still mid tool-call — the degenerate-loop signature", () => {
    warnIfTurnCapped("runAgent:sql-injection", resultWithSteps(31), 30);
    expect(String(warn.mock.calls[0]?.[0])).toContain("still mid tool-call");
  });

  it("omits the mid-tool-call note when the final step made no tool calls", () => {
    warnIfTurnCapped("runAgent:sql-injection", resultWithSteps(31, 0), 30);
    expect(warn).toHaveBeenCalledOnce();
    expect(String(warn.mock.calls[0]?.[0])).not.toContain("still mid tool-call");
  });

  it("stays silent when the model finished under the cap", () => {
    warnIfTurnCapped("runAgent:sql-injection", resultWithSteps(11), 30);
    expect(warn).not.toHaveBeenCalled();
  });

  it("stays silent one step below the ceiling (off-by-one guard)", () => {
    warnIfTurnCapped("runAgent:sql-injection", resultWithSteps(30), 30);
    expect(warn).not.toHaveBeenCalled();
  });

  describe("generation ids", () => {
    it("reports the id range and call count so the provider log is searchable", () => {
      warnIfTurnCapped("validate:abc123", resultWithGenIds(31), 30);
      const msg = String(warn.mock.calls[0]?.[0]);
      expect(msg).toContain("genIds=gen-0..gen-30");
      expect(msg).toContain("(31 calls)");
    });

    it("reports a bare id when only one generation is exposed", () => {
      warnIfTurnCapped("validate:abc123", { steps: resultWithGenIds(31).steps.slice(0, 1) }, 0);
      expect(String(warn.mock.calls[0]?.[0])).toContain("genId=gen-0");
    });

    it("says nothing about ids when the provider exposes none", () => {
      warnIfTurnCapped("runAgent:sql-injection", resultWithSteps(31), 30);
      expect(String(warn.mock.calls[0]?.[0])).not.toContain("genId");
    });

    it("falls back to the top-level response id when steps carry none", () => {
      const r = { ...resultWithSteps(31), response: { id: "gen-top" } };
      warnIfTurnCapped("runAgent:sql-injection", r, 30);
      expect(String(warn.mock.calls[0]?.[0])).toContain("genId=gen-top");
    });
  });

  describe("degrades quietly rather than breaking a scan", () => {
    it.each([
      ["a provider that omits steps", {}],
      ["a non-array steps field", { steps: "nope" }],
      ["a null result", null],
      ["an undefined result", undefined],
    ])("does not throw or warn on %s", (_label, result) => {
      expect(() => warnIfTurnCapped("runAgent:sql-injection", result, 30)).not.toThrow();
      expect(warn).not.toHaveBeenCalled();
    });

    it("does not throw when the final step has no toolCalls field", () => {
      expect(() =>
        warnIfTurnCapped(
          "runAgent:sql-injection",
          { steps: Array.from({ length: 31 }, () => ({})) },
          30,
        ),
      ).not.toThrow();
      expect(warn).toHaveBeenCalledOnce();
    });
  });
});
