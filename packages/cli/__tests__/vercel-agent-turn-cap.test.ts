/**
 * Tests for `warnIfTurnCapped` in detectors/vercel-agent.ts — the diagnostic
 * that catches a tool loop ending because it ran out of turns rather than
 * because the model finished.
 *
 * Why this exists: a capped batch produces no findings JSON, the reformat
 * fallback turns that into a valid `{findings: []}`, and the batch is recorded
 * as a clean success. Without this warning a model that degenerated into
 * repeating one Grep is indistinguishable from clean code. Observed in prod on
 * `z-ai/glm-5.2` (scan e43ed580, 2026-08-08): 31 step-groups against a 30-turn
 * cap, 0 findings; the identical rerun found 6.
 *
 * `generateText` is called with `maxSteps = maxTurns + 1`, so the cap is hit
 * when `steps.length` reaches that ceiling. Warn-only by design: a capped batch
 * still records 0 findings and the agent still completes. Pure-function tests —
 * no LLM calls.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { warnIfTurnCapped } from "../src/detectors/vercel-agent.js";

/** A generateText-shaped result with `n` steps, the last one mid tool-call. */
function resultWithSteps(n: number, lastToolCalls = 1) {
  const steps = Array.from({ length: n }, (_, i) => ({
    text: "",
    finishReason: i === n - 1 ? "tool-calls" : "tool-calls",
    toolCalls: i === n - 1 ? Array.from({ length: lastToolCalls }, () => ({})) : [{}],
  }));
  return { steps };
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
    warnIfTurnCapped("sql-injection", resultWithSteps(31), 30);
    expect(warn).toHaveBeenCalledOnce();
    const msg = String(warn.mock.calls[0]?.[0]);
    expect(msg).toContain("sql-injection");
    expect(msg).toContain("30-turn cap");
    expect(msg).toContain("31 steps");
  });

  it("warns at a raised cap supplied via --max-turns", () => {
    warnIfTurnCapped("xss", resultWithSteps(51), 50);
    expect(warn).toHaveBeenCalledOnce();
    expect(String(warn.mock.calls[0]?.[0])).toContain("50-turn cap");
  });

  it("notes when the loop was still mid tool-call — the degenerate-loop signature", () => {
    warnIfTurnCapped("sql-injection", resultWithSteps(31), 30);
    expect(String(warn.mock.calls[0]?.[0])).toContain("still mid tool-call");
  });

  it("omits the mid-tool-call note when the final step made no tool calls", () => {
    warnIfTurnCapped("sql-injection", resultWithSteps(31, 0), 30);
    expect(warn).toHaveBeenCalledOnce();
    expect(String(warn.mock.calls[0]?.[0])).not.toContain("still mid tool-call");
  });

  it("stays silent when the model finished under the cap", () => {
    warnIfTurnCapped("sql-injection", resultWithSteps(11), 30);
    expect(warn).not.toHaveBeenCalled();
  });

  it("stays silent one step below the ceiling (off-by-one guard)", () => {
    warnIfTurnCapped("sql-injection", resultWithSteps(30), 30);
    expect(warn).not.toHaveBeenCalled();
  });

  describe("degrades quietly rather than breaking a scan", () => {
    it.each([
      ["a provider that omits steps", {}],
      ["a non-array steps field", { steps: "nope" }],
      ["a null result", null],
      ["an undefined result", undefined],
    ])("does not throw or warn on %s", (_label, result) => {
      expect(() => warnIfTurnCapped("sql-injection", result, 30)).not.toThrow();
      expect(warn).not.toHaveBeenCalled();
    });

    it("does not throw when the final step has no toolCalls field", () => {
      expect(() =>
        warnIfTurnCapped("sql-injection", { steps: Array.from({ length: 31 }, () => ({})) }, 30),
      ).not.toThrow();
      expect(warn).toHaveBeenCalledOnce();
    });
  });
});
