/**
 * Tests for `budgetNotice` in detectors/vercel-agent.ts — what every tool
 * returns once the tool loop's output budget is spent.
 *
 * This message is the model's only instruction once its tools stop working, so
 * it has to be followable. The previous single-message version was not:
 *
 *   "Error: per-session read budget reached (~391 KB). Do not read more files.
 *    Output your final findings JSON now, based on what you have already
 *    examined."
 *
 *   - "findings JSON" is meaningless to the validator, recon, and agent-spec
 *     passes. Those emit a verdict, a brief, and a spec respectively.
 *   - "do not read more files" did not cover the stall actually observed on
 *     2026-08-10, which was 41 repeated Grep calls. A grep is not a file read.
 *   - "Error:" framed a normal limit as a fault, inviting a retry.
 *
 * Pure-function tests — no LLM calls.
 */
import { describe, expect, it } from "vitest";
import { budgetNotice, type ToolLoopPhase } from "../src/detectors/vercel-agent.js";

const PHASES: ToolLoopPhase[] = ["detect", "validate", "recon", "create-agent"];

describe("budgetNotice", () => {
  describe("names the artifact the phase actually produces", () => {
    it.each([
      ["detect", "findings JSON"],
      ["validate", "verdict JSON"],
      ["recon", "brief JSON"],
      ["create-agent", "agent spec JSON"],
    ] as const)("%s asks for %s", (phase, artifact) => {
      expect(budgetNotice(phase)).toContain(`Output your final ${artifact} now`);
    });

    // The regression that motivated this: every phase used to be told to emit
    // findings JSON, which only detection can do.
    it.each([
      "validate",
      "recon",
      "create-agent",
    ] as const)("%s is never told to emit findings JSON", (phase) => {
      expect(budgetNotice(phase)).not.toContain("findings JSON");
    });
  });

  describe("covers every tool, not just file reads", () => {
    it.each(PHASES)("%s names Read, Grep and Glob", (phase) => {
      const notice = budgetNotice(phase);
      expect(notice).toContain("Read");
      expect(notice).toContain("Grep");
      expect(notice).toContain("Glob");
    });

    it.each(PHASES)("%s does not say 'do not read more files'", (phase) => {
      expect(budgetNotice(phase).toLowerCase()).not.toContain("do not read more files");
    });
  });

  describe("reads as a limit, not a fault", () => {
    it.each(PHASES)("%s is not prefixed with Error", (phase) => {
      expect(budgetNotice(phase)).not.toMatch(/^Error/);
    });

    it.each(PHASES)("%s states the budget so the model can see why", (phase) => {
      expect(budgetNotice(phase)).toMatch(/~\d+ KB of tool output in this loop/);
    });
  });
});
