/**
 * Peak transcript size in the empty-answer diagnostic.
 *
 * `result.usage.promptTokens` on a multi-step loop is the SUM over every step,
 * so it grows with the step count and says nothing about how close the
 * transcript came to the context window. The last step's own prompt is the
 * peak, and a peak near the model's limit is its own failure cause: the
 * provider truncates and the model answers with nothing. Two runs in the
 * 2026-09-12 handoff ended with no text and no tool call, and neither log
 * could tell a runaway generation from an overfull transcript.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { logUnparseableGeneration } from "../src/detectors/vercel-agent.js";

let warned: string[];

beforeEach(() => {
  warned = [];
  vi.spyOn(console, "warn").mockImplementation((...a: unknown[]) => {
    warned.push(a.map(String).join(" "));
  });
});

afterEach(() => vi.restoreAllMocks());

describe("empty-answer diagnostic", () => {
  it("reports the last step's prompt tokens, not just the sum over steps", () => {
    logUnparseableGeneration("runAgent:sql-injection#3", {
      text: "",
      finishReason: "stop",
      usage: { promptTokens: 900_000, completionTokens: 0 },
      steps: [
        { finishReason: "tool-calls", usage: { promptTokens: 12_000, completionTokens: 50 } },
        { finishReason: "stop", usage: { promptTokens: 48_000, completionTokens: 0 } },
      ],
    });

    expect(warned[0]).toContain("lastPromptTokens=48000");
    expect(warned[0]).toContain("promptTokens=900000");
  });

  it("degrades to 0 when the provider reports no per-step usage", () => {
    logUnparseableGeneration("runAgent:sql-injection#4", {
      text: "",
      finishReason: "stop",
      steps: [{ finishReason: "stop" }],
    });

    expect(warned[0]).toContain("lastPromptTokens=0");
  });
});
