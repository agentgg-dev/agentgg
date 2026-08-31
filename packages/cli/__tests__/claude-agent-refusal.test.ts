/**
 * Refusal routing for the `anthropic` provider (ClaudeAgentDetector).
 *
 * A refusal reaches `runStructured` as a terminal `result` message carrying
 * prose and no `structured_output` — indistinguishable, at that layer, from a
 * genuinely failed generation. `runStructured` classifies it and throws
 * `RefusalError`; the phase-specific callers substitute an empty result so the
 * agent completes instead of failing (and burning its solo retry).
 *
 * The SDK `query` generator is mocked: these assert the routing, not the model.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const queryMock = vi.hoisted(() => vi.fn());
vi.mock("@anthropic-ai/claude-agent-sdk", () => ({ query: queryMock }));

const { ClaudeAgentDetector } = await import("../src/detectors/claude-agent.js");

/** Mock one terminal `result` message with the given fields. */
function mockResult(fields: Record<string, unknown>) {
  queryMock.mockImplementation(async function* () {
    yield { type: "result", ...fields };
  });
}

const REFUSAL = "I can't help analyze this exploit code.";

function makeDetector() {
  return new ClaudeAgentDetector({ apiKey: "test-key", model: "claude-opus-4-8" });
}

const AGENT = { slug: "sql-injection", prompt: "Find SQL injection." } as never;

function runAgentArgs() {
  return {
    agent: AGENT,
    candidates: [{ filePath: "src/db.ts", content: "const q = 'SELECT 1';", hits: [] }],
    rootDir: process.cwd(),
    // Required by RunAgentArgs; the `as never` below hides their absence from
    // the compiler, so they have to be supplied by hand.
    excludePatterns: [],
    maxFileSizeKb: 512,
    maxTurns: 3,
  } as never;
}

function validateArgs() {
  return {
    finding: {
      id: "f-1",
      filePath: "src/db.ts",
      title: "SQLi",
      vulnSlug: "sql-injection",
      agentSlug: "sql-injection",
      confidence: 0.8,
      summary: "Unparameterized query.",
      details: "User input flows into a template literal.",
      poc: "GET /users?id=1'--",
    },
    fileContent: "const q = 'SELECT * FROM t WHERE id=' + id;",
  } as never;
}

describe("ClaudeAgentDetector refusal routing", () => {
  beforeEach(() => {
    queryMock.mockReset();
    vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  describe("runAgent", () => {
    it("returns 0 findings when the model refuses", async () => {
      mockResult({ result: REFUSAL });
      await expect(makeDetector().runAgent(runAgentArgs())).resolves.toEqual([]);
    });

    it("still throws on a non-refusal empty generation", async () => {
      mockResult({ result: "" });
      await expect(makeDetector().runAgent(runAgentArgs())).rejects.toThrow(/no structured_output/);
    });

    it("still throws when the output is prose but not a refusal", async () => {
      mockResult({ result: "Here are the findings I identified:" });
      await expect(makeDetector().runAgent(runAgentArgs())).rejects.toThrow(/no structured_output/);
    });

    it("returns findings normally when structured output is present", async () => {
      mockResult({ structured_output: { findings: [] }, result: "done" });
      await expect(makeDetector().runAgent(runAgentArgs())).resolves.toEqual([]);
    });
  });

  describe("validateFinding", () => {
    it("records uncertain+refused when the model refuses", async () => {
      mockResult({ result: REFUSAL });
      await expect(makeDetector().validateFinding(validateArgs())).resolves.toEqual({
        verdict: "uncertain",
        reasoning: "Model declined to validate this finding (refusal).",
        refused: true,
      });
    });

    it("still throws on a non-refusal empty generation", async () => {
      mockResult({ result: "" });
      await expect(makeDetector().validateFinding(validateArgs())).rejects.toThrow(
        /no structured_output/,
      );
    });

    it("passes a real verdict through untouched", async () => {
      mockResult({
        structured_output: {
          verdict: "confirmed",
          reasoning: "Reachable from the handler.",
          confidence: 0.9,
        },
      });
      await expect(makeDetector().validateFinding(validateArgs())).resolves.toEqual({
        verdict: "confirmed",
        reasoning: "Reachable from the handler.",
      });
    });
  });

  describe("other phases still fail loud", () => {
    it("dedupeFindings propagates a refusal as an error", async () => {
      mockResult({ result: REFUSAL });
      await expect(
        makeDetector().dedupeFindings({ filePath: "src/db.ts", findings: [] }),
      ).rejects.toThrow(/refused/i);
    });
  });
});
