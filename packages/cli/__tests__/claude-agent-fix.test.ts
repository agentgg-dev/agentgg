import { beforeEach, describe, expect, it, vi } from "vitest";

// The SDK `query` generator is mocked: this asserts the wiring, not the model.
const queryMock = vi.hoisted(() => vi.fn());
vi.mock("@anthropic-ai/claude-agent-sdk", () => ({ query: queryMock }));

const { ClaudeAgentDetector } = await import("../src/detectors/claude-agent.js");

const ARGS = {
  finding: {
    id: "f-1",
    filePath: "src/db.ts",
    title: "SQLi in user lookup",
    vulnSlug: "sql-injection",
    agentSlug: "sql-injection",
    confidence: 0.8,
    summary: "Unparameterized query.",
    details: "User input flows into a template literal.",
    poc: "GET /users?id=1'--",
    impact: "Reads the users table.",
  },
  fileContent: "const q = 'SELECT * FROM t WHERE id=' + id;",
} as never;

describe("ClaudeAgentDetector.suggestFix", () => {
  beforeEach(() => {
    queryMock.mockReset();
  });

  it("sends the fix prompt with no tools and returns the fix text", async () => {
    queryMock.mockImplementation(async function* () {
      yield { type: "result", structured_output: { fix: "Bind the parameter." }, result: "done" };
    });
    const detector = new ClaudeAgentDetector({ apiKey: "test-key", model: "claude-opus-4-8" });

    await expect(detector.suggestFix(ARGS)).resolves.toBe("Bind the parameter.");

    const call = queryMock.mock.calls[0][0] as { prompt: string; options: { tools: string[] } };
    expect(call.prompt).toContain("SQLi in user lookup");
    expect(call.options.tools).toEqual([]);
  });
});
