/**
 * Every Claude Code session agentgg starts must ignore the user's own Claude
 * Code setup (settings, hooks, plugins, CLAUDE.md, MCP servers, auto memory),
 * so a scan behaves the same on every machine.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const queryMock = vi.hoisted(() => vi.fn());
vi.mock("@anthropic-ai/claude-agent-sdk", () => ({ query: queryMock }));

const { ClaudeAgentDetector } = await import("../src/detectors/claude-agent.js");

describe("ClaudeAgentDetector session isolation", () => {
  beforeEach(() => {
    queryMock.mockReset();
    queryMock.mockImplementation(async function* () {
      yield { type: "result", structured_output: { excludes: [] } };
    });
  });

  it("starts the session without the user's Claude Code setup", async () => {
    const detector = new ClaudeAgentDetector({ apiKey: "test-key", model: "claude-opus-4-8" });
    await detector.suggestExcludes({ instructions: "Pick folders.", dirTree: "src/  (3 files)" });

    const { options } = queryMock.mock.calls[0][0];
    expect(options.settingSources).toEqual([]);
    expect(options.strictMcpConfig).toBe(true);
    expect(options.env.CLAUDE_CODE_DISABLE_AUTO_MEMORY).toBe("1");
  });
});
