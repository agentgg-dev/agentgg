import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "@agentgg/core";

// Hoisted mock so it's installed before claude-agent.ts pulls in the
// SDK's `query` function. The mock is reconfigured per-test.
const queryMock = vi.hoisted(() => vi.fn());
vi.mock("@anthropic-ai/claude-agent-sdk", () => ({
  query: queryMock,
}));

import { ClaudeAgentDetector, parseJsonObject } from "../src/detectors/claude-agent.js";

describe("parseJsonObject", () => {
  it("parses pure JSON", () => {
    const out = parseJsonObject('{"findings":[]}');
    expect(out).toEqual({ findings: [] });
  });

  it("trims surrounding whitespace", () => {
    const out = parseJsonObject('   \n  {"findings":[]}  \n  ');
    expect(out).toEqual({ findings: [] });
  });

  it("strips ```json fences", () => {
    const text = '```json\n{"findings":[{"title":"X"}]}\n```';
    const out = parseJsonObject(text);
    expect(out).toEqual({ findings: [{ title: "X" }] });
  });

  it("strips plain ``` fences", () => {
    const text = '```\n{"findings":[]}\n```';
    const out = parseJsonObject(text);
    expect(out).toEqual({ findings: [] });
  });

  it("extracts the JSON object when the model wraps it in prose", () => {
    const text =
      'Here is the result you asked for:\n\n{"findings":[{"title":"Y"}]}\n\nLet me know if you need anything else.';
    const out = parseJsonObject(text);
    expect(out).toEqual({ findings: [{ title: "Y" }] });
  });

  it("throws a clear error on garbage input", () => {
    expect(() => parseJsonObject("not json at all")).toThrow(/parseable JSON/);
  });

  it("throws on empty input", () => {
    expect(() => parseJsonObject("")).toThrow(/parseable JSON/);
  });
});

describe("ClaudeAgentDetector.validateFinding (retry on bad JSON)", () => {
  beforeEach(() => {
    queryMock.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  function yieldResult(text: string) {
    return (async function* () {
      yield { type: "result", subtype: "success", result: text };
    })();
  }

  function makeFinding(): Finding {
    return {
      id: "abc123abc123",
      agentSlug: "sql-injection",
      title: "test",
      vulnSlug: "sql-injection",
      filePath: "src/foo.ts",
      summary: "s",
      details: "d",
      poc: "p",
      impact: "i",
      references: [],
      confidence: 0.8,
      notifications: [],
    };
  }

  it("returns the first attempt's verdict when JSON parses cleanly", async () => {
    const good = JSON.stringify({
      verdict: "confirmed",
      reasoning: "ok",
      confidence: 0.9,
    });
    queryMock.mockImplementationOnce(() => yieldResult(good));

    const detector = new ClaudeAgentDetector({
      apiKey: "sk-ant-test",
      model: "claude-sonnet-4-6",
    });
    const result = await detector.validateFinding({
      finding: makeFinding(),
      fileContent: "x",
    });

    expect(queryMock).toHaveBeenCalledTimes(1);
    expect(result.verdict).toBe("confirmed");
    expect(result.reasoning).toBe("ok");
  });

  it("retries once and succeeds when the first response is malformed JSON", async () => {
    // Bad JSON: stray invalid escape sequence inside a string. Same
    // shape as the production failure ("Bad escaped character at
    // position N"). JSON.parse should reject this.
    const bad = '{"verdict": "confirmed", "reasoning": "the regex \\X here", "confidence": 0.9}';
    const good = JSON.stringify({
      verdict: "false-positive",
      reasoning: "second-attempt verdict",
      confidence: 0.85,
    });
    queryMock.mockImplementationOnce(() => yieldResult(bad));
    queryMock.mockImplementationOnce(() => yieldResult(good));

    const detector = new ClaudeAgentDetector({
      apiKey: "sk-ant-test",
      model: "claude-sonnet-4-6",
    });
    const result = await detector.validateFinding({
      finding: makeFinding(),
      fileContent: "x",
    });

    expect(queryMock).toHaveBeenCalledTimes(2);
    expect(result.verdict).toBe("false-positive");
    expect(result.reasoning).toBe("second-attempt verdict");
  });

  it("retries when the JSON is well-formed but doesn't match the schema", async () => {
    // Valid JSON, wrong shape — LlmValidation.parse rejects an
    // unknown verdict. Retry path should still fire.
    const wrongShape = JSON.stringify({
      verdict: "totally-vulnerable",
      reasoning: "nope",
      confidence: 0.5,
    });
    const good = JSON.stringify({
      verdict: "uncertain",
      reasoning: "after retry",
      confidence: 0.5,
    });
    queryMock.mockImplementationOnce(() => yieldResult(wrongShape));
    queryMock.mockImplementationOnce(() => yieldResult(good));

    const detector = new ClaudeAgentDetector({
      apiKey: "sk-ant-test",
      model: "claude-sonnet-4-6",
    });
    const result = await detector.validateFinding({
      finding: makeFinding(),
      fileContent: "x",
    });

    expect(queryMock).toHaveBeenCalledTimes(2);
    expect(result.verdict).toBe("uncertain");
  });

  it("throws when both attempts fail to parse", async () => {
    queryMock.mockImplementationOnce(() => yieldResult("not json at all"));
    queryMock.mockImplementationOnce(() => yieldResult("still not json"));

    const detector = new ClaudeAgentDetector({
      apiKey: "sk-ant-test",
      model: "claude-sonnet-4-6",
    });
    await expect(
      detector.validateFinding({
        finding: makeFinding(),
        fileContent: "x",
      }),
    ).rejects.toThrow();
    expect(queryMock).toHaveBeenCalledTimes(2);
  });

  it("includes the prior error in the retry prompt so the model can self-correct", async () => {
    const bad = '{"verdict": "confirmed", "reasoning": "bad \\X", "confidence": 0.9}';
    const good = JSON.stringify({
      verdict: "confirmed",
      reasoning: "ok",
      confidence: 0.9,
    });
    let secondPrompt = "";
    queryMock.mockImplementationOnce(() => yieldResult(bad));
    queryMock.mockImplementationOnce((args: { prompt: string }) => {
      secondPrompt = args.prompt;
      return yieldResult(good);
    });

    const detector = new ClaudeAgentDetector({
      apiKey: "sk-ant-test",
      model: "claude-sonnet-4-6",
    });
    await detector.validateFinding({
      finding: makeFinding(),
      fileContent: "x",
    });

    expect(secondPrompt).toContain("did not parse as JSON");
  });
});
