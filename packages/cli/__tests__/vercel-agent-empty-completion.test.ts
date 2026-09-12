/**
 * Tests for the empty-completion guards on both tool-enabled paths in
 * detectors/vercel-agent.ts.
 *
 * A tool loop that spends every step on tool calls returns `text: ""`. Both
 * paths used to hand that to a structured reformat whose prompt carries ONLY
 * that text, so the model was asked to extract an answer from a blank page and
 * obliged:
 *
 *   - detection  -> `{findings: []}`, a fabricated all-clear indistinguishable
 *                   from real code review. Observed 2026-08-11 on `z-ai/glm-5.2`:
 *                   the xss agent hit its turn cap, wrote nothing, and the two
 *                   real findings from the prior run silently vanished.
 *   - validation -> `uncertain` + "No validation content or finding was
 *                   provided to analyze", which read like a real judgement.
 *
 * The two now diverge because the honest outcome differs. Detection has no
 * "unknown" to record, so an empty batch THROWS: scan.ts sets `rt.failed`,
 * suppresses the agent sidecar, and the agent re-runs. Validation does have
 * one, so it records `uncertain` with prose saying the run was cut short.
 *
 * The refusal path is asserted alongside each, because refusals also arrive as
 * unparseable text and must keep their existing (different) behavior.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Agent, Finding } from "@agentgg/core";
import { MockLanguageModelV1 } from "ai/test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VercelAgentDetector } from "../src/detectors/vercel-agent.js";
import { VALIDATION_CUT_SHORT } from "../src/validator.js";

/** A model whose final message is `text`, with no tool calls. */
function modelReturning(text: string, finishReason: "stop" | "tool-calls" = "stop") {
  return new MockLanguageModelV1({
    defaultObjectGenerationMode: "json",
    doGenerate: async () => ({
      rawCall: { rawPrompt: null, rawSettings: {} },
      finishReason,
      usage: { promptTokens: 10, completionTokens: 0 },
      text,
    }),
  });
}

function makeAgent(): Agent {
  return {
    slug: "xss",
    name: "xss",
    description: "Synthetic agent for empty-completion tests.",
    version: "0.0.1",
    noiseTier: "normal",
    where: {},
    prompt: "Stub agent body. Model is mocked.",
  } as Agent;
}

function makeFinding(): Finding {
  return {
    id: "abc123abc123",
    agentSlug: "xss",
    title: "dangerouslySetInnerHTML on untrusted comment body",
    vulnSlug: "xss",
    filePath: "comment.tsx",
    lineRange: [4, 6],
    summary: "Comment body is rendered as raw HTML.",
    details: "The component passes the raw comment through dangerouslySetInnerHTML.",
    poc: "Post a comment containing a script tag.",
    impact: "Stored XSS against every reader of the thread.",
    references: ["CWE-79"],
    confidence: 0.9,
    notifications: [],
  };
}

let rootDir: string;

beforeEach(() => {
  rootDir = mkdtempSync(join(tmpdir(), "agentgg-empty-"));
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  rmSync(rootDir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

function runAgentArgs(model: MockLanguageModelV1) {
  return {
    detector: new VercelAgentDetector("openai", model),
    args: {
      agent: makeAgent(),
      rootDir,
      candidates: [{ filePath: "comment.tsx", content: "<div/>", hits: [] }],
      excludePatterns: [],
      maxFileSizeKb: 256,
      maxTurns: 5,
    },
  };
}

describe("runAgent — empty completion", () => {
  it("throws rather than recording a fabricated 0 findings", async () => {
    const { detector, args } = runAgentArgs(modelReturning("", "tool-calls"));
    await expect(detector.runAgent(args)).rejects.toThrow(/without writing an answer/);
  });

  it("names the agent so the failing batch is identifiable in the logs", async () => {
    const { detector, args } = runAgentArgs(modelReturning("", "tool-calls"));
    await expect(detector.runAgent(args)).rejects.toThrow(/runAgent:xss/);
  });

  it("treats whitespace-only output as empty", async () => {
    const { detector, args } = runAgentArgs(modelReturning("   \n  ", "tool-calls"));
    await expect(detector.runAgent(args)).rejects.toThrow(/no analysis/);
  });

  it("still returns 0 findings on a content refusal, without throwing", async () => {
    const { detector, args } = runAgentArgs(
      modelReturning("I can't help analyze this exploit code."),
    );
    await expect(detector.runAgent(args)).resolves.toEqual([]);
  });

  it("passes a genuinely empty findings array through untouched", async () => {
    const { detector, args } = runAgentArgs(modelReturning(JSON.stringify({ findings: [] })));
    await expect(detector.runAgent(args)).resolves.toEqual([]);
  });
});

describe("validateFinding (tool-enabled) — empty completion", () => {
  function validateArgs(model: MockLanguageModelV1) {
    return {
      detector: new VercelAgentDetector("openai", model),
      args: { finding: makeFinding(), fileContent: "<div/>", root: rootDir },
    };
  }

  it("records uncertain with cut-short reasoning instead of inventing a verdict", async () => {
    const { detector, args } = validateArgs(modelReturning("", "tool-calls"));
    const result = await detector.validateFinding(args);
    expect(result.verdict).toBe("uncertain");
    expect(result.reasoning).toBe(VALIDATION_CUT_SHORT);
  });

  it("does not mark it refused — nothing was declined", async () => {
    const { detector, args } = validateArgs(modelReturning("", "tool-calls"));
    expect((await detector.validateFinding(args)).refused).toBeUndefined();
  });

  it("keeps the refusal path distinct from the cut-short path", async () => {
    const { detector, args } = validateArgs(
      modelReturning("I can't help analyze this exploit code."),
    );
    const result = await detector.validateFinding(args);
    expect(result.verdict).toBe("uncertain");
    expect(result.refused).toBe(true);
    expect(result.reasoning).not.toBe(VALIDATION_CUT_SHORT);
  });

  it("passes a real verdict through untouched", async () => {
    const { detector, args } = validateArgs(
      modelReturning(
        JSON.stringify({
          verdict: "false-positive",
          reasoning: "The body is escaped by the sanitizer above.",
          confidence: 0.8,
        }),
      ),
    );
    const result = await detector.validateFinding(args);
    expect(result.verdict).toBe("false-positive");
    expect(result.reasoning).toContain("sanitizer");
  });
});

/**
 * The forced answer, schema-constrained.
 *
 * When a tool loop ends with no text, `answerWithoutTools` re-asks with the
 * transcript and no tools. As free text that request can be answered with
 * nothing, and on 2026-09-12 it was: "asked again with no tools and still got
 * nothing". A request carrying the findings schema is much harder to answer
 * with nothing, and it is the last chance before the batch fails.
 */
describe("runAgent — forced answer carries the schema", () => {
  /** Records the `mode` of every request so the retry shape can be asserted. */
  function recordingModel(texts: string[]) {
    const modes: string[] = [];
    let n = 0;
    const model = new MockLanguageModelV1({
      defaultObjectGenerationMode: "json",
      doGenerate: async (options) => {
        modes.push((options.mode as { type: string }).type);
        return {
          rawCall: { rawPrompt: null, rawSettings: {} },
          finishReason: "stop" as const,
          usage: { promptTokens: 10, completionTokens: 0 },
          text: texts[Math.min(n++, texts.length - 1)],
        };
      },
    });
    return { model, modes };
  }

  it("re-asks in object mode after an empty loop, not as free text", async () => {
    const answer = JSON.stringify({ findings: [] });
    const { model, modes } = recordingModel(["", answer]);
    const { detector, args } = runAgentArgs(model);

    await detector.runAgent(args);

    expect(modes[0]).toBe("regular");
    expect(modes[1]).toBe("object-json");
  });

  it("returns the findings the schema-constrained retry produced", async () => {
    const answer = JSON.stringify({
      findings: [
        {
          title: "SQL injection in constructEquality",
          vulnSlug: "sql-injection",
          agentSlug: null,
          filePath: "comment.tsx",
          lineRange: [4, 6],
          summary: "Unescaped string value reaches the SQL string.",
          details: "The helper concatenates the literal without escaping it.",
          poc: "Send a filter whose literal closes the quote.",
          impact: "Arbitrary SQL runs against the backing database.",
          references: ["CWE-89"],
          confidence: 0.9,
        },
      ],
    });
    const { model } = recordingModel(["", answer]);
    const { detector, args } = runAgentArgs(model);

    const findings = await detector.runAgent(args);

    expect(findings).toHaveLength(1);
    expect(findings[0].title).toContain("constructEquality");
  });

  it("still fails the batch when even the schema request yields nothing", async () => {
    const { model } = recordingModel(["", ""]);
    const { detector, args } = runAgentArgs(model);

    await expect(detector.runAgent(args)).rejects.toThrow(/without writing an answer/);
  });
});
