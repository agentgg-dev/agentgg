import type { Finding } from "@agentgg/core";
import { openai } from "@ai-sdk/openai";
import { MockLanguageModelV1 } from "ai/test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { REPRODUCE_CUT_SHORT } from "../src/detect.js";
import { ClaudeAgentDetector } from "../src/detectors/claude-agent.js";
import { asReproduceField, VercelAgentDetector } from "../src/detectors/vercel-agent.js";
import { ollamaModule } from "../src/providers/ollama.js";

// reproduceFinding always attaches tools from the sandbox's Playwright MCP
// server. Keep every other export real; only the network-facing client is
// swapped, since each test's scripted answer ends the loop on its own.
vi.mock("ai", async (importOriginal) => {
  const actual = await importOriginal<typeof import("ai")>();
  return {
    ...actual,
    experimental_createMCPClient: vi.fn(async () => ({
      tools: async () => ({}),
      close: async () => {},
    })),
  };
});

function makeFinding(): Finding {
  return {
    id: "abc123abc123",
    agentSlug: "open-redirect",
    title: "Unvalidated redirect target",
    vulnSlug: "open-redirect",
    filePath: "src/routes/login.ts",
    lineRange: [20, 24],
    summary: "The redirect handler forwards the raw `next` query param.",
    details: "Line 22 calls res.redirect(req.query.next) with no allowlist check.",
    poc: "Visit /login?next=https://evil.example",
    impact: "Phishing via a trusted-looking redirect.",
    references: ["CWE-601"],
    confidence: 0.9,
    notifications: [],
  };
}

/** Replies with `texts` in order, clamped to the last once exhausted — the
 *  same shape as the tool-loop mocks in vercel-agent-empty-completion.test.ts. */
function scriptedModel(texts: string[]): MockLanguageModelV1 {
  let n = 0;
  return new MockLanguageModelV1({
    defaultObjectGenerationMode: "json",
    doGenerate: async () => ({
      rawCall: { rawPrompt: null, rawSettings: {} },
      finishReason: "stop" as const,
      usage: { promptTokens: 10, completionTokens: 5 },
      text: texts[Math.min(n++, texts.length - 1)],
    }),
  });
}

const reproduceArgs = () => ({
  finding: makeFinding(),
  baseUrl: "http://localhost:3000",
  browserEndpoint: "http://sandbox.local:1234/sse",
});

describe("reproduceFinding", () => {
  it("is present on the claude-agent detector", () => {
    const d = new ClaudeAgentDetector({ apiKey: "test", model: "claude-opus-4-8" });
    expect(typeof d.reproduceFinding).toBe("function");
  });

  it("is present on the vercel detector, so non-anthropic providers can live-validate", () => {
    const d = new VercelAgentDetector("openrouter", openai("gpt-4o-mini"));
    expect(typeof d.reproduceFinding).toBe("function");
  });
});

/**
 * Ollama composes two inner detectors, so the composite has to forward both
 * reproduce methods, and the proof script needs the structuredOutputs model.
 */
describe("ollama live validation", () => {
  const buildOllama = () =>
    ollamaModule.buildDetector(
      { ollama: { baseUrl: "http://ollama.test:11434" } } as never,
      {} as never,
    );

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("forwards both reproduce methods", () => {
    const d = buildOllama();
    expect(typeof d.reproduceFinding).toBe("function");
    expect(typeof d.generateReproScript).toBe("function");
  });

  it("sends the proof-script schema, not a bare json format", async () => {
    const inner = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            created_at: "2026-01-01T00:00:00Z",
            done: true,
            done_reason: "stop",
            eval_count: 1,
            eval_duration: 1,
            message: { content: '{"script":"await page.goto(base)"}', role: "assistant" },
            model: "qwen2.5",
            prompt_eval_count: 1,
            total_duration: 1,
          }),
          { headers: { "content-type": "application/json" } },
        ),
    );
    vi.stubGlobal("fetch", inner);

    const script = await buildOllama().generateReproScript?.({
      baseUrl: "http://localhost:3000",
      finding: makeFinding(),
    });

    expect(script).toBe("await page.goto(base)");
    const sent = JSON.parse((inner.mock.calls[0][1] as RequestInit).body as string);
    expect(sent.format).not.toBe("json");
    expect(sent.format.properties.script).toBeDefined();
  });
});

describe("asReproduceField", () => {
  it("keeps the script on a reproduction", () => {
    expect(
      asReproduceField({ result: "reproduced", reasoning: "r", counterevidence: "c", script: "s" }),
    ).toEqual({
      result: "reproduced",
      reasoning: "r",
      counterevidence: "c",
      script: "s",
    });
  });

  it("drops the script when the finding was refuted", () => {
    expect(
      asReproduceField({ result: "refuted", reasoning: "r", counterevidence: "c", script: "s" }),
    ).toEqual({
      result: "refuted",
      reasoning: "r",
      counterevidence: "c",
    });
  });

  it("omits the script key entirely when the model returned none", () => {
    expect(
      asReproduceField({ result: "reproduced", reasoning: "r", counterevidence: "c" }),
    ).toEqual({
      result: "reproduced",
      reasoning: "r",
      counterevidence: "c",
    });
  });
});

// parseReproduce is private, reached only through reproduceFinding. Each case
// drives the public method with a scripted model (and a stubbed MCP client —
// see the `vi.mock("ai", ...)` above) so the loop ends on the first turn with
// the text under test, exactly as the tool-enabled validateFinding tests in
// vercel-agent-empty-completion.test.ts drive parseValidation.
describe("VercelAgentDetector.reproduceFinding — parseReproduce branches", () => {
  beforeEach(() => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("records inconclusive with cut-short reasoning when the loop and its retry both answer nothing", async () => {
    const detector = new VercelAgentDetector("openrouter", scriptedModel(["", ""]));
    const result = await detector.reproduceFinding(reproduceArgs());
    expect(result.result).toBe("inconclusive");
    expect(result.reasoning).toBe(REPRODUCE_CUT_SHORT);
    expect(result.refused).toBeUndefined();
  });

  it("logs that the reproduce loop was cut short, not a silent uncertain", async () => {
    const detector = new VercelAgentDetector("openrouter", scriptedModel(["", ""]));
    await detector.reproduceFinding(reproduceArgs());
    expect(vi.mocked(console.warn).mock.calls.map((c) => String(c[0]))).toContainEqual(
      expect.stringContaining("stopped before it reported a verdict"),
    );
  });

  it("parses a well-formed reproduced result and keeps its script", async () => {
    const payload = JSON.stringify({
      result: "reproduced",
      reasoning: "Followed the link and landed on the external site unprompted.",
      counterevidence: "The redirect could also be the browser's own referrer-driven navigation.",
      script:
        "test('repro', async ({ page }) => { await page.goto('/login?next=https://evil'); });",
    });
    const detector = new VercelAgentDetector("openrouter", scriptedModel([payload]));
    const result = await detector.reproduceFinding(reproduceArgs());
    expect(result).toEqual({
      result: "reproduced",
      reasoning: "Followed the link and landed on the external site unprompted.",
      counterevidence: "The redirect could also be the browser's own referrer-driven navigation.",
      script:
        "test('repro', async ({ page }) => { await page.goto('/login?next=https://evil'); });",
    });
  });

  it("records inconclusive and refused on a content refusal, distinct from cut-short", async () => {
    const detector = new VercelAgentDetector(
      "openrouter",
      scriptedModel(["I can't help reproduce this exploit."]),
    );
    const result = await detector.reproduceFinding(reproduceArgs());
    expect(result.result).toBe("inconclusive");
    expect(result.refused).toBe(true);
    expect(result.reasoning).not.toBe(REPRODUCE_CUT_SHORT);
  });

  it("recovers a result via the structuredModel reformat when the loop's answer is unparseable", async () => {
    const reformatted = JSON.stringify({
      result: "refuted",
      reasoning: "The redirect target is checked against an allowlist.",
      counterevidence: "The allowlist check could be bypassed with a different encoding.",
    });
    const detector = new VercelAgentDetector(
      "openrouter",
      scriptedModel(["Garbled output with no JSON in it at all.", reformatted]),
    );
    const result = await detector.reproduceFinding(reproduceArgs());
    expect(result.result).toBe("refuted");
    expect(result.reasoning).toContain("allowlist");
  });
});

describe("VercelAgentDetector.reproduceFinding MCP logging", () => {
  afterEach(() => vi.restoreAllMocks());

  it("reports how many browser tools attached, the way the claude path reports status", async () => {
    const { experimental_createMCPClient } = await import("ai");
    vi.mocked(experimental_createMCPClient).mockResolvedValueOnce({
      tools: async () => {
        const stub = { parameters: z.object({}), execute: async () => ({}) };
        return { browser_navigate: stub, browser_click: stub, browser_evaluate: stub };
      },
      close: async () => {},
    } as never);
    const log = vi.spyOn(console, "log").mockImplementation(() => {});

    const detector = new VercelAgentDetector(
      "openrouter",
      scriptedModel([
        '{"result":"inconclusive","reasoning":"did not trigger","counterevidence":""}',
      ]),
    );
    await detector.reproduceFinding({
      finding: makeFinding(),
      baseUrl: "http://host.docker.internal:3000",
      browserEndpoint: "http://localhost:8931/sse",
    });

    expect(log.mock.calls.flat().join("\n")).toContain("MCP playwright: 3 tool(s)");
  });
});
