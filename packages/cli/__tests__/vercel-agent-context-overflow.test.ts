/**
 * Context-overflow recovery in `VercelAgentDetector.runAgent`.
 *
 * Why this exists: the agent tool-loop transcript grows with both the bytes the
 * tools return AND the number of turns those bytes get re-sent across, so a
 * long agent run on a big repo can blow the model's context window mid-batch. That
 * throws out of `generateText`, which fails the batch, which sets `rt.failed`,
 * which suppresses the agent's resume sidecar — and the platform then marks the
 * whole agent failed. Prod scan 764dbd1d lost `missing-access-control` this way
 * on 2026-08-18 (1,241,542 tokens requested against a 1,048,576 limit).
 *
 * Re-sending the same request can't work, which is why `withTpmRetry` refuses
 * to retry it. A SMALLER loop can, so `runAgent` retries once at half the read
 * budget and half the turn cap. Once only, and only for this error class.
 *
 * `generateText` is mocked: these assert the retry routing, not the model.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const generateTextMock = vi.hoisted(() => vi.fn());
vi.mock("ai", async (importOriginal) => ({
  ...(await importOriginal<typeof import("ai")>()),
  generateText: generateTextMock,
}));

const { VercelAgentDetector } = await import("../src/detectors/vercel-agent.js");

/** A `generateText` result the detector can parse into zero findings. */
function emptyResult() {
  return { text: '{"findings": []}', steps: [], usage: {} };
}

/** The overflow the provider actually returned on scan 764dbd1d. */
function contextOverflow() {
  return new Error(
    "This endpoint's maximum context length is 1048576 tokens. However, you " +
      "requested about 1241542 tokens (1241194 of text input, 348 of tool input).",
  );
}

function makeDetector() {
  return new VercelAgentDetector("test", { modelId: "test-model" } as never);
}

function runAgentArgs(maxTurns = 50) {
  return {
    agent: { slug: "missing-access-control", prompt: "Find missing access control." },
    candidates: [{ filePath: "src/api.py", content: "def get(id): ...", hits: [] }],
    rootDir: process.cwd(),
    excludePatterns: [],
    maxFileSizeKb: 512,
    maxTurns,
  } as never;
}

describe("runAgent context-overflow retry", () => {
  beforeEach(() => {
    generateTextMock.mockReset();
    vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  it("retries once at half the turn cap after a context overflow", async () => {
    generateTextMock.mockRejectedValueOnce(contextOverflow()).mockResolvedValueOnce(emptyResult());

    const findings = await makeDetector().runAgent(runAgentArgs(50));

    expect(findings).toEqual([]);
    expect(generateTextMock).toHaveBeenCalledTimes(2);
    // maxSteps is maxTurns + 1: 51 on the first attempt, 26 on the shrunk retry.
    expect(generateTextMock.mock.calls[0]?.[0].maxSteps).toBe(51);
    expect(generateTextMock.mock.calls[1]?.[0].maxSteps).toBe(26);
  });

  it("tells the log why the batch is running twice", async () => {
    generateTextMock.mockRejectedValueOnce(contextOverflow()).mockResolvedValueOnce(emptyResult());

    await makeDetector().runAgent(runAgentArgs());

    const warned = vi.mocked(console.warn).mock.calls.map((c) => String(c[0]));
    expect(warned.some((m) => m.includes("context overflow"))).toBe(true);
    expect(warned.some((m) => m.includes("missing-access-control"))).toBe(true);
  });

  it("does NOT retry a non-overflow error — one failure stays one call", async () => {
    generateTextMock.mockRejectedValue(new Error("Invalid API key"));

    await expect(makeDetector().runAgent(runAgentArgs())).rejects.toThrow(/Invalid API key/);
    expect(generateTextMock).toHaveBeenCalledTimes(1);
  });

  it("gives up after ONE shrunk retry rather than looping", async () => {
    generateTextMock.mockRejectedValue(contextOverflow());

    await expect(makeDetector().runAgent(runAgentArgs())).rejects.toThrow(/context length/i);
    expect(generateTextMock).toHaveBeenCalledTimes(2);
  });
});
