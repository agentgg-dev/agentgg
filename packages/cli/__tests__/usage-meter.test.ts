/**
 * Tests for LLM token-usage metering.
 *
 *   - `extractCallUsage` normalizes the Vercel AI SDK result shape into flat
 *     token counts; `extractClaudeUsage` does the same for the Claude Agent
 *     SDK's usage block. Both degrade to 0 on anything missing.
 *   - `UsageMeter` accumulates across calls, seeds from a prior ledger, and
 *     checkpoints to `state/usage.json` on flush.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readUsage } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { extractClaudeUsage } from "../src/detectors/claude-agent.js";
import { extractCallUsage } from "../src/detectors/vercel-agent.js";
import { UsageMeter } from "../src/usage-meter.js";

describe("extractCallUsage", () => {
  it("reads the documented usage shape", () => {
    expect(extractCallUsage({ usage: { promptTokens: 100, completionTokens: 40 } })).toEqual({
      inputTokens: 100,
      outputTokens: 40,
      cachedInputTokens: 0,
    });
  });

  it("pulls cached tokens from providerMetadata.openai (OpenAI-compat / Vertex MaaS)", () => {
    const usage = extractCallUsage({
      usage: { promptTokens: 100, completionTokens: 40 },
      providerMetadata: { openai: { cachedPromptTokens: 64 } },
    });
    expect(usage.cachedInputTokens).toBe(64);
  });

  it("falls back to experimental_providerMetadata", () => {
    const usage = extractCallUsage({
      usage: { promptTokens: 10, completionTokens: 2 },
      experimental_providerMetadata: { openai: { cachedPromptTokens: 8 } },
    });
    expect(usage.cachedInputTokens).toBe(8);
  });

  it("degrades to zeros on missing / malformed input", () => {
    const zero = { inputTokens: 0, outputTokens: 0, cachedInputTokens: 0 };
    expect(extractCallUsage(undefined)).toEqual(zero);
    expect(extractCallUsage(null)).toEqual(zero);
    expect(extractCallUsage({})).toEqual(zero);
    expect(extractCallUsage({ usage: { promptTokens: "lots" } })).toEqual(zero);
    expect(extractCallUsage({ usage: { promptTokens: -5 } })).toEqual(zero);
  });
});

describe("extractClaudeUsage", () => {
  it("folds cache tokens into inputTokens and surfaces cache reads", () => {
    expect(
      extractClaudeUsage({
        input_tokens: 100,
        output_tokens: 40,
        cache_read_input_tokens: 30,
        cache_creation_input_tokens: 20,
      }),
    ).toEqual({ inputTokens: 150, outputTokens: 40, cachedInputTokens: 30 });
  });

  it("degrades to zeros on missing / malformed input", () => {
    const zero = { inputTokens: 0, outputTokens: 0, cachedInputTokens: 0 };
    expect(extractClaudeUsage(undefined)).toEqual(zero);
    expect(extractClaudeUsage({})).toEqual(zero);
    expect(extractClaudeUsage({ input_tokens: "lots" })).toEqual(zero);
  });
});

describe("UsageMeter", () => {
  let outDir: string;

  beforeEach(() => {
    outDir = mkdtempSync(join(tmpdir(), "agentgg-usage-"));
  });
  afterEach(() => {
    rmSync(outDir, { recursive: true, force: true });
  });

  const call = (input: number, output: number, cached = 0) => ({
    inputTokens: input,
    outputTokens: output,
    cachedInputTokens: cached,
  });

  it("accumulates across calls and counts them", () => {
    const meter = new UsageMeter(outDir, "vertex");
    meter.record(call(100, 40, 10), "zai-org/glm-5-maas");
    meter.record(call(50, 20, 5));
    expect(meter.totalsSnapshot()).toEqual({
      inputTokens: 150,
      outputTokens: 60,
      cachedInputTokens: 15,
      calls: 2,
    });
  });

  it("flushes a ScanUsage ledger to state/usage.json", () => {
    const meter = new UsageMeter(outDir, "vertex");
    meter.record(call(100, 40), "zai-org/glm-5-maas");
    meter.flush();

    const ledger = readUsage(outDir);
    expect(ledger).not.toBeNull();
    expect(ledger?.provider).toBe("vertex");
    expect(ledger?.model).toBe("zai-org/glm-5-maas");
    expect(ledger?.totals.inputTokens).toBe(100);
    expect(ledger?.totals.calls).toBe(1);
    expect(typeof ledger?.updatedAt).toBe("string");
  });

  it("seeds from a prior ledger so a retried invocation continues the total", () => {
    const first = new UsageMeter(outDir, "vertex");
    first.record(call(100, 40), "zai-org/glm-5-maas");
    first.flush();

    // A fresh meter in the same dir, seeded from the persisted ledger.
    const resumed = new UsageMeter(outDir, "vertex", readUsage(outDir));
    resumed.record(call(10, 5));
    expect(resumed.totalsSnapshot()).toMatchObject({
      inputTokens: 110,
      outputTokens: 45,
      calls: 2,
    });
  });

  it("flush is a no-op when nothing was recorded", () => {
    new UsageMeter(outDir, "vertex").flush();
    expect(readUsage(outDir)).toBeNull();
  });
});
