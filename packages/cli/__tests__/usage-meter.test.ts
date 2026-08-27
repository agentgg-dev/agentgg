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
import { extractCallUsage, VercelAgentDetector } from "../src/detectors/vercel-agent.js";
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

  // A multi-step tool loop is the shape every scan actually runs. The SDK sums
  // `usage` across steps but exposes only the LAST step's `providerMetadata`,
  // so reading the top level under-counts cache hits by ~the step count.
  it("sums cached tokens across every step of a tool loop", () => {
    const step = (prompt: number, cached: number) => ({
      usage: { promptTokens: prompt, completionTokens: 5 },
      providerMetadata: { openai: { cachedPromptTokens: cached } },
    });
    const usage = extractCallUsage({
      // What the SDK reports: cumulative usage, final step's metadata.
      usage: { promptTokens: 300, completionTokens: 15 },
      providerMetadata: { openai: { cachedPromptTokens: 90 } },
      steps: [step(50, 0), step(100, 70), step(150, 90)],
    });
    expect(usage.inputTokens).toBe(300);
    expect(usage.outputTokens).toBe(15);
    expect(usage.cachedInputTokens).toBe(160);
  });

  it("reads experimental_providerMetadata on steps too", () => {
    const usage = extractCallUsage({
      usage: { promptTokens: 200, completionTokens: 4 },
      steps: [
        { experimental_providerMetadata: { openai: { cachedPromptTokens: 30 } } },
        { experimental_providerMetadata: { openai: { cachedPromptTokens: 45 } } },
      ],
    });
    expect(usage.cachedInputTokens).toBe(75);
  });

  // generateObject results carry no `steps` — the structured-output paths in
  // MultiProviderDetector and the reformat fallbacks depend on this.
  it("falls back to top-level metadata when there are no steps", () => {
    expect(
      extractCallUsage({
        usage: { promptTokens: 100, completionTokens: 40 },
        providerMetadata: { openai: { cachedPromptTokens: 64 } },
      }).cachedInputTokens,
    ).toBe(64);
    expect(
      extractCallUsage({
        usage: { promptTokens: 100, completionTokens: 40 },
        providerMetadata: { openai: { cachedPromptTokens: 64 } },
        steps: [],
      }).cachedInputTokens,
    ).toBe(64);
  });

  // Bedrock (@ai-sdk/amazon-bedrock) and ollama never emit a cache figure;
  // they must stay at 0 rather than picking up noise from the step walk.
  it("reports zero cache for providers that omit the metadata", () => {
    const usage = extractCallUsage({
      usage: { promptTokens: 500, completionTokens: 20 },
      steps: [
        { usage: { promptTokens: 200, completionTokens: 10 } },
        { usage: { promptTokens: 300, completionTokens: 10 }, providerMetadata: { bedrock: {} } },
      ],
    });
    expect(usage).toEqual({ inputTokens: 500, outputTokens: 20, cachedInputTokens: 0 });
  });

  // Billing subtracts cached from input; cached > input would clamp input to 0
  // and misprice the whole scan at the cache rate.
  it("never reports more cached tokens than input tokens", () => {
    const usage = extractCallUsage({
      usage: { promptTokens: 300, completionTokens: 10 },
      steps: [
        {
          usage: { promptTokens: 100, completionTokens: 5 },
          providerMetadata: { openai: { cachedPromptTokens: 100 } },
        },
        {
          usage: { promptTokens: 200, completionTokens: 5 },
          providerMetadata: { openai: { cachedPromptTokens: 200 } },
        },
      ],
    });
    expect(usage.cachedInputTokens).toBeLessThanOrEqual(usage.inputTokens);
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

/**
 * Provider cost tracking. Only OpenRouter reports a per-call charge, and it
 * arrives through the provider's fetch wrapper rather than the SDK result —
 * so the meter reads a running total from a source instead of a per-call value.
 */
describe("UsageMeter cost tracking", () => {
  let outDir: string;

  beforeEach(() => {
    outDir = mkdtempSync(join(tmpdir(), "agentgg-cost-"));
  });
  afterEach(() => {
    rmSync(outDir, { recursive: true, force: true });
  });

  const call = (input: number, output: number) => ({
    inputTokens: input,
    outputTokens: output,
    cachedInputTokens: 0,
  });

  it("writes the tracked provider cost into the ledger", () => {
    const meter = new UsageMeter(outDir, "openrouter");
    meter.trackCost(() => 0.25);
    meter.record(call(100, 40), "z-ai/glm-5.2");
    meter.flush();

    expect(readUsage(outDir)?.costUsd).toBe(0.25);
  });

  it("omits costUsd for providers that report no cost", () => {
    const meter = new UsageMeter(outDir, "vertex");
    meter.record(call(100, 40));
    meter.flush();

    expect(readUsage(outDir)?.costUsd).toBeUndefined();
  });

  // The accumulator lives in the fetch wrapper, in process memory, so it
  // restarts at 0. Without the seed a retry would overwrite the earlier spend
  // while the token totals stayed cumulative — a fake margin in the report.
  it("adds this run's cost to the seeded ledger so a resumed run keeps earlier spend", () => {
    const first = new UsageMeter(outDir, "openrouter");
    first.trackCost(() => 0.4);
    first.record(call(100, 40), "z-ai/glm-5.2");
    first.flush();
    expect(readUsage(outDir)?.costUsd).toBe(0.4);

    const resumed = new UsageMeter(outDir, "openrouter", readUsage(outDir));
    resumed.trackCost(() => 0.25);
    resumed.record(call(10, 5));
    resumed.flush();

    expect(readUsage(outDir)?.costUsd).toBeCloseTo(0.65, 10);
  });
});

/**
 * The detector is the seam between the provider's cost counter and the meter:
 * the provider builds the counter inside its fetch wrapper, and the commands
 * hand the meter to the detector. Without this forwarding the counter would
 * tick with nothing reading it.
 */
describe("VercelAgentDetector cost wiring", () => {
  let outDir: string;

  beforeEach(() => {
    outDir = mkdtempSync(join(tmpdir(), "agentgg-wiring-"));
  });
  afterEach(() => {
    rmSync(outDir, { recursive: true, force: true });
  });

  const stubModel = { modelId: "z-ai/glm-5.2" } as never;

  it("forwards its cost source to the meter it is given", () => {
    const detector = new VercelAgentDetector("openrouter", stubModel, {
      costSource: () => 0.5,
    });
    const meter = new UsageMeter(outDir, "openrouter");
    detector.attachUsageMeter(meter);
    meter.record({ inputTokens: 10, outputTokens: 4, cachedInputTokens: 0 });
    meter.flush();

    expect(readUsage(outDir)?.costUsd).toBe(0.5);
  });

  it("leaves the ledger cost-free for a provider with no cost source", () => {
    const detector = new VercelAgentDetector("vertex", stubModel);
    const meter = new UsageMeter(outDir, "vertex");
    detector.attachUsageMeter(meter);
    meter.record({ inputTokens: 10, outputTokens: 4, cachedInputTokens: 0 });
    meter.flush();

    expect(readUsage(outDir)?.costUsd).toBeUndefined();
  });
});
