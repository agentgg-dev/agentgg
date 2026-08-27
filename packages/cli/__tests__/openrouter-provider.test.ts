import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readUsage } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildProviderRouting,
  createCostMeter,
  createRoutingFetch,
  openrouterModule,
} from "../src/providers/openrouter.js";
import { UsageMeter } from "../src/usage-meter.js";

const ENV_KEYS = [
  "OPENROUTER_QUANTIZATIONS",
  "OPENROUTER_SORT",
  "OPENROUTER_PROVIDER_ORDER",
  "OPENROUTER_ALLOW_FALLBACKS",
  "OPENROUTER_MAX_PRICE_PROMPT",
  "OPENROUTER_MAX_PRICE_COMPLETION",
  "OPENROUTER_ZDR",
  "OPENROUTER_IGNORE",
];
afterEach(() => {
  for (const k of ENV_KEYS) delete process.env[k];
});

describe("buildProviderRouting", () => {
  it("defaults to fp8 + require_parameters + throughput sort", () => {
    const r = buildProviderRouting();
    expect(r.quantizations).toEqual(["fp8"]);
    expect(r.require_parameters).toBe(true);
    expect(r.sort).toBe("throughput");
    expect(r.order).toBeUndefined();
  });

  it("uses an explicit provider order when set, dropping sort", () => {
    process.env.OPENROUTER_PROVIDER_ORDER = "baseten,gmicloud";
    const r = buildProviderRouting();
    expect(r.order).toEqual(["baseten", "gmicloud"]);
    expect(r.allow_fallbacks).toBe(true);
    expect(r.sort).toBeUndefined();
  });

  it("adds a max_price ceiling from env", () => {
    process.env.OPENROUTER_MAX_PRICE_PROMPT = "1.5";
    process.env.OPENROUTER_MAX_PRICE_COMPLETION = "4.5";
    expect(buildProviderRouting().max_price).toEqual({ prompt: 1.5, completion: 4.5 });
  });

  it("omits `ignore` entirely when OPENROUTER_IGNORE is unset", () => {
    expect(buildProviderRouting().ignore).toBeUndefined();
  });

  it("excludes providers listed in OPENROUTER_IGNORE", () => {
    process.env.OPENROUTER_IGNORE = "novita, baseten/fast";
    // Whitespace trimmed by the shared csv() helper; a bare slug and a
    // variant-suffixed slug are both valid and mean different things to
    // OpenRouter (base matches every endpoint, suffixed matches one).
    expect(buildProviderRouting().ignore).toEqual(["novita", "baseten/fast"]);
  });

  it("applies `ignore` alongside an explicit provider order", () => {
    // The two are not alternatives: an order is a preference list, and a
    // broken endpoint still has to be excluded from the fallback tail.
    process.env.OPENROUTER_IGNORE = "novita";
    process.env.OPENROUTER_PROVIDER_ORDER = "streamlake/fp8,baidu/fp8";
    const r = buildProviderRouting();
    expect(r.ignore).toEqual(["novita"]);
    expect(r.order).toEqual(["streamlake/fp8", "baidu/fp8"]);
  });

  it("lets the JSON override replace an env-derived ignore list", () => {
    process.env.OPENROUTER_IGNORE = "novita";
    expect(buildProviderRouting('{"ignore":["sail-research"]}').ignore).toEqual(["sail-research"]);
  });
});

describe("buildProviderRouting with --openrouter-routing override", () => {
  it("merges the JSON override over env defaults, keeping fp8 + require_parameters", () => {
    const r = buildProviderRouting('{"order":["baseten"],"allow_fallbacks":false}');
    expect(r.order).toEqual(["baseten"]);
    expect(r.allow_fallbacks).toBe(false);
    expect(r.quantizations).toEqual(["fp8"]); // default preserved
    expect(r.require_parameters).toBe(true); // default preserved
    expect(r.sort).toBeUndefined(); // pinned providers -> env-default sort dropped
  });

  it("lets the override replace a default value (quantizations)", () => {
    expect(buildProviderRouting('{"quantizations":["bf16"]}').quantizations).toEqual(["bf16"]);
  });

  it("ignores an empty / whitespace override (env defaults stand)", () => {
    const r = buildProviderRouting("   ");
    expect(r.sort).toBe("throughput");
    expect(r.order).toBeUndefined();
  });

  it("throws a clear error on malformed JSON, before any LLM call", () => {
    expect(() => buildProviderRouting("{not json")).toThrow(/not valid JSON/);
  });

  it("treats a non-{ value as a file path (a bare JSON array reads as a filename)", () => {
    expect(() => buildProviderRouting('["baseten"]')).toThrow(/nor a readable file/);
  });

  it("rejects a file whose JSON is valid but not an object", () => {
    const dir = mkdtempSync(join(tmpdir(), "or-routing-"));
    try {
      const file = join(dir, "arr.json");
      writeFileSync(file, '["baseten"]');
      expect(() => buildProviderRouting(file)).toThrow(/must be a JSON object/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("reads routing JSON from a file path (UTF-8 BOM tolerated)", () => {
    const dir = mkdtempSync(join(tmpdir(), "or-routing-"));
    try {
      const file = join(dir, "routing.json");
      writeFileSync(file, '﻿{"order":["baseten"],"allow_fallbacks":false}');
      const r = buildProviderRouting(file);
      expect(r.order).toEqual(["baseten"]);
      expect(r.allow_fallbacks).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("throws a clear error when the file path cannot be read", () => {
    expect(() => buildProviderRouting("/no/such/routing.json")).toThrow(/nor a readable file/);
  });
});

describe("createRoutingFetch", () => {
  it("injects the provider block into chat-completions bodies", async () => {
    const inner = vi.fn(async () => new Response("{}"));
    const f = createRoutingFetch({ quantizations: ["fp8"] }, inner as unknown as typeof fetch);
    await f("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "z-ai/glm-5.2", messages: [] }),
    });
    const sentBody = JSON.parse((inner.mock.calls[0][1] as RequestInit).body as string);
    expect(sentBody.provider).toEqual({ quantizations: ["fp8"] });
  });

  it("does not touch non chat-completions URLs", async () => {
    const inner = vi.fn(async () => new Response("[]"));
    const f = createRoutingFetch({ quantizations: ["fp8"] }, inner as unknown as typeof fetch);
    await f("https://openrouter.ai/api/v1/models", { method: "GET" });
    expect((inner.mock.calls[0][1] as RequestInit).body).toBeUndefined();
  });
});

/**
 * Cost capture. OpenRouter returns what it charged in `usage.cost` when the
 * request asks for usage accounting. The AI SDK's OpenAI-compatible client
 * drops that field, so the fetch wrapper reads it off the response instead.
 */
describe("createRoutingFetch cost capture", () => {
  const completion = (cost: unknown) =>
    new Response(
      JSON.stringify({
        choices: [{ message: { content: "hi" } }],
        usage: { prompt_tokens: 14, completion_tokens: 112, cost },
      }),
      { headers: { "content-type": "application/json" } },
    );

  it("asks OpenRouter for usage accounting on chat-completions bodies", async () => {
    const inner = vi.fn(async () => completion(0.001));
    const f = createRoutingFetch({}, inner as unknown as typeof fetch, createCostMeter());
    await f("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "z-ai/glm-5.2", messages: [] }),
    });
    const sentBody = JSON.parse((inner.mock.calls[0][1] as RequestInit).body as string);
    expect(sentBody.usage).toEqual({ include: true });
  });

  it("accumulates the cost OpenRouter reports across calls", async () => {
    const meter = createCostMeter();
    const inner = vi.fn(async () => completion(0.0005124));
    const f = createRoutingFetch({}, inner as unknown as typeof fetch, meter);
    const post = () =>
      f("https://openrouter.ai/api/v1/chat/completions", {
        method: "POST",
        body: JSON.stringify({ model: "z-ai/glm-5.2", messages: [] }),
      });
    await post();
    await post();
    expect(meter.totalUsd()).toBeCloseTo(0.0010248, 10);
  });

  // Reading the body must not consume it — the SDK parses the same response.
  it("leaves the response body readable by the caller", async () => {
    const inner = vi.fn(async () => completion(0.001));
    const f = createRoutingFetch({}, inner as unknown as typeof fetch, createCostMeter());
    const res = await f("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "z-ai/glm-5.2", messages: [] }),
    });
    expect(((await res.json()) as { usage: { cost: number } }).usage.cost).toBe(0.001);
  });

  it("stays at zero when the response carries no usable cost", async () => {
    const meter = createCostMeter();
    const bodies = [completion(undefined), completion("free"), new Response("not json")];
    const inner = vi.fn(async () => bodies.shift() as Response);
    const f = createRoutingFetch({}, inner as unknown as typeof fetch, meter);
    for (let i = 0; i < 3; i++) {
      await f("https://openrouter.ai/api/v1/chat/completions", {
        method: "POST",
        body: JSON.stringify({ model: "z-ai/glm-5.2", messages: [] }),
      });
    }
    expect(meter.totalUsd()).toBe(0);
  });
});

/**
 * End of the wiring: the provider owns the counter, so the detector it builds
 * has to carry it to the usage meter. A meter with a source attached writes a
 * `costUsd` even before any call is made; one without omits the field. That
 * difference is what this asserts, with no network involved.
 */
describe("openrouterModule.buildDetector", () => {
  let outDir: string;

  beforeEach(() => {
    outDir = mkdtempSync(join(tmpdir(), "agentgg-or-build-"));
  });
  afterEach(() => {
    rmSync(outDir, { recursive: true, force: true });
  });

  it("hands the detector a cost source that reaches the usage meter", () => {
    const detector = openrouterModule.buildDetector(
      { openrouter: { apiKey: "sk-or-test" } } as never,
      {} as never,
    );
    const meter = new UsageMeter(outDir, "openrouter");
    detector.attachUsageMeter?.(meter);
    meter.record({ inputTokens: 10, outputTokens: 4, cachedInputTokens: 0 });
    meter.flush();

    expect(readUsage(outDir)?.costUsd).toBe(0);
  });
});

/**
 * A streamed completion must not be read here. Cloning and parsing an SSE body
 * drains it to completion before the caller sees the response, which would turn
 * a stream into a blocking call. The engine only uses generateText /
 * generateObject today, so this guards a future streaming path.
 */
describe("createRoutingFetch and streamed responses", () => {
  it("never reads the body of an event-stream response", async () => {
    const meter = createCostMeter();
    const res = new Response("data: {}\n\n", {
      headers: { "content-type": "text/event-stream" },
    });
    const clone = vi.spyOn(res, "clone");
    const inner = vi.fn(async () => res);
    const f = createRoutingFetch({}, inner as unknown as typeof fetch, meter);
    await f("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "z-ai/glm-5.2", messages: [], stream: true }),
    });

    expect(clone).not.toHaveBeenCalled();
    expect(res.bodyUsed).toBe(false);
    expect(meter.totalUsd()).toBe(0);
  });
});
