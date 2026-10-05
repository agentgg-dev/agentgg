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
  parseSavedRouting,
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
  "OPENROUTER_MAX_TOKENS",
  "OPENROUTER_REASONING_MAX_TOKENS",
  "OPENROUTER_REASONING_EFFORT",
];
afterEach(() => {
  for (const k of ENV_KEYS) delete process.env[k];
});

describe("buildProviderRouting", () => {
  it("defaults to require_parameters + price sort, with no quantization filter", () => {
    const r = buildProviderRouting();
    expect(r.quantizations).toBeUndefined();
    expect(r.require_parameters).toBe(true);
    expect(r.sort).toBe("price");
    expect(r.order).toBeUndefined();
  });

  it("pins quantizations only when OPENROUTER_QUANTIZATIONS is set", () => {
    process.env.OPENROUTER_QUANTIZATIONS = "fp8, bf16";
    expect(buildProviderRouting().quantizations).toEqual(["fp8", "bf16"]);
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
  it("merges the JSON override over env defaults, keeping require_parameters", () => {
    const r = buildProviderRouting('{"order":["baseten"],"allow_fallbacks":false}');
    expect(r.order).toEqual(["baseten"]);
    expect(r.allow_fallbacks).toBe(false);
    expect(r.require_parameters).toBe(true); // default preserved
    expect(r.sort).toBeUndefined(); // pinned providers -> env-default sort dropped
  });

  it("lets the override replace a default value (quantizations)", () => {
    expect(buildProviderRouting('{"quantizations":["bf16"]}').quantizations).toEqual(["bf16"]);
  });

  it("ignores an empty / whitespace override (env defaults stand)", () => {
    const r = buildProviderRouting("   ");
    expect(r.sort).toBe("price");
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
 * Writing the proof script is mechanical work with no tools to check anything
 * with, which is where a model with a deep default effort talks itself in
 * circles until the budget is gone. The phase asks for less than the default.
 */
describe("per-phase reasoning effort", () => {
  const sendProofScript = async () => {
    const inner = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            id: "gen-test",
            object: "chat.completion",
            created: 0,
            model: "z-ai/glm-5.2",
            choices: [
              {
                index: 0,
                message: { role: "assistant", content: '{"script":"x"}' },
                finish_reason: "stop",
              },
            ],
            usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
          }),
          { headers: { "content-type": "application/json" } },
        ),
    );
    vi.stubGlobal("fetch", inner);
    const detector = openrouterModule.buildDetector(
      { openrouter: { apiKey: "sk-or-test" } } as never,
      {} as never,
    );
    await detector.generateReproScript?.({
      finding: { id: "f1", title: "t", summary: "s", poc: "p", impact: "i" } as never,
      baseUrl: "https://example.test",
    });
    return JSON.parse((inner.mock.calls[0][1] as RequestInit).body as string);
  };

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("asks for a low effort when generating a proof script", async () => {
    const sent = await sendProofScript();
    expect(sent.reasoning_effort).toBe("low");
  });

  it("does not add a second effort next to the per-phase one", async () => {
    expect((await sendProofScript()).reasoning).toBeUndefined();
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

/**
 * Output caps. Without one, a generation can end at `finishReason=length` with
 * six figures of completion tokens, no text and no tool call: the model spends
 * the whole generation on reasoning the caller never sees. Nothing caps it,
 * because `providerOptionsArg()` returns undefined for OpenRouter and no
 * `maxTokens` is set anywhere.
 *
 * Both halves are needed. The reasoning cap bounds the thinking; the total cap
 * bounds the runaway. The total must stay the larger of the two, or a session
 * that spends its whole reasoning budget has nothing left to answer with, which
 * is the failure this is meant to stop.
 */
describe("createRoutingFetch output caps", () => {
  const send = async (body: Record<string, unknown>) => {
    const inner = vi.fn(async () => new Response("{}"));
    const f = createRoutingFetch({}, inner as unknown as typeof fetch);
    await f("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "z-ai/glm-5.2", messages: [], ...body }),
    });
    return JSON.parse((inner.mock.calls[0][1] as RequestInit).body as string);
  };

  it("caps total output so a runaway generation cannot run to six figures", async () => {
    expect((await send({})).max_tokens).toBe(64_000);
  });

  // Set the cap too low and the model spends its whole output budget on
  // reasoning and writes nothing, which fails the batch. The cap has to leave
  // room for an answer AFTER a long think, not squeeze the think.
  it("leaves room for an answer after a long reasoning spend", async () => {
    expect((await send({})).max_tokens).toBeGreaterThan(2 * 32_000 - 1);
  });

  // A model whose default effort is its deepest allots nearly all of
  // max_tokens to thinking and is then cut mid-answer.
  it("bounds reasoning with an effort by default", async () => {
    expect((await send({})).reasoning).toEqual({ effort: "high" });
  });

  // A token budget and an effort are alternatives, and OpenRouter rejects a
  // request carrying both.
  it("sends no reasoning token budget alongside the effort", async () => {
    expect((await send({})).reasoning).not.toHaveProperty("max_tokens");
  });

  it("takes the effort from the environment", async () => {
    process.env.OPENROUTER_REASONING_EFFORT = "low";
    expect((await send({})).reasoning).toEqual({ effort: "low" });
  });

  it("ignores an effort that is not a level OpenRouter accepts", async () => {
    process.env.OPENROUTER_REASONING_EFFORT = "nope";
    expect((await send({})).reasoning).toEqual({ effort: "high" });
  });

  it("leaves a caller's own caps alone", async () => {
    const sent = await send({ max_tokens: 100, reasoning: { effort: "low" } });
    expect(sent.max_tokens).toBe(100);
    expect(sent.reasoning).toEqual({ effort: "low" });
  });

  // What the AI SDK emits for a per-call effort. Adding `reasoning` next to it
  // would send two efforts for one call.
  it("leaves a caller's shorthand effort alone", async () => {
    const sent = await send({ reasoning_effort: "low" });
    expect(sent.reasoning).toBeUndefined();
    expect(sent.reasoning_effort).toBe("low");
  });

  it("takes the total cap from the environment", async () => {
    process.env.OPENROUTER_MAX_TOKENS = "4000";
    expect((await send({})).max_tokens).toBe(4_000);
  });

  it("sends a reasoning cap only when the environment asks for one", async () => {
    process.env.OPENROUTER_REASONING_MAX_TOKENS = "1000";
    expect((await send({})).reasoning).toEqual({ max_tokens: 1_000 });
  });

  it("ignores a cap that is not a positive number", async () => {
    process.env.OPENROUTER_MAX_TOKENS = "nope";
    expect((await send({})).max_tokens).toBe(64_000);
  });
});

describe("buildProviderRouting with saved routing", () => {
  it("applies the saved routing over the built-in defaults", () => {
    const r = buildProviderRouting(undefined, { quantizations: ["fp8"], sort: "latency" });
    expect(r.quantizations).toEqual(["fp8"]);
    expect(r.sort).toBe("latency");
    expect(r.require_parameters).toBe(true);
  });

  it("env vars override the saved routing, key by key", () => {
    process.env.OPENROUTER_QUANTIZATIONS = "bf16";
    const r = buildProviderRouting(undefined, { quantizations: ["fp8"], zdr: true });
    expect(r.quantizations).toEqual(["bf16"]);
    expect(r.zdr).toBe(true);
  });

  it("the scan flag overrides both", () => {
    process.env.OPENROUTER_QUANTIZATIONS = "bf16";
    const r = buildProviderRouting('{"quantizations":["fp16"]}', { quantizations: ["fp8"] });
    expect(r.quantizations).toEqual(["fp16"]);
  });

  it("a saved provider pin drops the default sort", () => {
    const r = buildProviderRouting(undefined, { only: ["deepinfra"] });
    expect(r.only).toEqual(["deepinfra"]);
    expect(r.sort).toBeUndefined();
  });
});

describe("parseSavedRouting", () => {
  it("parses inline JSON and treats none as clear", () => {
    expect(parseSavedRouting('{"quantizations":["fp8"]}')).toEqual({ quantizations: ["fp8"] });
    expect(parseSavedRouting("none")).toBeNull();
    expect(parseSavedRouting(" NONE ")).toBeNull();
  });

  it("rejects a value that is neither JSON nor a file", () => {
    expect(() => parseSavedRouting("fp8")).toThrow(/neither inline JSON/);
  });
});

describe("openrouterModule.formatForList", () => {
  it("shows the saved routing", () => {
    const line = openrouterModule.formatForList({
      provider: "openrouter",
      openrouter: { apiKey: "sk-or-v1-x", routing: { quantizations: ["fp8"] } },
      schemaVersion: 1,
    });
    expect(line).toContain('routing={"quantizations":["fp8"]}');
  });
});

describe("openrouterModule.collectCredentials routing", () => {
  const existing = {
    provider: "openrouter" as const,
    openrouter: { apiKey: "sk-or-old", routing: { quantizations: ["fp8"] } },
    schemaVersion: 1 as const,
  };
  const collect = (openrouterRouting?: string) =>
    openrouterModule.collectCredentials({
      inputs: { apiKey: "sk-or-new", openrouterRouting },
      env: {},
      interactive: false,
      existing,
    });

  it("keeps the saved routing when no routing is given", async () => {
    expect((await collect()).openrouter?.routing).toEqual({ quantizations: ["fp8"] });
  });

  it("replaces it with a new value", async () => {
    expect((await collect('{"sort":"latency"}')).openrouter?.routing).toEqual({ sort: "latency" });
  });

  it("clears it with none", async () => {
    expect((await collect("none")).openrouter).toEqual({
      apiKey: "sk-or-new",
      model: "z-ai/glm-5.2",
    });
  });
});
