import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildProviderRouting, createRoutingFetch } from "../src/providers/openrouter.js";

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
