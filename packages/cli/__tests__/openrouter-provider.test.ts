import { afterEach, describe, expect, it, vi } from "vitest";
import { buildProviderRouting, createRoutingFetch } from "../src/providers/openrouter.js";

const ENV_KEYS = [
  "OPENROUTER_QUANTIZATIONS", "OPENROUTER_SORT", "OPENROUTER_PROVIDER_ORDER",
  "OPENROUTER_ALLOW_FALLBACKS", "OPENROUTER_MAX_PRICE_PROMPT",
  "OPENROUTER_MAX_PRICE_COMPLETION", "OPENROUTER_ZDR",
];
afterEach(() => { for (const k of ENV_KEYS) delete process.env[k]; });

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
