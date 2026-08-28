/**
 * Tests for generation-id capture on the paths that previously lost it:
 * a call that FAILED, and a call that succeeded but printed nothing.
 *
 * Why this exists: `formatGenerationIds` reads `response.id`, which only
 * exists on a result. When a call throws — OpenRouter credits exhausted, a
 * dropped connection, a 400 — there is no result, so the one identifier that
 * makes the provider's dashboard searchable is gone. The provider still echoes
 * a request id in the error's response headers; `formatErrorIds` salvages it.
 *
 * Pure-function tests. No LLM calls.
 */
import type { Finding } from "@agentgg/core";
import { MockLanguageModelV1 } from "ai/test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  formatErrorIds,
  logFailedCallIds,
  logGenerationIds,
  VercelAgentDetector,
} from "../src/detectors/vercel-agent.js";

/** An APICallError-shaped throw: what the AI SDK hands us on a failed request. */
function apiCallError(headers: Record<string, string>, responseBody?: string) {
  return Object.assign(new Error("Bad Request"), {
    statusCode: 400,
    url: "https://openrouter.ai/api/v1/chat/completions",
    responseHeaders: headers,
    responseBody,
  });
}

describe("formatErrorIds", () => {
  it("salvages the request id an OpenAI-style provider echoes in its headers", () => {
    const out = formatErrorIds(apiCallError({ "x-request-id": "req_abc123" }));
    expect(out).toContain("reqId=req_abc123");
    expect(out).toContain("x-request-id");
  });

  it("reads Anthropic's request-id header", () => {
    expect(formatErrorIds(apiCallError({ "request-id": "req_ant_1" }))).toContain(
      "reqId=req_ant_1",
    );
  });

  it("matches headers case-insensitively", () => {
    expect(formatErrorIds(apiCallError({ "X-Request-Id": "req_upper" }))).toContain("req_upper");
  });

  it("falls back to the Cloudflare ray id when no request id is present", () => {
    const out = formatErrorIds(apiCallError({ "cf-ray": "9a1b2c3d4e5f-LHR" }));
    expect(out).toContain("reqId=9a1b2c3d4e5f-LHR");
    expect(out).toContain("cf-ray");
  });

  it("prefers the request id over the ray id when both are present", () => {
    const out = formatErrorIds(apiCallError({ "cf-ray": "ray-1", "x-request-id": "req_1" }));
    expect(out).toContain("req_1");
    expect(out).not.toContain("ray-1");
  });

  it("finds the id through a cause chain", () => {
    const wrapped = new Error("context length exceeded: Bad Request", {
      cause: apiCallError({ "x-request-id": "req_deep" }),
    });
    expect(formatErrorIds(wrapped)).toContain("req_deep");
  });

  it("reports first..last plus the count when a RetryError carries every attempt", () => {
    const retry = Object.assign(new Error("Failed after 3 attempts"), {
      reason: "maxRetriesExceeded",
      errors: [
        apiCallError({ "x-request-id": "req_1" }),
        apiCallError({ "x-request-id": "req_2" }),
        apiCallError({ "x-request-id": "req_3" }),
      ],
    });
    const out = formatErrorIds(retry);
    expect(out).toContain("reqIds=req_1..req_3");
    expect(out).toContain("3 attempts");
  });

  it("does not double-count the attempt RetryError exposes as both lastError and errors", () => {
    const last = apiCallError({ "x-request-id": "req_only" });
    const retry = Object.assign(new Error("Failed after 1 attempt"), {
      lastError: last,
      errors: [last],
    });
    expect(formatErrorIds(retry)).toContain("reqId=req_only");
  });

  it("lifts a generation id out of the error body when the provider returned one", () => {
    const err = apiCallError({}, JSON.stringify({ id: "gen-1786494581", error: { code: 402 } }));
    expect(formatErrorIds(err)).toContain("genId=gen-1786494581");
  });

  it("reports the generation id and the request id when both are available", () => {
    const err = apiCallError({ "x-request-id": "req_both" }, JSON.stringify({ id: "gen-both" }));
    const out = formatErrorIds(err);
    expect(out).toContain("genId=gen-both");
    expect(out).toContain("reqId=req_both");
  });

  // Header shapes below were measured against the live OpenRouter API on
  // 2026-08-28, not guessed. OpenRouter sends the GENERATION id as a header
  // (X-Generation-Id, same value as the body's `id`) and does NOT send
  // x-request-id at all; the only request-ish header is Cloudflare's CF-RAY.
  // That inverts the original assumption that headers carry request ids only.
  describe("OpenRouter, as the live API actually answers", () => {
    it("prefers the generation id header over the cloudflare edge id", () => {
      const out = formatErrorIds(
        apiCallError({
          "X-Generation-Id": "gen-1787910087-YiDs6QhKhlryJxmeA7cl",
          "CF-RAY": "a3225c3f7823252d-SEA",
        }),
      );
      expect(out).toContain("genId=gen-1787910087-YiDs6QhKhlryJxmeA7cl");
      expect(out).toContain("reqId=a3225c3f7823252d-SEA (cf-ray)");
    });

    it("falls back to CF-RAY when the call failed before any generation", () => {
      // A 400 for a bad model id: nothing was generated, so there is no
      // generation id anywhere, and the edge trace is all we can offer.
      const out = formatErrorIds(
        apiCallError(
          { "CF-RAY": "a3225bf43abac96d-SEA" },
          '{"error":{"message":"x is not a valid model ID","code":400},"user_id":"user_3Hbc"}',
        ),
      );
      expect(out).toBe(" reqId=a3225bf43abac96d-SEA (cf-ray)");
    });

    it("does not mistake user_id in an error body for a generation id", () => {
      const out = formatErrorIds(apiCallError({}, '{"error":{"code":402},"user_id":"user_3Hbc"}'));
      expect(out).toBe("");
    });
  });

  // Shapes below were measured against each live API on 2026-08-28.
  describe("the other providers that reach this code", () => {
    it("takes OpenAI's x-request-id, the id its dashboard indexes", () => {
      const out = formatErrorIds(
        apiCallError({
          "x-request-id": "req_c7e80b8e674349b1a71774b127f04d93",
          "CF-Ray": "a3226840ecfa6de2-SEA",
        }),
      );
      expect(out).toBe(" reqId=req_c7e80b8e674349b1a71774b127f04d93 (x-request-id)");
    });

    it("reads Bedrock's id from $metadata, where the AWS SDK puts it", () => {
      // @ai-sdk/amazon-bedrock never populates responseHeaders; the AWS SDK
      // error carries $metadata.requestId instead.
      const err = Object.assign(new Error("ValidationException"), {
        $metadata: { httpStatusCode: 400, requestId: "163a8eb7-6723-40d3-942e-53942a97ed6c" },
      });
      expect(formatErrorIds(err)).toBe(
        " reqId=163a8eb7-6723-40d3-942e-53942a97ed6c ($metadata.requestId)",
      );
    });

    it("reports nothing for Vertex, which exposes no id header at all", () => {
      const out = formatErrorIds(
        apiCallError({
          "x-xss-protection": "0",
          "x-frame-options": "SAMEORIGIN",
          "x-content-type-options": "nosniff",
        }),
      );
      expect(out).toBe("");
    });
  });

  it("says nothing when the provider exposed no ids", () => {
    expect(formatErrorIds(apiCallError({ "content-type": "application/json" }))).toBe("");
  });

  describe("degrades quietly rather than breaking a scan", () => {
    it.each([
      ["a plain error", new Error("boom")],
      ["a string throw", "boom"],
      ["null", null],
      ["undefined", undefined],
      ["a non-JSON response body", apiCallError({}, "<html>502 Bad Gateway</html>")],
      ["a non-object headers field", Object.assign(new Error("x"), { responseHeaders: "nope" })],
    ])("returns an empty string on %s", (_label, err) => {
      expect(formatErrorIds(err)).toBe("");
    });

    it("does not recurse forever on a self-referential cause", () => {
      const err = new Error("loop") as Error & { cause?: unknown };
      err.cause = err;
      expect(() => formatErrorIds(err)).not.toThrow();
    });
  });
});

describe("logFailedCallIds", () => {
  let warn: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  });
  afterEach(() => {
    warn.mockRestore();
  });

  it("attributes the failed call to its tool loop", () => {
    logFailedCallIds("validate:197815be26e3", apiCallError({ "x-request-id": "req_x" }));
    expect(warn).toHaveBeenCalledOnce();
    const msg = String(warn.mock.calls[0]?.[0]);
    expect(msg).toContain("validate:197815be26e3");
    expect(msg).toContain("req_x");
  });

  it("includes the first line of the error so the id has context", () => {
    logFailedCallIds("recon", apiCallError({ "x-request-id": "req_x" }));
    expect(String(warn.mock.calls[0]?.[0])).toContain("Bad Request");
  });

  it("stays silent when there is no id to report", () => {
    logFailedCallIds("recon", new Error("fetch failed"));
    expect(warn).not.toHaveBeenCalled();
  });

  it("stays silent on a user cancel, which is not a provider failure", () => {
    const controller = new AbortController();
    controller.abort();
    logFailedCallIds("recon", apiCallError({ "x-request-id": "req_x" }), controller.signal);
    expect(warn).not.toHaveBeenCalled();
  });

  it("stays silent on an AbortError even without the signal", () => {
    const err = Object.assign(apiCallError({ "x-request-id": "req_x" }), { name: "AbortError" });
    logFailedCallIds("recon", err);
    expect(warn).not.toHaveBeenCalled();
  });
});

describe("logGenerationIds", () => {
  // Asserts on console.error, not console.warn: a successful call is INFO on
  // stderr. A `[WARN]` per healthy call would devalue the level, and stdout
  // would corrupt `--json`.
  let warn: ReturnType<typeof vi.spyOn>;
  const result = { response: { id: "gen-42" } };

  beforeEach(() => {
    warn = vi.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(() => {
    warn.mockRestore();
  });

  it("reports a working call at INFO, never WARN", () => {
    const realWarn = vi.spyOn(console, "warn").mockImplementation(() => {});
    logGenerationIds("recon", result, { AGENTGG_LOG_GENERATION_IDS: "1" });
    expect(realWarn).not.toHaveBeenCalled();
    expect(String(warn.mock.calls[0]?.[0])).toContain("[INFO]");
    realWarn.mockRestore();
  });

  it("stays silent by default, so a normal scan log is unchanged", () => {
    logGenerationIds("recon", result, {});
    expect(warn).not.toHaveBeenCalled();
  });

  it("prints the id per call when tracing is turned on", () => {
    logGenerationIds("score:abc", result, { AGENTGG_LOG_GENERATION_IDS: "1" });
    expect(warn).toHaveBeenCalledOnce();
    const msg = String(warn.mock.calls[0]?.[0]);
    expect(msg).toContain("score:abc");
    expect(msg).toContain("genId=gen-42");
  });

  it.each(["0", "false", ""])("treats %o as off", (value) => {
    logGenerationIds("recon", result, { AGENTGG_LOG_GENERATION_IDS: value });
    expect(warn).not.toHaveBeenCalled();
  });

  it("stays silent when the provider exposed no id", () => {
    logGenerationIds("recon", { steps: [] }, { AGENTGG_LOG_GENERATION_IDS: "1" });
    expect(warn).not.toHaveBeenCalled();
  });
});

/**
 * The wiring, not the formatting: every LLM call funnels through `metered`, so
 * a throw anywhere in the detector has to come back out with a label and an id
 * attached. `scoreFinding` stands in for all of them — it is the shortest path
 * through `metered` (no tools, one call).
 */
describe("a failed call reports its ids through metered", () => {
  let warn: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  function throwingDetector(err: unknown) {
    return new VercelAgentDetector(
      "openrouter",
      new MockLanguageModelV1({
        defaultObjectGenerationMode: "json",
        doGenerate: async () => {
          throw err;
        },
      }),
    );
  }

  const finding = {
    id: "abc123abc123",
    agentSlug: "xss",
    title: "Stored XSS in the comment renderer",
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
  } as Finding;

  it("names the loop and the request id, and still rethrows", async () => {
    const detector = throwingDetector(apiCallError({ "x-request-id": "req_scored" }));
    await expect(detector.scoreFinding({ finding, fileContent: "const x = 1;" })).rejects.toThrow();
    const logged = warn.mock.calls.map((c) => String(c[0])).filter((m) => m.includes("req_scored"));
    expect(logged).toHaveLength(1);
    expect(logged[0]).toContain("[score:abc123abc123]");
  });

  it("says nothing extra when the failure carries no id", async () => {
    const detector = throwingDetector(new Error("Authentication failed: invalid API key"));
    await expect(detector.scoreFinding({ finding, fileContent: "const x = 1;" })).rejects.toThrow();
    expect(warn.mock.calls.filter((c) => String(c[0]).includes("call failed"))).toHaveLength(0);
  });
});
