/**
 * Tests for the rate-limit detection + Retry-After parsing used by
 * `withTpmRetry` in vercel-agent.ts. Pure-function tests — no LLM calls.
 *
 * The matcher set must cover every provider we support (OpenAI, Anthropic,
 * Vertex MaaS via the Vercel AI SDK) without false-positives on unrelated
 * errors. Vertex MaaS specifically used to slip past the old `/tpm/i` regex
 * because its 429 body says "Too Many Requests" with no TPM wording, so the
 * Vercel-fixture tests below are the regression guard.
 */
import { describe, expect, it } from "vitest";
import {
  isContextLengthError,
  isRateLimitError,
  isTransientUpstreamError,
  parseRetryAfterMs,
} from "../src/detectors/vercel-agent.js";

describe("isRateLimitError", () => {
  describe("matches known rate-limit errors", () => {
    it.each([
      // OpenAI
      ["Rate limit reached for gpt-4o tokens per minute (TPM)"],
      ["Rate limit reached for gpt-4o-mini in organization org-xxx on tokens per min"],
      // Anthropic
      ["Number of tokens has exceeded TPM limit"],
      ["tpm exceeded for claude-3-5-sonnet"],
      // Vertex MaaS via Vercel AI SDK
      ["AI_RetryError: Failed after 3 attempts. Last error: Too Many Requests"],
      ["Too Many Requests"],
      ["HTTP 429: Quota exceeded for the project"],
      // Google services generic
      ["RESOURCE_EXHAUSTED: Quota exceeded"],
      ["Quota exceeded for quota metric foo"],
    ])("matches %s", (msg) => {
      expect(isRateLimitError(msg)).toBe(true);
    });
  });

  describe("does NOT match unrelated errors", () => {
    it.each([
      ["Internal server error"],
      ["Authentication failed: invalid API key"],
      ["Connection timed out"],
      ["malformed JSON response"],
      ["Model not found"],
      // 429 must be a standalone token, not a substring of a longer number
      // (e.g. timestamps like 20260603225429).
      ["timestamp: 20260603225429"],
      // "tpm" must be standalone — "stump" / "phantpm" shouldn't trip it.
      ["stumped on parsing input"],
    ])("does not match %s", (msg) => {
      expect(isRateLimitError(msg)).toBe(false);
    });
  });
});

describe("isTransientUpstreamError", () => {
  describe("matches retryable upstream/transport flakes", () => {
    it.each([
      // Vertex MaaS gateway: HTTP 200 with a plain-text timeout body, which the
      // OpenAI-compatible parser rejects as "Invalid JSON response".
      ["AI_APICallError: Invalid JSON response | upstream request timeout"],
      ["Invalid JSON response"],
      ["upstream request timeout"],
      // Dropped / slow connections.
      ["Failed after 3 attempts. Last error: Cannot connect to API: Headers Timeout Error"],
      ["Cannot connect to API"],
      ["fetch failed"],
      ["socket hang up"],
      ["read ECONNRESET"],
      ["connect ETIMEDOUT 10.0.0.1:443"],
      ["terminated"],
      // 5xx gateway errors.
      ["503 Service Unavailable"],
      ["502 Bad Gateway"],
      ["504 Gateway Timeout"],
    ])("matches %s", (msg) => {
      expect(isTransientUpstreamError(msg)).toBe(true);
    });
  });

  describe("does NOT match deterministic or unrelated errors", () => {
    it.each([
      // Context overflow is a 400 — deterministic, must NOT be retried here.
      ["The input (207058 tokens) is longer than the model's context length (202752 tokens)."],
      ["Bad Request"],
      ["Authentication failed: invalid API key"],
      ["Model not found"],
      // A standalone 404/400 must not trip the 502/503/504 matcher.
      ["HTTP 404 Not Found"],
      ["HTTP 400 invalid argument"],
    ])("does not match %s", (msg) => {
      expect(isTransientUpstreamError(msg)).toBe(false);
    });
  });
});

describe("isContextLengthError", () => {
  describe("matches context-overflow rejections across providers", () => {
    it.each([
      // Vertex / GLM-5 MaaS (the production case).
      ["The input (207058 tokens) is longer than the model's context length (202752 tokens)."],
      // OpenAI.
      ["context_length_exceeded: maximum context length is 128000 tokens"],
      ["This model's maximum context length is 8192 tokens"],
      // Anthropic.
      ["prompt is too long: 250000 tokens > 200000 maximum"],
    ])("matches %s", (msg) => {
      expect(isContextLengthError(msg)).toBe(true);
    });
  });

  describe("does NOT match unrelated errors", () => {
    it.each([
      ["Too Many Requests"],
      ["Invalid JSON response"],
      ["Bad Request"],
      ["Internal server error"],
    ])("does not match %s", (msg) => {
      expect(isContextLengthError(msg)).toBe(false);
    });
  });
});

describe("parseRetryAfterMs", () => {
  it("parses OpenAI 'try again in Xs' (decimal seconds, with 200ms buffer)", () => {
    expect(parseRetryAfterMs("Please try again in 1.5s")).toBe(1700);
    expect(parseRetryAfterMs("retry — try again in 60s — exit if abort")).toBe(60200);
  });

  it("parses HTTP 'Retry-After: <seconds>'", () => {
    expect(parseRetryAfterMs("Retry-After: 30")).toBe(30200);
    expect(parseRetryAfterMs("retry-after: 5")).toBe(5200);
    expect(parseRetryAfterMs("retry after 10s")).toBe(10200);
  });

  it("returns null when no recognized delay pattern is present", () => {
    expect(parseRetryAfterMs("Too Many Requests")).toBeNull();
    expect(parseRetryAfterMs("AI_RetryError: Failed after 3 attempts")).toBeNull();
    expect(parseRetryAfterMs("")).toBeNull();
  });
});
