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
import { isRateLimitError, parseRetryAfterMs } from "../src/detectors/vercel-agent.js";

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
