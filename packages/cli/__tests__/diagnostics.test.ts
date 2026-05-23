/**
 * Fixture-based tests for the QuotaExhausted diagnostic.
 *
 * Provider error shapes are recorded from official docs / community
 * reports — see comments above each fixture for the source. Each fixture
 * is the minimum payload needed for the classifier to fire (or correctly
 * NOT fire, for the rate-limit cases that should stay retryable).
 *
 * No live LLM calls — the diagnostic operates entirely on error
 * properties, so we can simulate every provider's failure shape with
 * a plain `Error` plus the same decorations the SDKs attach.
 */
import { describe, expect, it, vi } from "vitest";
import { diagnoseScanError, FatalScanError, handleDetectorError } from "../src/diagnostics.js";

/**
 * Build an Error decorated the way the Vercel AI SDK / Anthropic SDK /
 * AWS SDK surface failed HTTP responses. Different SDKs hang fields on
 * the error or on `err.cause`; the classifier walks both.
 */
function buildHttpError(opts: {
  message?: string;
  statusCode?: number;
  responseBody?: string;
  name?: string;
  // AWS SDK v3 attaches __type and $metadata on typed exceptions.
  __type?: string;
  $metadata?: { httpStatusCode?: number };
  cause?: Record<string, unknown>;
}): Error {
  const err = new Error(opts.message ?? "Provider returned an error response");
  if (opts.name) err.name = opts.name;
  return Object.assign(err, {
    statusCode: opts.statusCode,
    responseBody: opts.responseBody,
    __type: opts.__type,
    $metadata: opts.$metadata,
    cause: opts.cause,
  });
}

describe("QuotaExhausted classifier", () => {
  describe("Anthropic", () => {
    it("recognizes the modern 402 billing_error shape (per platform.claude.com errors doc)", () => {
      const err = buildHttpError({
        statusCode: 402,
        responseBody: JSON.stringify({
          type: "error",
          error: {
            type: "billing_error",
            message:
              "There's an issue with your billing or payment information. Check your payment details in the Claude Console.",
          },
        }),
      });
      const d = diagnoseScanError(err);
      expect(d?.fatal).toBe(true);
      expect(d?.format()).toMatch(/Anthropic/);
      expect(d?.format()).toMatch(/console\.anthropic\.com/);
    });

    it("recognizes the legacy 400 + 'credit balance is too low' shape (anthropics/claude-code#867)", () => {
      const err = buildHttpError({
        statusCode: 400,
        responseBody: JSON.stringify({
          type: "error",
          error: {
            type: "invalid_request_error",
            message:
              "Your credit balance is too low to access the Anthropic API. Please go to Plans & Billing to upgrade or purchase credits.",
          },
        }),
      });
      const d = diagnoseScanError(err);
      expect(d?.fatal).toBe(true);
      expect(d?.format()).toMatch(/Anthropic/);
    });

    it("recognizes the legacy shape when the message appears on err.message directly (claude-agent-sdk subprocess stderr surface)", () => {
      // claude-agent-sdk wraps subprocess output as the error message itself
      // rather than as a responseBody, so the haystack scan has to find it
      // there too.
      const err = buildHttpError({
        message: "Your credit balance is too low to access the Anthropic API.",
      });
      const d = diagnoseScanError(err);
      expect(d?.fatal).toBe(true);
      expect(d?.format()).toMatch(/Anthropic/);
    });

    it("does NOT trigger on 429 rate_limit_error (Option A: retryable — withTpmRetry handles it)", () => {
      const err = buildHttpError({
        statusCode: 429,
        responseBody: JSON.stringify({
          type: "error",
          error: {
            type: "rate_limit_error",
            message: "Number of request tokens has exceeded your per-minute rate limit.",
          },
        }),
      });
      const d = diagnoseScanError(err);
      expect(d).toBeNull();
    });

    it("does NOT trigger on 529 overloaded_error (provider-wide overload, retryable)", () => {
      const err = buildHttpError({
        statusCode: 529,
        responseBody: JSON.stringify({
          type: "error",
          error: { type: "overloaded_error", message: "Overloaded" },
        }),
      });
      const d = diagnoseScanError(err);
      expect(d).toBeNull();
    });
  });

  describe("OpenAI", () => {
    it("recognizes insufficient_quota via error.type field (both insufficient_quota and rate_limit_exceeded are 429 — distinguish on body)", () => {
      const err = buildHttpError({
        statusCode: 429,
        responseBody: JSON.stringify({
          error: {
            message: "You exceeded your current quota, please check your plan and billing details.",
            type: "insufficient_quota",
            code: "insufficient_quota",
          },
        }),
      });
      const d = diagnoseScanError(err);
      expect(d?.fatal).toBe(true);
      expect(d?.format()).toMatch(/OpenAI/);
      expect(d?.format()).toMatch(/platform\.openai\.com/);
    });

    it("recognizes insufficient_quota via error.code field too (some SDK paths set code but not type)", () => {
      const err = buildHttpError({
        statusCode: 429,
        responseBody: JSON.stringify({
          error: {
            message: "You exceeded your current quota, please check your plan and billing details.",
            code: "insufficient_quota",
          },
        }),
      });
      const d = diagnoseScanError(err);
      expect(d?.fatal).toBe(true);
    });

    it("does NOT trigger on rate_limit_exceeded (short-term TPM/RPM, retryable — same 429 status)", () => {
      const err = buildHttpError({
        statusCode: 429,
        responseBody: JSON.stringify({
          error: {
            message:
              "Rate limit reached for gpt-4 in organization org-xxx on tokens per min. Please try again in 20s.",
            type: "rate_limit_exceeded",
            code: "rate_limit_exceeded",
          },
        }),
      });
      const d = diagnoseScanError(err);
      // Regression: any classifier change must not accidentally flag a
      // recoverable TPM limit as fatal — that would bail out perfectly
      // healthy scans the moment they hit one slow minute.
      expect(d).toBeNull();
    });
  });

  describe("AWS Bedrock", () => {
    it("recognizes ServiceQuotaExceededException via error.name (AWS SDK v3 typed exception)", () => {
      const err = buildHttpError({
        message: "Your request exceeds the service quota for your account.",
        statusCode: 429,
        name: "ServiceQuotaExceededException",
        $metadata: { httpStatusCode: 429 },
      });
      const d = diagnoseScanError(err);
      expect(d?.fatal).toBe(true);
      expect(d?.format()).toMatch(/Bedrock/);
      expect(d?.format()).toMatch(/quota increase/);
    });

    it("recognizes ServiceQuotaExceededException via __type wire field", () => {
      const err = buildHttpError({
        statusCode: 429,
        __type: "com.amazonaws.bedrockruntime#ServiceQuotaExceededException",
      });
      const d = diagnoseScanError(err);
      expect(d?.fatal).toBe(true);
      expect(d?.format()).toMatch(/Bedrock/);
    });

    it("does NOT trigger on ThrottlingException (short-term throttle, retryable — same 429 status)", () => {
      const err = buildHttpError({
        message: "Too many requests, please wait before trying again.",
        statusCode: 429,
        name: "ThrottlingException",
        $metadata: { httpStatusCode: 429 },
      });
      const d = diagnoseScanError(err);
      expect(d).toBeNull();
    });
  });

  it("returns null for unrelated errors so they fall through to the generic logger", () => {
    expect(diagnoseScanError(new Error("ECONNREFUSED"))).toBeNull();
    expect(diagnoseScanError(new Error("Type validation failed: expected number"))).toBeNull();
    expect(diagnoseScanError("not even an Error object")).toBeNull();
  });
});

describe("handleDetectorError abort-and-suppress behavior", () => {
  it("throws FatalScanError and aborts the controller when a fatal diagnostic fires", () => {
    const abortController = new AbortController();
    const abortSpy = vi.spyOn(abortController, "abort");
    const quotaErr = buildHttpError({
      statusCode: 402,
      responseBody: JSON.stringify({
        type: "error",
        error: { type: "billing_error", message: "billing issue" },
      }),
    });

    expect(() =>
      handleDetectorError({ verbose: false }, "file:src/a.ts", quotaErr, abortController),
    ).toThrow(FatalScanError);
    // Critical: in-flight sibling HTTP requests need to be cancelled at
    // the SDK layer before unwinding. Without this call, workers wait
    // out their (doomed) requests against an exhausted credential.
    expect(abortSpy).toHaveBeenCalledTimes(1);
    expect(abortController.signal.aborted).toBe(true);
  });

  it("suppresses AbortError siblings AFTER the controller has been aborted", () => {
    const abortController = new AbortController();
    abortController.abort(new Error("first worker hit quota"));

    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const siblingAbort = new Error("The operation was aborted");
      siblingAbort.name = "AbortError";
      // Sibling task's in-flight request gets cancelled when the
      // controller aborts — the resulting AbortError is informational
      // noise, not actionable. Suppressed by default.
      handleDetectorError({ verbose: false }, "file:src/b.ts", siblingAbort, abortController);
      expect(stderrSpy).not.toHaveBeenCalled();
    } finally {
      stderrSpy.mockRestore();
    }
  });

  it("shows the one-liner 'cancelled' message under --verbose so operators can see why siblings exited", () => {
    const abortController = new AbortController();
    abortController.abort(new Error("first worker hit quota"));

    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const siblingAbort = new Error("aborted");
      siblingAbort.name = "AbortError";
      handleDetectorError({ verbose: true }, "file:src/b.ts", siblingAbort, abortController);
      expect(stderrSpy).toHaveBeenCalledTimes(1);
      expect(stderrSpy.mock.calls[0]?.[0]).toMatch(/cancelled/);
    } finally {
      stderrSpy.mockRestore();
    }
  });

  it("still logs non-abort errors normally even when the controller is aborted (genuine new failures keep their full diagnostic)", () => {
    const abortController = new AbortController();
    abortController.abort(new Error("earlier fatal"));

    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      // A 500 from the provider AFTER the abort is NOT just abort fallout —
      // it's a real new failure, log it fully so operators don't miss it.
      const real500 = buildHttpError({
        statusCode: 500,
        message: "Internal server error",
      });
      handleDetectorError({ verbose: false }, "file:src/c.ts", real500, abortController);
      expect(stderrSpy).toHaveBeenCalled();
      expect(stderrSpy.mock.calls.some((c) => /detection failed/.test(String(c[0])))).toBe(true);
    } finally {
      stderrSpy.mockRestore();
    }
  });

  it("does not throw or abort when there is no diagnostic (normal recoverable error path)", () => {
    const abortController = new AbortController();
    const abortSpy = vi.spyOn(abortController, "abort");

    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const networkBlip = new Error("ECONNRESET");
      // Should NOT throw — recoverable errors just get logged so the
      // worker pool moves on to the next item.
      expect(() =>
        handleDetectorError({ verbose: false }, "file:src/d.ts", networkBlip, abortController),
      ).not.toThrow();
      expect(abortSpy).not.toHaveBeenCalled();
      expect(abortController.signal.aborted).toBe(false);
    } finally {
      stderrSpy.mockRestore();
    }
  });
});
