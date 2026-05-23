/**
 * Translate raw LLM/SDK errors into actionable, user-facing diagnostics.
 *
 * The scan pipeline surfaces failures from many layers (HTTP, JSON parsing,
 * provider quirks, auth, rate limits). Most of them ship a Zod stack or a
 * "Type validation failed" dump that's useless to operators. A diagnostic
 * recognizes one specific failure shape and rewrites it into a single sentence
 * with concrete remedies.
 *
 * To add a new diagnostic: subclass `ScanDiagnostic`, implement the static
 * `from(err)` (return `null` if it doesn't match) and `format()`, then add
 * the class to `DIAGNOSTICS`. The caller code never changes.
 */

export abstract class ScanDiagnostic {
  abstract format(): string;
  /**
   * When true, this failure mode will reproduce on every subsequent
   * detector call — there is no point continuing the run. Callers
   * surface the message once and abort.
   */
  readonly fatal: boolean = false;
}

interface DiagnosticConstructor {
  from(err: unknown): ScanDiagnostic | null;
}

/**
 * Thrown out of `handleDetectorError` when the underlying error is
 * unrecoverable (e.g. invalid API key). Bubbles up past the
 * per-file / per-agent try/catches so the scan as a whole aborts
 * instead of repeating the same failure on every remaining file.
 */
export class FatalScanError extends Error {
  constructor(
    public readonly diagnostic: ScanDiagnostic,
    public readonly label: string,
  ) {
    super(diagnostic.format());
    this.name = "FatalScanError";
  }
}

/**
 * Ollama returns a partial response (`done:false`, missing eval counts) when
 * the model overflows its context window — special tokens like `<|im_start|>`
 * leak out and the Vercel SDK rejects the payload as "Invalid JSON response".
 * The stacktrace is unactionable; the actual remedy is more context, a better
 * model, or a tighter scan scope.
 */
class OllamaContextOverflow extends ScanDiagnostic {
  private constructor(private readonly model: string) {
    super();
  }

  static from(err: unknown): OllamaContextOverflow | null {
    if (!(err instanceof Error)) return null;
    if (!/invalid json response/i.test(err.message)) return null;

    const haystack = collectResponseBodies(err).join(" ");
    if (!haystack) return null;

    const truncated = /"done"\s*:\s*false/.test(haystack);
    const templateLeak = /<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>/.test(haystack);
    if (!truncated && !templateLeak) return null;

    const modelMatch = haystack.match(/"model"\s*:\s*"([^"]+)"/);
    return new OllamaContextOverflow(modelMatch?.[1] ?? "the model");
  }

  format(): string {
    return (
      `Ollama returned an incomplete response from ${this.model}, likely because the ` +
      `conversation grew past its context window. Use a more capable model, narrow the ` +
      `scan with --only / --exclude, or raise num_ctx in your Ollama Modelfile and re-run.`
    );
  }
}

/**
 * The provider rejected the credentials. Every subsequent call in this
 * run will fail the same way, so the scan should bail immediately
 * rather than churn through every (file, agent) pair.
 *
 * Recognizes the common shapes:
 *   - HTTP 401 / 403 carried on the error or its cause.
 *   - Anthropic `authentication_error` / "invalid x-api-key" payloads.
 *   - OpenAI "Incorrect API key" / "invalid_api_key" payloads.
 *   - claude-agent-sdk subprocess stderr containing the same phrases
 *     when the CLI fails to auth.
 */
class AuthFailure extends ScanDiagnostic {
  override readonly fatal = true;

  private constructor(private readonly providerLabel: string) {
    super();
  }

  static from(err: unknown): AuthFailure | null {
    if (!(err instanceof Error)) return null;
    const e = err as Error & {
      statusCode?: number;
      responseBody?: string;
      cause?: unknown;
    };
    const cause =
      typeof e.cause === "object" && e.cause !== null
        ? (e.cause as { statusCode?: number; responseBody?: string; message?: string })
        : undefined;

    const status = e.statusCode ?? cause?.statusCode;
    const isAuthStatus = status === 401 || status === 403;

    const haystack = [e.message, e.responseBody, cause?.message, cause?.responseBody]
      .filter((v): v is string => typeof v === "string" && v.length > 0)
      .join("\n");

    const authPhrase =
      /authentication[_\s-]?error|invalid[_\s-]*(?:x-?)?api[_\s-]?key|incorrect[_\s-]?api[_\s-]?key|invalid[_\s-]?bearer[_\s-]?token|oauth[_\s-]?token[_\s-]?(?:invalid|expired)|\b401\b\s*(?:unauthor|invalid)|unauthorized.*(?:api|token|credential)/i.test(
        haystack,
      );

    if (!isAuthStatus && !authPhrase) return null;

    let provider = "The LLM provider";
    if (/anthropic|claude|x-api-key|sk-ant/i.test(haystack)) provider = "Anthropic";
    else if (/openai|sk-[A-Za-z0-9_-]{20,}/i.test(haystack)) provider = "OpenAI";

    return new AuthFailure(provider);
  }

  format(): string {
    const hint =
      this.providerLabel === "Anthropic"
        ? "Verify your `--api-key` (sk-ant-…) or `--oauth-token` (sk-ant-oat-…), or re-run `agentgg init`."
        : this.providerLabel === "OpenAI"
          ? "Verify your `--api-key` (sk-…), or re-run `agentgg init`."
          : "Verify the credentials for your provider, or re-run `agentgg init`.";
    return `${this.providerLabel} rejected the credentials. ${hint}`;
  }
}

/**
 * Provider quota / billing / credit exhaustion. Distinct from short-term
 * rate limiting: rate limits resolve in seconds (handled by withTpmRetry
 * in the Vercel detector); quota exhaustion needs a top-up / quota
 * increase request and won't fix itself inside a single scan run. Marked
 * fatal so the scan aborts cleanly and resume picks up where it stopped.
 *
 * Recognized shapes (verified against provider docs / community reports —
 * see packages/cli/src/__tests__/fixtures/quota/ for canonical bodies):
 *
 *   Anthropic API key — modern: HTTP 402 with error.type === "billing_error".
 *   Anthropic API key — legacy: HTTP 400 with error.type === "invalid_request_error"
 *                              AND body matching /credit balance is too low/i.
 *                              Same handler still surfaces in the wild via the
 *                              Claude Agent SDK subprocess stderr.
 *   OpenAI:               HTTP 429 with error.type or error.code === "insufficient_quota"
 *                         (status alone is ambiguous — short-term rate limits are also 429).
 *   AWS Bedrock:          ServiceQuotaExceededException — recognized via the AWS SDK's
 *                         __type field or the exception's name property.
 *
 * Deliberately NOT recognized (handled elsewhere or kept retryable):
 *   - Anthropic 429 rate_limit_error: retryable (existing withTpmRetry) for
 *     API-key TPM and OAuth Pro/Max usage-window cases. The OAuth window
 *     case may need a separate diagnostic later — pending real-error
 *     capture to confirm the body shape.
 *   - OpenAI 429 rate_limit_exceeded: retryable.
 *   - Bedrock ThrottlingException: retryable.
 */
class QuotaExhausted extends ScanDiagnostic {
  override readonly fatal = true;

  private constructor(
    private readonly providerLabel: string,
    private readonly remediation: string,
  ) {
    super();
  }

  static from(err: unknown): QuotaExhausted | null {
    if (!(err instanceof Error)) return null;
    const e = err as Error & {
      statusCode?: number;
      responseBody?: string;
      cause?: unknown;
      name?: string;
      // AWS SDK v3 attaches these on service exceptions.
      $metadata?: { httpStatusCode?: number };
      __type?: string;
    };
    const cause =
      typeof e.cause === "object" && e.cause !== null
        ? (e.cause as {
            statusCode?: number;
            responseBody?: string;
            message?: string;
            name?: string;
            $metadata?: { httpStatusCode?: number };
            __type?: string;
          })
        : undefined;

    const status = e.statusCode ?? cause?.statusCode ?? e.$metadata?.httpStatusCode;
    const haystack = [e.message, e.responseBody, cause?.message, cause?.responseBody]
      .filter((v): v is string => typeof v === "string" && v.length > 0)
      .join("\n");

    // Anthropic — modern billing_error path: HTTP 402 OR error.type
    // explicitly named. Body shape per platform.claude.com errors doc.
    if (status === 402 || /"type"\s*:\s*"billing_error"/i.test(haystack)) {
      return new QuotaExhausted(
        "Anthropic",
        "Top up at https://console.anthropic.com/settings/billing, then re-run the scan — resume picks up pending files automatically.",
      );
    }

    // Anthropic — legacy/secondary shape: 400 invalid_request_error with
    // "credit balance is too low" body. Still observed in the wild and
    // surfaces verbatim through the Claude Agent SDK subprocess stderr,
    // so match on the message string regardless of statusCode.
    if (/credit balance is too low/i.test(haystack)) {
      return new QuotaExhausted(
        "Anthropic",
        "Top up at https://console.anthropic.com/settings/billing, then re-run the scan — resume picks up pending files automatically.",
      );
    }

    // OpenAI — distinguish quota from short-term rate limit by the body
    // type/code field. Both are HTTP 429, so status alone is ambiguous.
    // Match the literal token rather than the message string because
    // OpenAI rewords the user-facing message periodically.
    if (
      /"(?:type|code)"\s*:\s*"insufficient_quota"/i.test(haystack) ||
      /insufficient_quota/i.test(e.name ?? "")
    ) {
      return new QuotaExhausted(
        "OpenAI",
        "Add credits or upgrade your plan at https://platform.openai.com/account/billing, then re-run the scan — resume picks up pending files automatically.",
      );
    }

    // AWS Bedrock — account-level service quota exceeded. AWS SDK v3
    // surfaces this as a typed exception with `name === "ServiceQuotaExceededException"`
    // and (sometimes) `__type` set on the wire payload. Distinct from
    // ThrottlingException (short-term, retryable).
    const bedrockName = e.name ?? cause?.name ?? "";
    const bedrockType = e.__type ?? cause?.__type ?? "";
    if (
      /ServiceQuotaExceededException/.test(bedrockName) ||
      /ServiceQuotaExceededException/.test(bedrockType) ||
      /"__type"\s*:\s*"[^"]*ServiceQuotaExceededException/i.test(haystack)
    ) {
      return new QuotaExhausted(
        "AWS Bedrock",
        "Request a quota increase via AWS Support (Service Quotas → Amazon Bedrock), then re-run the scan — resume picks up pending files automatically.",
      );
    }

    return null;
  }

  format(): string {
    return `${this.providerLabel} quota / credits exhausted. ${this.remediation}`;
  }
}

const DIAGNOSTICS: DiagnosticConstructor[] = [AuthFailure, QuotaExhausted, OllamaContextOverflow];

export function diagnoseScanError(err: unknown): ScanDiagnostic | null {
  for (const cls of DIAGNOSTICS) {
    const result = cls.from(err);
    if (result) return result;
  }
  return null;
}

/** Detect whether an error came from an `AbortController.abort()` we initiated. */
function isAbortError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  if (err.name === "AbortError") return true;
  // Vercel AI SDK + node fetch wrap aborts as DOMException("AbortError")
  // or surface them via the `cause` chain. Walk one level of cause.
  const cause = (err as Error & { cause?: unknown }).cause;
  if (
    cause instanceof Error &&
    (cause.name === "AbortError" || /aborted|abort_err/i.test(cause.message))
  ) {
    return true;
  }
  return /\b(aborted|the operation was aborted|request was aborted)\b/i.test(err.message);
}

/**
 * Single sink for detector-side errors. Recoverable errors get logged
 * inline with optional stack-trace context; fatal errors (e.g. bad
 * credentials) are converted into a `FatalScanError` and thrown so the
 * caller's outer try/catch can abort the run cleanly.
 *
 * When `abortController` is passed and the diagnostic is fatal, the
 * controller is aborted BEFORE the throw — that cancels every in-flight
 * detector HTTP request so sibling workers exit immediately instead of
 * waiting for their (doomed) requests to settle. The thrown
 * `FatalScanError` still propagates up via `runConcurrent` to the outer
 * scan handler.
 *
 * Once `abortController.signal.aborted` is true, subsequent calls into
 * this sink for the same scan are expected to be `AbortError`s from
 * sibling in-flight requests (they all share the same dead credential).
 * Those get a single-line "cancelled" log instead of the full stack +
 * response body dump — there's nothing actionable about an abort
 * triggered by an earlier diagnostic.
 */
export function handleDetectorError(
  opts: { verbose?: boolean },
  label: string,
  err: unknown,
  abortController?: AbortController,
): void {
  const e = err as Error & {
    cause?: unknown;
    responseBody?: string;
    statusCode?: number;
    url?: string;
  };

  // Already-aborted scan: in-flight siblings throw AbortError once the
  // controller fires. Surface them as a one-liner — the originating
  // fatal diagnostic has already been printed by the worker that hit it.
  if (abortController?.signal.aborted && isAbortError(err)) {
    if (opts.verbose) {
      console.error(`    ${label}: cancelled (scan aborted)`);
    }
    return;
  }

  const diagnostic = diagnoseScanError(err);
  if (diagnostic?.fatal) {
    // Cancel in-flight sibling requests before throwing so they unwind
    // immediately instead of waiting out their HTTP timeout against an
    // exhausted credential.
    abortController?.abort(new FatalScanError(diagnostic, label));
    throw new FatalScanError(diagnostic, label);
  }

  const msg = e.message || String(err);

  if (diagnostic) {
    console.error(`    ${label}: ${diagnostic.format()}`);
    if (opts.verbose && e.stack) {
      console.error(
        e.stack
          .split("\n")
          .slice(0, 8)
          .map((l) => `      ${l}`)
          .join("\n"),
      );
    }
    return;
  }

  console.error(`    ${label}: detection failed — ${msg}`);
  if (e.statusCode) console.error(`      HTTP ${e.statusCode} ${e.url ?? ""}`);
  if (e.responseBody) {
    console.error(`      Response: ${String(e.responseBody).slice(0, 300)}`);
  }
  if (e.cause && typeof e.cause === "object") {
    const c = e.cause as Error & { responseBody?: string; statusCode?: number };
    if (c.message && c.message !== msg) console.error(`      Cause: ${c.message}`);
    if (c.statusCode) console.error(`      Cause HTTP: ${c.statusCode}`);
    if (c.responseBody) {
      console.error(`      Cause body: ${String(c.responseBody).slice(0, 300)}`);
    }
  }
  if (opts.verbose && e.stack) {
    console.error(
      e.stack
        .split("\n")
        .slice(0, 8)
        .map((l) => `      ${l}`)
        .join("\n"),
    );
  }
}

function collectResponseBodies(err: Error): string[] {
  const bodies: string[] = [];
  const e = err as Error & { responseBody?: string; cause?: unknown };
  if (e.responseBody) bodies.push(e.responseBody);
  const cause = e.cause as { responseBody?: string; message?: string } | undefined;
  if (cause?.responseBody) bodies.push(cause.responseBody);
  if (cause?.message) bodies.push(cause.message);
  return bodies;
}
