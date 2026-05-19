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

const DIAGNOSTICS: DiagnosticConstructor[] = [AuthFailure, OllamaContextOverflow];

export function diagnoseScanError(err: unknown): ScanDiagnostic | null {
  for (const cls of DIAGNOSTICS) {
    const result = cls.from(err);
    if (result) return result;
  }
  return null;
}

/**
 * Single sink for detector-side errors. Recoverable errors get logged
 * inline with optional stack-trace context; fatal errors (e.g. bad
 * credentials) are converted into a `FatalScanError` and thrown so the
 * caller's outer try/catch can abort the run cleanly.
 */
export function handleDetectorError(
  opts: { verbose?: boolean },
  label: string,
  err: unknown,
): void {
  const e = err as Error & {
    cause?: unknown;
    responseBody?: string;
    statusCode?: number;
    url?: string;
  };

  const diagnostic = diagnoseScanError(err);
  if (diagnostic?.fatal) {
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
