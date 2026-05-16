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
}

interface DiagnosticConstructor {
  from(err: unknown): ScanDiagnostic | null;
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

const DIAGNOSTICS: DiagnosticConstructor[] = [OllamaContextOverflow];

export function diagnoseScanError(err: unknown): ScanDiagnostic | null {
  for (const cls of DIAGNOSTICS) {
    const result = cls.from(err);
    if (result) return result;
  }
  return null;
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
