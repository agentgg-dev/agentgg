/**
 * Rolling 60-second tokens-per-minute budget shared across concurrent
 * workers. Each caller reserves an estimated token cost before its
 * request, then reconciles with actual usage from the response. When
 * the bucket is full, callers sleep until enough budget falls out of
 * the rolling window.
 *
 * Designed to be installed below the AI SDK by wrapping `fetch` — that
 * way every HTTP call (each step of a hunt tool loop, every file-mode
 * call, every validation) is throttled automatically, without having
 * to thread state through the SDK.
 */
export class TpmBucket {
  private readonly windowMs = 60_000;
  private history: { t: number; tokens: number }[] = [];
  private pending = new Map<number, number>();
  private nextId = 1;

  constructor(public limit: number) {}

  /** Reserve `estimate` tokens. Returns a release fn that records the
   *  actual usage once the response comes back. Call release exactly once
   *  per reserve (use a try/finally if the request can throw). */
  async reserve(estimate: number): Promise<(actual: number) => void> {
    const id = await this.acquire(estimate);
    return (actual: number) => this.release(id, actual);
  }

  private async acquire(estimate: number): Promise<number> {
    // Each iteration's check-then-set runs synchronously (no awaits
    // between the budget check and `pending.set`), so concurrent callers
    // cannot race past the cap by their own reservation amount.
    while (true) {
      this.prune();
      const used = this.sumHistory() + this.sumPending();
      if (used + estimate <= this.limit) {
        const id = this.nextId++;
        this.pending.set(id, estimate);
        return id;
      }
      await new Promise((r) => setTimeout(r, this.computeSleepMs()));
    }
  }

  private release(id: number, actualTokens: number): void {
    this.pending.delete(id);
    this.history.push({ t: Date.now(), tokens: Math.max(0, actualTokens) });
    this.prune();
  }

  private prune(): void {
    const cutoff = Date.now() - this.windowMs;
    while (this.history.length && this.history[0].t < cutoff) {
      this.history.shift();
    }
  }

  private sumHistory(): number {
    let s = 0;
    for (const e of this.history) s += e.tokens;
    return s;
  }

  private sumPending(): number {
    let s = 0;
    for (const v of this.pending.values()) s += v;
    return s;
  }

  /** Sleep until the oldest in-window entry expires, clamped to a sane
   *  range so we don't tight-loop or wait unboundedly when the window is
   *  empty (which can happen if all reservations are pending). */
  private computeSleepMs(): number {
    const oldest = this.history[0];
    if (!oldest) return 250;
    const untilFreed = oldest.t + this.windowMs - Date.now();
    return Math.max(100, Math.min(2000, untilFreed + 50));
  }
}

/**
 * Wrap fetch with TPM-aware throttling. Estimates token cost from request
 * body size, reserves against the bucket, then reconciles with actual
 * `usage.total_tokens` from the response JSON.
 *
 * Failed requests (4xx/5xx) release as 0 tokens since OpenAI does not
 * charge them against the TPM window. Streaming responses (no JSON body
 * we can read here) fall back to the estimate.
 */
export function createThrottledFetch(bucket: TpmBucket): typeof fetch {
  return async (input, init) => {
    const estimate = estimateTokens(init?.body);
    const release = await bucket.reserve(estimate);
    let response: Response;
    try {
      response = await fetch(input as RequestInfo | URL, init);
    } catch (err) {
      release(estimate);
      throw err;
    }

    if (response.status >= 400) {
      release(0);
      return response;
    }

    let actual = estimate;
    const ct = response.headers.get("content-type") ?? "";
    if (ct.includes("application/json")) {
      try {
        const cloned = response.clone();
        const json = (await cloned.json()) as { usage?: { total_tokens?: number } };
        if (typeof json?.usage?.total_tokens === "number") {
          actual = json.usage.total_tokens;
        }
      } catch {
        // Body wasn't parseable JSON — keep the estimate.
      }
    }
    release(actual);
    return response;
  };
}

/** Rough chars-to-tokens estimate with a 1.2× safety factor so we tend
 *  to over-reserve rather than under-reserve. Bodies that aren't a plain
 *  string (FormData, streams) fall back to a conservative floor. */
function estimateTokens(body: BodyInit | null | undefined): number {
  const FLOOR = 1500;
  if (typeof body !== "string") return FLOOR;
  return Math.max(FLOOR, Math.ceil((body.length / 4) * 1.2));
}
