/**
 * Rolling 60-second tokens-per-minute budget shared across concurrent
 * workers. Each caller reserves an estimated token cost before its
 * request, then reconciles with actual usage from the response. When
 * the bucket is full, callers sleep until enough budget falls out of
 * the rolling window.
 *
 * Designed to be installed below the AI SDK by wrapping `fetch` — that
 * way every HTTP call (each step of an agent's tool loop, every
 * structured-output call, every validation) is throttled automatically,
 * without having to thread state through the SDK.
 */
import { logInfo, logWarn } from "./log.js";
export class TpmBucket {
  private readonly windowMs = 60_000;
  private history: { t: number; tokens: number }[] = [];
  private pending = new Map<number, number>();
  private nextId = 1;
  /** Set once the first response's rate-limit header has been inspected. */
  observedChecked = false;

  constructor(public limit: number) {}

  /** Reserve `estimate` tokens. Returns a release fn that records the
   *  actual usage once the response comes back. Call release exactly once
   *  per reserve (use a try/finally if the request can throw). */
  async reserve(estimate: number): Promise<(actual: number) => void> {
    const id = await this.acquire(estimate);
    return (actual: number) => this.release(id, actual);
  }

  private async acquire(estimate: number): Promise<number> {
    // A single body can estimate above the whole minute budget (tool-loop
    // history grows every turn), and `used + estimate <= limit` would then
    // never hold — the caller would sleep forever. Clamp the reservation so
    // an oversized request waits for a clear window instead, and give it a
    // deadline so steady small traffic cannot starve it indefinitely.
    const need = Math.min(estimate, this.limit);
    const deadline = need >= this.limit ? Date.now() + this.windowMs * 2 : Number.POSITIVE_INFINITY;
    // Each iteration's check-then-set runs synchronously (no awaits
    // between the budget check and `pending.set`), so concurrent callers
    // cannot race past the cap by their own reservation amount.
    while (true) {
      this.prune();
      const used = this.sumHistory() + this.sumPending();
      if (used + need <= this.limit || Date.now() >= deadline) {
        const id = this.nextId++;
        this.pending.set(id, need);
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
 * Read a TPM knob from the environment. Every path is spoken out loud on
 * stderr, so a slow or stalled run is self-diagnosing: an unreadable value
 * falls back to `fallback` with a warning rather than turning the throttle
 * off in silence. An unset or empty variable means "not configured".
 */
export function resolveTpmLimit(
  raw: string | undefined,
  fallback: number,
  opts: { label: string; envVar: string },
): { limit: number; pinned: boolean } {
  const trimmed = raw?.trim();
  if (!trimmed) return { limit: fallback, pinned: false };
  if (!/^\d+$/.test(trimmed)) {
    logWarn(
      `[${opts.label}] ${opts.envVar}="${trimmed}" is not a whole number of tokens. ` +
        `Using ${fallback} TPM instead. Set a number, or 0 to disable throttling.`,
    );
    return { limit: fallback, pinned: false };
  }
  return { limit: Number.parseInt(trimmed, 10), pinned: true };
}

/** Print the effective throttle once, on stderr, so a stalled or slow run
 *  is self-diagnosing instead of looking like a hung process. */
export function announceThrottle(opts: ThrottleLabels, limit: number): void {
  if (limit <= 0) {
    logInfo(`[${opts.label}] token throttling is off (${opts.envVar}=0)`, "err");
    return;
  }
  const source = opts.pinned
    ? `set by ${opts.envVar}`
    : `starting value, ${opts.envVar} overrides; 0 disables`;
  logInfo(`[${opts.label}] throttling to ${limit} TPM (${source})`, "err");
}

/**
 * Adopt the account's real cap from the first response. Providers return
 * `x-ratelimit-limit-tokens` on every call, so the true limit costs nothing
 * to learn and beats any default we could ship. A limit the user set by
 * hand wins: we only warn when it is far below what the account allows.
 */
function adoptObservedLimit(bucket: TpmBucket, response: Response, opts: ThrottleLabels): void {
  if (bucket.observedChecked) return;
  const raw = response.headers.get("x-ratelimit-limit-tokens");
  if (!raw) return;
  const observed = Number.parseInt(raw, 10);
  // Only latch once a usable value arrives. Latching on a header we could
  // not parse would pin the whole run to the starting value.
  if (!Number.isFinite(observed) || observed <= 0) return;
  bucket.observedChecked = true;

  if (opts.pinned) {
    if (observed > bucket.limit * 4) {
      logWarn(
        `[${opts.label}] ${opts.envVar} throttles to ${bucket.limit} TPM, but this account allows ${observed} TPM. ` +
          `Scans will be much slower than they need to be. Unset ${opts.envVar} to use the account limit.`,
      );
    }
    return;
  }
  if (observed === bucket.limit) return;
  const verb = observed > bucket.limit ? "raising" : "lowering";
  bucket.limit = observed;
  logInfo(`[${opts.label}] account limit is ${observed} TPM; ${verb} the throttle to match`, "err");
}

export interface ThrottleLabels {
  label: string;
  envVar: string;
  /** True when the user set the limit by hand. Then we never change it. */
  pinned: boolean;
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
export function createThrottledFetch(bucket: TpmBucket, labels?: ThrottleLabels): typeof fetch {
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

    if (labels) adoptObservedLimit(bucket, response, labels);

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
