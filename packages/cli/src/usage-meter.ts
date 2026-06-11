import { type LlmUsage, readUsage, type ScanUsage, writeUsage } from "@agentgg/core";

/**
 * LLM token-usage metering.
 *
 * A flat, invocation-scoped accumulator the detector records every LLM
 * response into. It checkpoints to `<outputDir>/state/usage.json` as the run
 * proceeds — debounced during normal operation, and synchronously on demand
 * (`flush()`) from the orchestrator's shutdown handler and finalize path. The
 * incremental write means a run cancelled or killed mid-flight still leaves an
 * accurate tally of the tokens it spent on disk.
 *
 * Deliberately flat — no per-phase or per-slug breakdown. Each CLI invocation
 * (recon / each agent run / dedup / …) writes its own usage.json; a consumer
 * that wants a scan-wide figure sums them. See the ScanUsage doc comment in
 * @agentgg/core for the rationale.
 *
 * The meter holds raw token counts only — no pricing. The CLI doesn't bill
 * anything (you bring your own model/key); usage.json is just an observability
 * surface for whoever reads it.
 */

/** One LLM response's token counts, normalized across providers. */
export interface CallUsage {
  inputTokens: number;
  outputTokens: number;
  /** Subset of inputTokens served from prompt cache (0 when not reported). */
  cachedInputTokens: number;
}

/** How long to coalesce records before a background checkpoint write. */
const FLUSH_DEBOUNCE_MS = 1500;

export class UsageMeter {
  private readonly totals: LlmUsage = blankUsage();
  private model: string | undefined;
  private dirty = false;
  private timer: NodeJS.Timeout | undefined;

  /**
   * @param outDir   scan output dir (usage.json lives under its `state/`).
   * @param provider detector name the tokens are billed against.
   * @param seed     prior ledger (from `readUsage`) so a resumed/retried run
   *                 preserves earlier totals instead of restarting from zero.
   */
  constructor(
    private readonly outDir: string,
    private readonly provider: string,
    seed?: ScanUsage | null,
  ) {
    if (seed) {
      addUsage(this.totals, seed.totals);
      this.model = seed.model;
    }
  }

  /** Fold one LLM response into the running totals and schedule a checkpoint. */
  record(usage: CallUsage, model?: string): void {
    if (model) this.model = model;
    this.totals.inputTokens += usage.inputTokens;
    this.totals.outputTokens += usage.outputTokens;
    this.totals.cachedInputTokens += usage.cachedInputTokens;
    this.totals.calls += 1;
    this.dirty = true;
    this.scheduleFlush();
  }

  /**
   * Write the current ledger to disk now, synchronously. Idempotent and
   * best-effort — safe to call from a SIGINT/SIGTERM handler (the underlying
   * write is a synchronous atomic temp+rename). A no-op when nothing changed
   * since the last flush.
   */
  flush(): void {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
    if (!this.dirty) return;
    try {
      writeUsage(this.outDir, this.snapshot());
      this.dirty = false;
    } catch {
      // Best-effort: a failed checkpoint leaves the prior usage.json in place
      // and the next flush retries. Never let metering break a scan.
    }
  }

  /** Current totals (a copy). */
  totalsSnapshot(): LlmUsage {
    return { ...this.totals };
  }

  private snapshot(): ScanUsage {
    return {
      provider: this.provider,
      model: this.model,
      totals: { ...this.totals },
      updatedAt: new Date().toISOString(),
    };
  }

  private scheduleFlush(): void {
    if (this.timer) return;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      this.flush();
    }, FLUSH_DEBOUNCE_MS);
    // Don't keep the event loop alive for a pending checkpoint — finalize and
    // the shutdown handler both force a synchronous flush, so an unref'd timer
    // never strands data.
    this.timer.unref?.();
  }
}

/**
 * Read any existing ledger for `outDir` and build a meter seeded from it, so a
 * retried CLI invocation in the same state dir continues the total instead of
 * resetting. Convenience wrapper so callers don't import `readUsage` too.
 */
export function createUsageMeter(outDir: string, provider: string): UsageMeter {
  return new UsageMeter(outDir, provider, readUsage(outDir));
}

function blankUsage(): LlmUsage {
  return { inputTokens: 0, outputTokens: 0, cachedInputTokens: 0, calls: 0 };
}

function addUsage(target: LlmUsage, u: LlmUsage): void {
  target.inputTokens += u.inputTokens;
  target.outputTokens += u.outputTokens;
  target.cachedInputTokens += u.cachedInputTokens;
  target.calls += u.calls;
}
