/**
 * Tests for the rolling TPM budget.
 *
 *   - A request whose estimate exceeds the whole budget must still run.
 *     Before the clamp it waited on `used + estimate <= limit`, which can
 *     never hold, so recon sat at ~1% CPU forever.
 *   - Requests that fit are admitted immediately.
 *   - `createThrottledFetch` warns when the account's real cap is far
 *     above the configured bucket.
 */
import { describe, expect, it, vi } from "vitest";
import { createThrottledFetch, resolveTpmLimit, TpmBucket } from "../src/tpm-bucket.js";

describe("resolveTpmLimit", () => {
  const opts = { label: "openai", envVar: "AGENTGG_OPENAI_TPM" };

  function resolve(raw: string | undefined) {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const result = resolveTpmLimit(raw, 30_000, opts);
    const messages = warn.mock.calls.map((c) => String(c[0]));
    warn.mockRestore();
    return { ...result, messages };
  }

  it("uses the fallback when unset or empty", () => {
    expect(resolve(undefined)).toMatchObject({ limit: 30_000, pinned: false, messages: [] });
    expect(resolve("")).toMatchObject({ limit: 30_000, pinned: false, messages: [] });
  });

  it("pins a number the user set", () => {
    expect(resolve("40000000")).toMatchObject({ limit: 40_000_000, pinned: true });
    expect(resolve("0")).toMatchObject({ limit: 0, pinned: true });
  });

  it("warns and falls back on junk instead of disabling the throttle in silence", () => {
    for (const junk of ["abc", "30k", "-5", "1.5", "30000abc"]) {
      const r = resolve(junk);
      expect(r.limit, junk).toBe(30_000);
      expect(r.pinned, junk).toBe(false);
      expect(r.messages[0], junk).toContain("AGENTGG_OPENAI_TPM");
    }
  });
});

describe("TpmBucket", () => {
  it("admits a request that fits", async () => {
    const bucket = new TpmBucket(30_000);
    const release = await bucket.reserve(1_500);
    release(1_400);
  });

  it("admits an oversized request instead of waiting forever", async () => {
    const bucket = new TpmBucket(30_000);
    // 120k estimated tokens against a 30k budget: unsatisfiable before the fix.
    const release = await Promise.race([
      bucket.reserve(120_000),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("stalled")), 5_000)),
    ]);
    release(120_000);
  });

  it("serialises an oversized request behind in-flight work", async () => {
    const bucket = new TpmBucket(30_000);
    const first = await bucket.reserve(20_000);
    let admitted = false;
    const second = bucket.reserve(120_000).then((r) => {
      admitted = true;
      return r;
    });
    await new Promise((r) => setTimeout(r, 300));
    expect(admitted).toBe(false);
    first(0);
    (await second)(0);
    expect(admitted).toBe(true);
  });
});

describe("createThrottledFetch", () => {
  /** Drive `calls` requests through the wrapper against a stub that returns
   *  `header` as x-ratelimit-limit-tokens. Returns the stderr lines. */
  async function run(bucket: TpmBucket, pinned: boolean, header: string, calls = 2) {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const original = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response("{}", {
        status: 200,
        headers: {
          "content-type": "application/json",
          "x-ratelimit-limit-tokens": header,
        },
      })) as typeof fetch;
    try {
      const throttled = createThrottledFetch(bucket, {
        label: "openai",
        envVar: "AGENTGG_OPENAI_TPM",
        pinned,
      });
      for (let i = 0; i < calls; i++) {
        await throttled("https://api.openai.com/v1/chat/completions", { body: "hi" });
      }
    } finally {
      globalThis.fetch = original;
    }
    // Read the calls before restore: mockRestore also clears the history.
    // [WARN] and [INFO]-on-stderr both land here; warn first keeps ordering stable.
    const messages = [...warn.mock.calls, ...err.mock.calls].map((c) => String(c[0]));
    warn.mockRestore();
    err.mockRestore();
    return messages;
  }

  it("adopts the account limit from the first response", async () => {
    const bucket = new TpmBucket(30_000);
    const messages = await run(bucket, false, "40000000");
    expect(bucket.limit).toBe(40_000_000);
    // Announced once, not once per request.
    expect(messages.filter((m) => m.includes("40000000"))).toHaveLength(1);
  });

  it("lowers the throttle when the account allows less than the default", async () => {
    const bucket = new TpmBucket(30_000);
    await run(bucket, false, "10000");
    expect(bucket.limit).toBe(10_000);
  });

  it("keeps a hand-set limit but warns when it is far too low", async () => {
    const bucket = new TpmBucket(30_000);
    const messages = await run(bucket, true, "40000000");
    expect(bucket.limit).toBe(30_000);
    expect(messages[0]).toContain("AGENTGG_OPENAI_TPM");
  });

  it("retries adoption after a header it cannot parse", async () => {
    const bucket = new TpmBucket(30_000);
    // A malformed first header must not latch the run at the starting value.
    await run(bucket, false, "unlimited", 1);
    expect(bucket.limit).toBe(30_000);
    await run(bucket, false, "40000000", 1);
    expect(bucket.limit).toBe(40_000_000);
  });

  it("keeps the starting value when no header comes back", async () => {
    const bucket = new TpmBucket(30_000);
    const original = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response("{}", {
        status: 200,
        headers: { "content-type": "application/json" },
      })) as typeof fetch;
    try {
      const throttled = createThrottledFetch(bucket, {
        label: "openai",
        envVar: "AGENTGG_OPENAI_TPM",
        pinned: false,
      });
      await throttled("https://api.openai.com/v1/chat/completions", { body: "hi" });
    } finally {
      globalThis.fetch = original;
    }
    expect(bucket.limit).toBe(30_000);
  });
});
