import { describe, expect, it } from "vitest";
import { runConcurrent } from "../src/concurrent.js";

describe("runConcurrent", () => {
  it("processes every item in order-independent fashion", async () => {
    const items = ["a", "b", "c", "d", "e"];
    const processed: string[] = [];
    await runConcurrent(items, 2, async (item) => {
      processed.push(item);
    });
    expect(processed.sort()).toEqual([...items].sort());
  });

  it("is a no-op for an empty array", async () => {
    const fn = async () => {
      throw new Error("should never run");
    };
    await expect(runConcurrent([], 5, fn)).resolves.toBeUndefined();
  });

  it("clamps limit to at least 1", async () => {
    const items = ["a", "b"];
    const seen: string[] = [];
    await runConcurrent(items, 0, async (item) => {
      seen.push(item);
    });
    expect(seen.sort()).toEqual(["a", "b"]);
  });

  it("caps active workers at `limit`", async () => {
    let inFlight = 0;
    let peak = 0;
    const items = Array.from({ length: 20 }, (_, i) => i);
    await runConcurrent(items, 3, async () => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight--;
    });
    expect(peak).toBeLessThanOrEqual(3);
    expect(peak).toBeGreaterThan(1); // proof we actually parallelised
  });

  it("never starts more workers than items even if limit is larger", async () => {
    let started = 0;
    await runConcurrent(["only-one"], 10, async () => {
      started++;
    });
    expect(started).toBe(1);
  });

  it("rejects when fn throws (caller is responsible for catching)", async () => {
    await expect(
      runConcurrent([1, 2, 3], 2, async (n) => {
        if (n === 2) throw new Error("boom");
      }),
    ).rejects.toThrow(/boom/);
  });

  it("parallel execution finishes faster than sequential", async () => {
    const items = Array.from({ length: 8 }, (_, i) => i);
    const delay = 30;

    const sequentialStart = Date.now();
    await runConcurrent(items, 1, async () => {
      await new Promise((r) => setTimeout(r, delay));
    });
    const sequentialMs = Date.now() - sequentialStart;

    const parallelStart = Date.now();
    await runConcurrent(items, 4, async () => {
      await new Promise((r) => setTimeout(r, delay));
    });
    const parallelMs = Date.now() - parallelStart;

    // With 4× parallelism we expect at least ~2× speedup. Generous
    // margin since setTimeout precision varies on Windows CI runners.
    expect(parallelMs).toBeLessThan(sequentialMs / 1.5);
  });
});
