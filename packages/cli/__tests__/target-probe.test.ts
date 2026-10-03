import { afterEach, describe, expect, it, vi } from "vitest";
import { probeTarget } from "../src/validation/reproduce";

const TARGET = "https://target.example";

function networkError(code: string): TypeError {
  const cause = Object.assign(new Error(`connect ${code} 203.0.113.7:443`), { code });
  return new TypeError("fetch failed", { cause });
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("probeTarget", () => {
  it("counts any HTTP answer at once", async () => {
    const fetchMock = vi.fn(async () => new Response("down for maintenance", { status: 503 }));
    vi.stubGlobal("fetch", fetchMock);

    expect(await probeTarget(TARGET)).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("asks again after a network error and logs its code", async () => {
    vi.useFakeTimers();
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    let tries = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        tries++;
        if (tries < 3) throw networkError("ETIMEDOUT");
        return new Response("<html></html>");
      }),
    );

    const answered = probeTarget(TARGET);
    await vi.advanceTimersByTimeAsync(20_000);

    expect(await answered).toBe(true);
    expect(tries).toBe(3);
    const lines = log.mock.calls.map((args) => args.map(String).join(" "));
    expect(lines.filter((l) => l.includes("(ETIMEDOUT)"))).toHaveLength(2);
    expect(lines.some((l) => l.includes("203.0.113.7"))).toBe(false);
  });

  it("gives up when nothing answers for a minute", async () => {
    vi.useFakeTimers();
    vi.spyOn(console, "log").mockImplementation(() => {});
    const askedAt: number[] = [];
    // Never answers; like `fetch`, it rejects when its signal aborts.
    vi.stubGlobal(
      "fetch",
      vi.fn((_url: string, init?: RequestInit) => {
        askedAt.push(Date.now());
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("aborted")), {
            once: true,
          });
        });
      }),
    );

    const answered = probeTarget(TARGET);
    await vi.advanceTimersByTimeAsync(300_000);

    expect(await answered).toBe(false);
    expect(askedAt.at(-1)! - askedAt[0]).toBe(60_000);
  });
});
