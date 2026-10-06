// A crash and a timeout both leave the live pass without a result, but only
// the timeout is evidence: the agent spent its whole budget and found no proof.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { effectiveVerdict, type Finding, writeFileRecord } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Sandbox } from "../src/validation/sandbox.js";

const fakeSandbox: Sandbox = {
  browserEndpoint: () => "http://localhost:8931/sse",
  async exec() {
    return { code: 0, stdout: "", stderr: "" };
  },
  async readFile(path) {
    throw new Error(`no such file: ${path}`);
  },
  async writeFile() {},
  async logs() {
    return "";
  },
  async dispose() {},
};

describe("live pass without a result", () => {
  let outDir: string;
  let fetchSpy: ReturnType<typeof vi.spyOn>;
  let ceiling: () => number | null;

  beforeEach(() => {
    outDir = mkdtempSync(join(tmpdir(), "agentgg-live-crash-"));
    fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));
  });

  afterEach(() => {
    fetchSpy.mockRestore();
    rmSync(outDir, { recursive: true, force: true });
    vi.doUnmock("../src/validation/sandbox.js");
    vi.doUnmock("../src/validation/image.js");
    vi.resetModules();
  });

  async function run(
    reproduceFinding: (a: { signal: AbortSignal }) => Promise<never>,
    count = 1,
  ): Promise<Finding[]> {
    vi.doMock("../src/validation/sandbox.js", async (orig) => ({
      ...(await orig<typeof import("../src/validation/sandbox.js")>()),
      startLocalDockerSandbox: async () => fakeSandbox,
    }));
    vi.doMock("../src/validation/image.js", () => ({
      ensureSandboxImage: async () => ({ ok: true, built: false }),
    }));
    vi.resetModules();
    const { runReproducePhase } = await import("../src/validation/reproduce.js");
    ({ requestDeadlineCeilingMs: ceiling } = await import("../src/request-deadline.js"));

    const findings: Finding[] = Array.from({ length: count }, (_, i) => ({
      id: `xss-${i + 1}`,
      agentSlug: "a",
      title: "Reflected XSS on /search",
      vulnSlug: "xss",
      filePath: "src/server.ts",
      summary: "s",
      details: "d",
      poc: "p",
      impact: "i",
      references: [],
      confidence: 0.9,
      notifications: [],
      validation: { verdict: "confirmed", reasoning: "r" },
    }));
    writeFileRecord(outDir, {
      agentSlug: "a",
      filePath: "src/server.ts",
      contentHash: "h",
      findings,
      analysisHistory: [],
      candidates: [],
      status: "analyzed",
    } as never);

    await runReproducePhase({
      findings,
      // biome-ignore lint/suspicious/noExplicitAny: only reproduceFinding is exercised
      detector: { name: "fake", reproduceFinding } as any,
      outDir,
      runId: "test-run",
      targetUrl: "http://localhost:3000",
      image: "img",
      timeoutMs: 50,
      signal: new AbortController().signal,
    });
    return findings;
  }

  it("records a crash as error and keeps the static verdict", async () => {
    const [finding] = await run(async () => {
      throw new Error("MCP connection refused");
    });
    expect(finding.live?.result).toBe("error");
    expect(effectiveVerdict(finding)).toBe("confirmed");
  });

  it("records a timeout as inconclusive and demotes a static confirm", async () => {
    const [finding] = await run(
      ({ signal }) =>
        new Promise<never>((_, reject) => {
          signal.addEventListener("abort", () => reject(new Error("aborted")));
        }),
    );
    expect(finding.live?.result).toBe("inconclusive");
    expect(finding.live?.reasoning).toMatch(/timed out/);
    expect(effectiveVerdict(finding)).toBe("uncertain");
  });

  // The ceiling is what stops one stalled request from spending the whole
  // per-finding budget, so the phase must install it and lift it again.
  it("installs the live request ceiling while a finding runs and lifts it after", async () => {
    let seen: number | null = -1;
    await run(async () => {
      seen = ceiling();
      throw new Error("stop here");
    });
    expect(seen).toBe(50);
    expect(ceiling()).toBeNull();
  });

  // A detector that ignores its abort signal must not strand the pass: the
  // timer alone has to settle the finding and release the loop.
  it("times out a detector that never settles and still runs the next finding", async () => {
    const findings = await run(() => new Promise<never>(() => {}), 2);
    expect(findings.map((f) => f.live?.result)).toEqual(["inconclusive", "inconclusive"]);
    expect(findings[1]?.live?.reasoning).toMatch(/timed out/);
  });
});
