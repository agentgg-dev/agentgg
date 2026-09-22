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

  async function run(reproduceFinding: (a: { signal: AbortSignal }) => Promise<never>) {
    vi.doMock("../src/validation/sandbox.js", async (orig) => ({
      ...(await orig<typeof import("../src/validation/sandbox.js")>()),
      startLocalDockerSandbox: async () => fakeSandbox,
    }));
    vi.doMock("../src/validation/image.js", () => ({
      ensureSandboxImage: async () => ({ ok: true, built: false }),
    }));
    vi.resetModules();
    const { runReproducePhase } = await import("../src/validation/reproduce.js");

    const finding: Finding = {
      id: "xss-1",
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
    };
    writeFileRecord(outDir, {
      agentSlug: finding.agentSlug,
      filePath: finding.filePath,
      contentHash: "h",
      findings: [finding],
      analysisHistory: [],
      candidates: [],
      status: "analyzed",
    } as never);

    await runReproducePhase({
      findings: [finding],
      // biome-ignore lint/suspicious/noExplicitAny: only reproduceFinding is exercised
      detector: { name: "fake", reproduceFinding } as any,
      outDir,
      runId: "test-run",
      targetUrl: "http://localhost:3000",
      auth: {},
      image: "img",
      timeoutMs: 50,
      budgetMs: 60_000,
      max: 10,
      signal: new AbortController().signal,
    });
    return finding;
  }

  it("records a crash as error and keeps the static verdict", async () => {
    const finding = await run(async () => {
      throw new Error("MCP connection refused");
    });
    expect(finding.live?.result).toBe("error");
    expect(effectiveVerdict(finding)).toBe("confirmed");
  });

  it("records a timeout as inconclusive and demotes a static confirm", async () => {
    const finding = await run(
      ({ signal }) =>
        new Promise<never>((_, reject) => {
          signal.addEventListener("abort", () => reject(new Error("aborted")));
        }),
    );
    expect(finding.live?.result).toBe("inconclusive");
    expect(finding.live?.reasoning).toMatch(/timed out/);
    expect(effectiveVerdict(finding)).toBe("uncertain");
  });
});
