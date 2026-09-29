// The reproduce phase must attach to an already-running sandbox instead of
// starting Docker when the caller passes `attach`, and it must leave a
// localhost target URL untouched (there is no container to redirect into).
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Finding, writeFileRecord } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Sandbox } from "../src/validation/sandbox.js";

const sandbox: Sandbox = {
  browserEndpoint: () => "http://127.0.0.1:8931/sse",
  async exec() {
    return { code: 0, stdout: "", stderr: "" };
  },
  async readFile() {
    throw new Error("no such file");
  },
  async writeFile() {},
  async logs() {
    return "";
  },
  async dispose() {},
};

const started: string[] = [];
vi.mock("../src/validation/sandbox.js", async (orig) => ({
  ...(await orig<typeof import("../src/validation/sandbox.js")>()),
  startLocalDockerSandbox: async () => {
    started.push("local");
    return sandbox;
  },
  startAttachedSandbox: async () => {
    started.push("attached");
    return sandbox;
  },
}));

const ensure = vi.fn(async () => ({ ok: true, built: false }));
vi.mock("../src/validation/image.js", () => ({ ensureSandboxImage: ensure }));

const { runReproducePhase } = await import("../src/validation/reproduce.js");

const finding = (id: string, slug: string): Finding =>
  ({
    id,
    agentSlug: slug,
    title: `finding ${id}`,
    vulnSlug: "xss",
    filePath: "src/server.ts",
    summary: "s",
    details: "d",
    poc: "p",
    impact: "i",
    references: [],
    confidence: 0.9,
    notifications: [],
  }) as Finding;

describe("runReproducePhase with an attached sandbox", () => {
  let outDir: string;
  let fetchSpy: ReturnType<typeof vi.spyOn>;
  let detectorCalls: Array<{ baseUrl: string }>;
  let baseArgs: {
    findings: Finding[];
    // biome-ignore lint/suspicious/noExplicitAny: only reproduceFinding is exercised
    detector: any;
    outDir: string;
    runId: string;
    auth: Record<string, never>;
    image: string;
    timeoutMs: number;
    signal: AbortSignal;
  };

  beforeEach(() => {
    started.length = 0;
    ensure.mockClear();
    outDir = mkdtempSync(join(tmpdir(), "agentgg-attach-"));
    fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));

    const a = finding("aaa", "agent-a");
    writeFileRecord(outDir, {
      agentSlug: a.agentSlug,
      filePath: a.filePath,
      contentHash: "h",
      findings: [a],
      analysisHistory: [],
      candidates: [],
      status: "analyzed",
    } as never);

    detectorCalls = [];
    const detector = {
      name: "fake",
      async reproduceFinding(args: { baseUrl: string }) {
        detectorCalls.push({ baseUrl: args.baseUrl });
        return { result: "inconclusive" as const, reasoning: "r", counterevidence: "" };
      },
    };

    baseArgs = {
      findings: [a],
      detector,
      outDir,
      runId: "test-run",
      auth: {},
      image: "img",
      timeoutMs: 30_000,
      signal: new AbortController().signal,
    };
  });

  afterEach(() => {
    fetchSpy.mockRestore();
    rmSync(outDir, { recursive: true, force: true });
  });

  it("uses the attached sandbox, skips the image preflight, and keeps localhost targets as given", async () => {
    await runReproducePhase({
      ...baseArgs,
      targetUrl: "http://localhost:3000",
      attach: {
        endpoint: "http://127.0.0.1:8931",
        controlUrl: "http://127.0.0.1:8932",
        token: "tk",
      },
    });
    expect(started).toEqual(["attached"]);
    expect(ensure).not.toHaveBeenCalled();
    expect(detectorCalls[0].baseUrl).toBe("http://localhost:3000");
  });

  it("uses the local docker sandbox and the image preflight when not attaching", async () => {
    await runReproducePhase({
      ...baseArgs,
      targetUrl: "http://localhost:3000",
    });
    expect(started).toEqual(["local"]);
    expect(ensure).toHaveBeenCalledTimes(1);
    expect(detectorCalls[0].baseUrl).toBe("http://host.docker.internal:3000/");
  });
});
