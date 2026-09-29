// The sandbox is started once per phase and /out is shared, so each finding's
// evidence must be isolated from the previous finding's artifacts.
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Finding, getEvidenceDir, writeFileRecord } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Sandbox } from "../src/validation/sandbox.js";

/** /out, shared across findings exactly as the real container's is. */
const out = new Map<string, Buffer>();

/** Set by the failed-replay-warning test to control what the (real,
 *  unmocked) repro-script runner sees from `npx playwright test`. */
let playwrightResult: { code: number; stdout: string; stderr: string } | undefined;

const sandbox: Sandbox = {
  browserEndpoint: () => "http://localhost:8931/sse",
  async exec(cmd) {
    const line = cmd.join(" ");
    if (line.startsWith("ls -1t /out")) {
      const names = [...out.keys()].map((p) => p.slice("/out/".length));
      return { code: 0, stdout: `${names.reverse().join("\n")}\n`, stderr: "" };
    }
    if (line.includes("find /out/traces")) return { code: 1, stdout: "", stderr: "" };
    if (line.includes("rm -rf")) {
      out.clear();
      return { code: 0, stdout: "", stderr: "" };
    }
    if (line.startsWith("npx playwright test") && playwrightResult) return playwrightResult;
    return { code: 0, stdout: "", stderr: "" };
  },
  async readFile(path) {
    const buf = out.get(path);
    if (!buf) throw new Error(`no such file: ${path}`);
    return buf;
  },
  async writeFile() {},
  async logs() {
    return "";
  },
  async dispose() {},
};

vi.mock("../src/validation/sandbox.js", async (orig) => ({
  ...(await orig<typeof import("../src/validation/sandbox.js")>()),
  startLocalDockerSandbox: async () => sandbox,
}));

vi.mock("../src/validation/image.js", () => ({
  ensureSandboxImage: async () => ({ ok: true, built: false }),
}));

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

describe("evidence isolation between findings", () => {
  let outDir: string;
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    out.clear();
    playwrightResult = undefined;
    outDir = mkdtempSync(join(tmpdir(), "agentgg-iso-"));
    fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));
  });
  afterEach(() => {
    fetchSpy.mockRestore();
    rmSync(outDir, { recursive: true, force: true });
  });

  it("does not copy an earlier finding's video into a later finding's evidence", async () => {
    const a = finding("aaa", "agent-a");
    const b = finding("bbb", "agent-b");
    for (const f of [a, b]) {
      writeFileRecord(outDir, {
        agentSlug: f.agentSlug,
        filePath: f.filePath,
        contentHash: "h",
        findings: [f],
        analysisHistory: [],
        candidates: [],
        status: "analyzed",
      } as never);
    }

    let call = 0;
    const detector = {
      name: "fake",
      async reproduceFinding() {
        call++;
        // Playwright writes the session video into the shared /out.
        out.set(`/out/page-${call}.webm`, Buffer.from(`video ${call}`));
        return {
          result: "reproduced" as const,
          reasoning: "r",
          counterevidence: "",
          script: "// repro",
        };
      },
    };

    await runReproducePhase({
      findings: [a, b],
      // biome-ignore lint/suspicious/noExplicitAny: only reproduceFinding is exercised
      detector: detector as any,
      outDir,
      runId: "test-run",
      targetUrl: "http://localhost:3000",
      auth: {},
      image: "img",
      timeoutMs: 30_000,
      signal: new AbortController().signal,
    });

    const dirA = getEvidenceDir(outDir, a.agentSlug, a.id);
    const dirB = getEvidenceDir(outDir, b.agentSlug, b.id);

    expect(existsSync(join(dirA, "page-1.webm"))).toBe(true);
    expect(existsSync(join(dirB, "page-2.webm"))).toBe(true);
    // The leak: without clearing /out, finding B inherits A's recording.
    expect(existsSync(join(dirB, "page-1.webm"))).toBe(false);
    expect(b.live?.evidence?.video).toBe("page-2.webm");
  });

  it("does not carry a reproduced finding's artifacts into a refuted one", async () => {
    const a = finding("aaa", "agent-a");
    const b = finding("bbb", "agent-b");
    for (const f of [a, b]) {
      writeFileRecord(outDir, {
        agentSlug: f.agentSlug,
        filePath: f.filePath,
        contentHash: "h",
        findings: [f],
        analysisHistory: [],
        candidates: [],
        status: "analyzed",
      } as never);
    }

    let call = 0;
    const detector = {
      name: "fake",
      async reproduceFinding() {
        call++;
        out.set(`/out/page-${call}.webm`, Buffer.from(`video ${call}`));
        out.set(`/out/shot-${call}.png`, Buffer.from(`png ${call}`));
        return call === 1
          ? { result: "reproduced" as const, reasoning: "r", counterevidence: "", script: "// s" }
          : { result: "refuted" as const, reasoning: "r", counterevidence: "", script: "// n" };
      },
    };

    await runReproducePhase({
      findings: [a, b],
      // biome-ignore lint/suspicious/noExplicitAny: only reproduceFinding is exercised
      detector: detector as any,
      outDir,
      runId: "test-run",
      targetUrl: "http://localhost:3000",
      auth: {},
      image: "img",
      timeoutMs: 30_000,
      signal: new AbortController().signal,
    });

    const dirB = getEvidenceDir(outDir, b.agentSlug, b.id);
    expect(existsSync(join(dirB, "shot-2.png"))).toBe(true);
    expect(existsSync(join(dirB, "shot-1.png"))).toBe(false);
    // The refuted path drops every video, this finding's included.
    expect(existsSync(join(dirB, "page-2.webm"))).toBe(false);
    expect(b.live?.evidence?.video).toBeUndefined();
  });

  it("forwards the configured turn cap to the detector", async () => {
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

    let seen: number | undefined;
    const detector = {
      name: "fake",
      async reproduceFinding(args: { maxTurns?: number }) {
        seen = args.maxTurns;
        return { result: "inconclusive" as const, reasoning: "r", counterevidence: "" };
      },
    };

    await runReproducePhase({
      findings: [a],
      // biome-ignore lint/suspicious/noExplicitAny: only reproduceFinding is exercised
      detector: detector as any,
      outDir,
      runId: "test-run",
      targetUrl: "http://localhost:3000",
      auth: {},
      image: "img",
      timeoutMs: 30_000,
      reproduceMaxTurns: 75,
      signal: new AbortController().signal,
    });

    expect(seen).toBe(75);
  });

  it("redacts the target password from the failed-replay warning", async () => {
    const pw = "hunter2secret";
    playwrightResult = { code: 1, stdout: `password leaked: ${pw}\n1 failed`, stderr: "" };
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

    const detector = {
      name: "fake",
      async reproduceFinding() {
        // A video in /out lets the copy skip its wait for one to appear.
        out.set("/out/page-1.webm", Buffer.from("video"));
        return {
          result: "reproduced" as const,
          reasoning: "r",
          counterevidence: "",
          script: "// s",
        };
      },
    };

    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      await runReproducePhase({
        findings: [a],
        // biome-ignore lint/suspicious/noExplicitAny: only reproduceFinding is exercised
        detector: detector as any,
        outDir,
        runId: "test-run",
        targetUrl: "http://localhost:3000",
        auth: { username: "alice", password: pw },
        image: "img",
        timeoutMs: 30_000,
        signal: new AbortController().signal,
      });
      const warned = warnSpy.mock.calls.map((c) => c.join(" ")).join("\n");
      expect(warned).toContain("***");
      expect(warned).not.toContain(pw);
    } finally {
      warnSpy.mockRestore();
    }
  });
});
