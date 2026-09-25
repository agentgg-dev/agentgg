// A refuted verdict is a positive claim: the sink did not fire, and here is
// the negative control. So it keeps its artifacts, minus the video, whose
// value is the "watch the alert fire" moment a refutation does not have.

import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Finding, getEvidenceDir, writeFileRecord } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Sandbox } from "../src/validation/sandbox.js";

/** /out, as the shared container directory the phase copies from. */
const out = new Map<string, Buffer>();

const sandbox: Sandbox = {
  browserEndpoint: () => "http://localhost:8931/sse",
  async exec(cmd) {
    const line = cmd.join(" ");
    if (line.startsWith("ls -1t /out")) {
      const names = [...out.keys()]
        .filter((p) => !p.slice("/out/".length).includes("/"))
        .map((p) => p.slice("/out/".length));
      return { code: 0, stdout: `${names.reverse().join("\n")}\n`, stderr: "" };
    }
    if (line.includes("find /out/traces")) {
      const hits = [...out.keys()].filter((p) => p.startsWith("/out/traces/"));
      if (hits.length === 0) return { code: 1, stdout: "", stderr: "" };
      return { code: 0, stdout: `${hits.join("\n")}\n`, stderr: "" };
    }
    if (line.includes("rm -rf")) {
      out.clear();
      return { code: 0, stdout: "", stderr: "" };
    }
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

/** Scripts handed to the replay runner. A refuted run must leave this empty. */
const replayed: string[] = [];
vi.mock("../src/validation/repro-script.js", () => ({
  runReproScript: async (_sb: Sandbox, script: string) => {
    replayed.push(script);
    return { path: "repro.spec.ts", executed: true, passed: true, output: "1 passed" };
  },
}));

const { runReproducePhase } = await import("../src/validation/reproduce.js");

const finding = (id: string): Finding =>
  ({
    id,
    agentSlug: "agent-a",
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

/** What a Playwright session leaves in /out for one finding. */
function sessionArtifacts(): void {
  out.set("/out/page-1.webm", Buffer.from("recording"));
  out.set("/out/shot-1.png", Buffer.from("png one"));
  out.set("/out/shot-2.png", Buffer.from("png two"));
  out.set("/out/traces/trace-1.trace", Buffer.from("trace events"));
  out.set(
    "/out/traces/trace-1.network",
    Buffer.from(
      JSON.stringify({
        type: "resource-snapshot",
        snapshot: {
          request: { method: "GET", url: "http://app/notes/2", headers: [] },
          response: { status: 403, headers: [] },
        },
      }),
    ),
  );
}

async function runPhase(
  outDir: string,
  f: Finding,
  reproduceFinding: () => Promise<unknown>,
): Promise<void> {
  writeFileRecord(outDir, {
    agentSlug: f.agentSlug,
    filePath: f.filePath,
    contentHash: "h",
    findings: [f],
    analysisHistory: [],
    candidates: [],
    status: "analyzed",
  } as never);

  await runReproducePhase({
    findings: [f],
    // biome-ignore lint/suspicious/noExplicitAny: only reproduceFinding is exercised
    detector: { name: "fake", reproduceFinding } as any,
    outDir,
    runId: "test-run",
    targetUrl: "http://localhost:3000",
    auth: {},
    image: "img",
    timeoutMs: 30_000,
    budgetMs: 60_000,
    max: 10,
    signal: new AbortController().signal,
  });
}

describe("evidence for a refuted finding", () => {
  let outDir: string;
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    out.clear();
    replayed.length = 0;
    outDir = mkdtempSync(join(tmpdir(), "agentgg-refuted-"));
    fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));
  });
  afterEach(() => {
    fetchSpy.mockRestore();
    rmSync(outDir, { recursive: true, force: true });
  });

  const refutes = async () => {
    sessionArtifacts();
    return {
      result: "refuted" as const,
      reasoning: "r",
      counterevidence: "",
      script: "// negative control",
    };
  };

  it("keeps the trace, the screenshots and the requests", async () => {
    const f = finding("aaa");
    await runPhase(outDir, f, refutes);

    const dir = getEvidenceDir(outDir, f.agentSlug, f.id);
    expect(existsSync(join(dir, "trace.zip"))).toBe(true);
    expect(existsSync(join(dir, "shot-1.png"))).toBe(true);
    expect(existsSync(join(dir, "requests.http"))).toBe(true);
    expect(f.live?.result).toBe("refuted");
    expect(f.live?.evidence?.trace).toBe("trace.zip");
    expect(f.live?.evidence?.screenshots?.sort()).toEqual(["shot-1.png", "shot-2.png"]);
    expect(f.live?.evidence?.requests).toEqual([
      { method: "GET", url: "http://app/notes/2", status: 403 },
    ]);
  });

  it("drops the video, the one artifact a refutation cannot use", async () => {
    const f = finding("aaa");
    await runPhase(outDir, f, refutes);

    const dir = getEvidenceDir(outDir, f.agentSlug, f.id);
    expect(existsSync(join(dir, "page-1.webm"))).toBe(false);
    expect(f.live?.evidence?.video).toBeUndefined();
  });

  it("saves the negative control script without replaying it", async () => {
    const f = finding("aaa");
    await runPhase(outDir, f, refutes);

    const dir = getEvidenceDir(outDir, f.agentSlug, f.id);
    expect(readFileSync(join(dir, "repro.spec.ts"), "utf8")).toBe("// negative control");
    expect(f.live?.evidence?.script).toEqual({
      path: "repro.spec.ts",
      executed: false,
      passed: false,
    });
    // A negative control that "passes" would contradict the verdict.
    expect(replayed).toEqual([]);
  });

  it("records no evidence when the refuting session captured nothing", async () => {
    const f = finding("aaa");
    await runPhase(outDir, f, async () => ({
      result: "refuted" as const,
      reasoning: "r",
      counterevidence: "",
    }));

    // An empty evidence block renders an empty Evidence panel in the viewer,
    // which reads as a promise of artifacts that are not there.
    expect(f.live?.result).toBe("refuted");
    expect(f.live?.evidence).toBeUndefined();
  });

  it("saves nothing for an inconclusive run, which backs no claim", async () => {
    const f = finding("bbb");
    await runPhase(outDir, f, async () => {
      sessionArtifacts();
      return {
        result: "inconclusive" as const,
        reasoning: "r",
        counterevidence: "",
        script: "// partial",
      };
    });

    expect(f.live?.result).toBe("inconclusive");
    expect(f.live?.evidence).toBeUndefined();
    expect(existsSync(join(getEvidenceDir(outDir, f.agentSlug, f.id), "trace.zip"))).toBe(false);
  });
});
