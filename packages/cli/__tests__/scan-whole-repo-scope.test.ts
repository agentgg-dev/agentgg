import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding, UserConfig } from "@agentgg/core";
import { readAgentRun, readFileRecord, saveUserConfig } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Every runAgent argument these tests care about. `maxTurns` is recorded
// alongside the candidate count because the dispatch call is the only place
// the resolved turn budget becomes observable.
type RunAgentCall = {
  agent: { slug: string };
  candidates: { filePath: string }[];
  maxTurns: number;
};

const detectorMock = vi.hoisted(() => ({
  recon: vi.fn(async () => ({
    purpose: "test fixture",
    languages: ["typescript"],
    frameworks: [] as string[],
    authModel: null as string | null,
    integrations: [] as string[],
    notableDirs: [] as string[],
    summary: "A small TS test fixture.",
  })),
  checkPrecondition: vi.fn(async () => ({ relevant: true, reason: "stub" })),
  runAgent: vi.fn(async (_args: RunAgentCall) => [] as Finding[]),
  validateFinding: vi.fn(async () => ({
    verdict: "confirmed" as const,
    reasoning: "default",
  })),
}));

vi.mock("../src/llm.js", async () => {
  const actual = await vi.importActual<typeof import("../src/llm.js")>("../src/llm.js");
  return {
    ...actual,
    resolveDetector: () => ({
      name: "test-mock",
      recon: detectorMock.recon,
      checkPrecondition: detectorMock.checkPrecondition,
      runAgent: detectorMock.runAgent,
      validateFinding: detectorMock.validateFinding,
    }),
  };
});

import { runScan } from "../src/commands/scan.js";

let agentggHome: string;
let projectRoot: string;
let outputDir: string;
let agentsDir: string;
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  agentggHome = mkdtempSync(join(tmpdir(), "agentgg-home-"));
  projectRoot = mkdtempSync(join(tmpdir(), "agentgg-target-"));
  outputDir = mkdtempSync(join(tmpdir(), "agentgg-out-"));
  agentsDir = mkdtempSync(join(tmpdir(), "agentgg-agents-"));
  env = { AGENTGG_HOME: agentggHome };

  mkdirSync(join(projectRoot, "src"), { recursive: true });
  writeFileSync(join(projectRoot, "src", "a.ts"), "export const a = 1;\n", "utf8");

  const cfg: UserConfig = {
    provider: "anthropic",
    anthropic: { apiKey: "sk-ant-test", model: "claude-sonnet-4-6" },
    schemaVersion: 1,
  };
  saveUserConfig(cfg, env);

  detectorMock.recon.mockImplementation(async () => ({
    purpose: "test fixture",
    languages: ["typescript"],
    frameworks: [],
    authModel: null,
    integrations: [],
    notableDirs: [],
    summary: "A small TS test fixture.",
  }));
  detectorMock.checkPrecondition.mockImplementation(async () => ({
    relevant: true,
    reason: "stub",
  }));
  detectorMock.runAgent.mockImplementation(async () => []);
  detectorMock.validateFinding.mockImplementation(async () => ({
    verdict: "confirmed",
    reasoning: "default",
  }));
});

afterEach(() => {
  rmSync(agentggHome, { recursive: true, force: true });
  rmSync(projectRoot, { recursive: true, force: true });
  rmSync(outputDir, { recursive: true, force: true });
  rmSync(agentsDir, { recursive: true, force: true });
  vi.restoreAllMocks();
  detectorMock.recon.mockReset();
  detectorMock.checkPrecondition.mockReset();
  detectorMock.runAgent.mockReset();
  detectorMock.validateFinding.mockReset();
  for (const h of process.listeners("SIGINT")) {
    process.removeListener("SIGINT", h);
  }
});

/** Silence the scan and return the `console.log` lines it emitted. */
function captureLogs(): string[] {
  const lines: string[] = [];
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    lines.push(args.join(" "));
  });
  vi.spyOn(console, "error").mockImplementation(() => {});
  return lines;
}

function suppressLogs() {
  captureLogs();
}

/** Write a synthetic agent whose frontmatter carries `where` verbatim. */
function writeAgent(slug: string, where: string): string {
  const body = `---
slug: ${slug}
name: ${slug}
description: Synthetic agent for scope tests.
${where}---
Stub agent body. Detector is mocked.
`;
  const path = join(agentsDir, `${slug}.md`);
  writeFileSync(path, body, "utf8");
  return path;
}

/** One row per runAgent call, in call order. */
function dispatched(): { slug: string; candidateCount: number; maxTurns: number }[] {
  return (detectorMock.runAgent.mock.calls as unknown as [RunAgentCall][]).map(([a]) => ({
    slug: a.agent.slug,
    candidateCount: a.candidates.length,
    maxTurns: a.maxTurns,
  }));
}

function turnsFor(slug: string): number[] {
  return dispatched()
    .filter((c) => c.slug === slug)
    .map((c) => c.maxTurns);
}

// The id lands in a filename verbatim (findingFilenameSlug), so it stays
// path-safe.
function mockFinding(slug: string, filePath: string): Finding {
  return {
    id: `${slug}-mock`,
    agentSlug: slug,
    title: "mock finding",
    vulnSlug: slug,
    filePath,
    summary: "s",
    details: "d",
    poc: "p",
    impact: "i",
    references: [],
    confidence: 0.9,
    notifications: [],
  };
}

describe("an agent with no file scope", () => {
  it("runs exactly one batch with no candidates", async () => {
    suppressLogs();
    const path = writeAgent("no-scope", "");
    await runScan(projectRoot, { template: [path], output: outputDir }, env);

    expect(dispatched()).toEqual([{ slug: "no-scope", candidateCount: 0, maxTurns: 150 }]);
  });

  it("does not take the zero-candidate early exit", async () => {
    suppressLogs();
    // A repository where the walk yields nothing: the only file is one the
    // default excludes drop. That is the case that reaches the zero-candidate
    // early exit, which writes a zero-finding completion sidecar and never
    // calls runAgent — a silent no-op that looks like a clean scan result.
    // Asserting the session ran AND its finding landed is what distinguishes
    // "it worked" from "nothing happened without erroring".
    const vendoredOnly = mkdtempSync(join(tmpdir(), "agentgg-vendored-"));
    mkdirSync(join(vendoredOnly, "node_modules"), { recursive: true });
    writeFileSync(join(vendoredOnly, "node_modules", "dep.js"), "// vendored\n", "utf8");
    const path = writeAgent("no-scope", "");
    detectorMock.runAgent.mockImplementation(async ({ agent }) => [
      mockFinding(agent.slug, "node_modules/dep.js"),
    ]);
    try {
      await runScan(vendoredOnly, { template: [path], output: outputDir }, env);

      expect(detectorMock.runAgent).toHaveBeenCalledTimes(1);
      expect(dispatched()[0].candidateCount).toBe(0);
      expect(readFileRecord(outputDir, "no-scope", "node_modules/dep.js")?.findings.length).toBe(1);
    } finally {
      rmSync(vendoredOnly, { recursive: true, force: true });
    }
  });

  it("still walks and batches an agent that declares extensions", async () => {
    suppressLogs();
    const path = writeAgent("scoped", "where:\n  extensions:\n    - ts\n");
    await runScan(projectRoot, { template: [path], output: outputDir }, env);

    const calls = dispatched();
    expect(calls.length).toBe(1);
    expect(calls[0].candidateCount).toBeGreaterThan(0);
  });

  it("says what it dispatched and what the session covered", async () => {
    // Both lines are user-facing copy, and the second only reads sensibly
    // because a batch with no candidate files names its scope rather than
    // rendering an empty list of paths.
    const logs = captureLogs();
    const path = writeAgent("no-scope", "");
    detectorMock.runAgent.mockImplementation(async ({ agent }) => [
      mockFinding(agent.slug, "src/a.ts"),
    ]);
    await runScan(projectRoot, { template: [path], output: outputDir }, env);

    expect(logs.find((l) => l.includes("no file scope"))).toBe(
      "  no-scope: no file scope, whole repository → 1 session of up to 150 turns",
    );
    expect(logs.find((l) => l.includes("no-scope ["))).toBe(
      "    no-scope [whole repository]: 1 finding(s)",
    );
  });

  it("leaves an agent whose declared scope matches nothing on the early exit", async () => {
    suppressLogs();
    // This agent has a file scope; the scope just selects no file here. That
    // is not the same as declaring none, and it still belongs on the
    // zero-candidate early exit rather than getting an empty batch.
    const path = writeAgent("scoped-empty", "where:\n  extensions:\n    - php\n");
    await runScan(projectRoot, { template: [path], output: outputDir }, env);

    expect(detectorMock.runAgent).not.toHaveBeenCalled();
  });

  it("records seeded: false and filesReviewed as the distinct files its findings named", async () => {
    suppressLogs();
    writeFileSync(join(projectRoot, "src", "b.ts"), "export const b = 2;\n", "utf8");
    const path = writeAgent("no-scope", "");
    detectorMock.runAgent.mockImplementation(async ({ agent }) => [
      mockFinding(agent.slug, "src/a.ts"),
      mockFinding(agent.slug, "src/b.ts"),
    ]);
    await runScan(projectRoot, { template: [path], output: outputDir }, env);

    const sidecar = readAgentRun(outputDir, "no-scope");
    expect(sidecar?.seeded).toBe(false);
    expect(sidecar?.filesReviewed).toBe(2);
  });
});

describe("AgentRun.seeded for a seeded agent", () => {
  it("stays true, and filesReviewed stays the candidate count", async () => {
    suppressLogs();
    const path = writeAgent("scoped", "where:\n  extensions:\n    - ts\n");
    detectorMock.runAgent.mockImplementation(async ({ agent }) => [
      mockFinding(agent.slug, "src/a.ts"),
    ]);
    await runScan(projectRoot, { template: [path], output: outputDir }, env);

    const candidateCount = dispatched().find((c) => c.slug === "scoped")?.candidateCount;
    const sidecar = readAgentRun(outputDir, "scoped");
    expect(sidecar?.seeded).toBe(true);
    expect(sidecar?.filesReviewed).toBe(candidateCount);
  });
});

describe("the turn budget a batch is dispatched with", () => {
  it("is 150 for an agent that declares no extensions and no filePatterns", async () => {
    suppressLogs();
    const path = writeAgent("no-scope", "");
    await runScan(projectRoot, { template: [path], output: outputDir }, env);

    expect(turnsFor("no-scope")).toEqual([150]);
  });

  it("is 50 for an agent that declares extensions", async () => {
    suppressLogs();
    const path = writeAgent("scoped", "where:\n  extensions:\n    - ts\n");
    await runScan(projectRoot, { template: [path], output: outputDir }, env);

    expect(turnsFor("scoped")).toEqual([50]);
  });

  it("is the declared where.maxTurnsPerBatch, not the default", async () => {
    suppressLogs();
    const unscoped = writeAgent("declared-no-scope", "where:\n  maxTurnsPerBatch: 22\n");
    const scoped = writeAgent(
      "declared-scoped",
      "where:\n  extensions:\n    - ts\n  maxTurnsPerBatch: 33\n",
    );
    await runScan(
      projectRoot,
      { template: [unscoped, scoped], output: outputDir, concurrency: 1 },
      env,
    );

    expect(turnsFor("declared-no-scope")).toEqual([22]);
    expect(turnsFor("declared-scoped")).toEqual([33]);
  });

  it("is the --max-turns value, which overrides both defaults and a declared value", async () => {
    suppressLogs();
    const unscoped = writeAgent("no-scope", "");
    const scoped = writeAgent("scoped", "where:\n  extensions:\n    - ts\n");
    const declared = writeAgent("declared-no-scope", "where:\n  maxTurnsPerBatch: 22\n");
    await runScan(
      projectRoot,
      {
        template: [unscoped, scoped, declared],
        output: outputDir,
        concurrency: 1,
        maxTurns: 7,
      },
      env,
    );

    expect(turnsFor("no-scope")).toEqual([7]);
    expect(turnsFor("scoped")).toEqual([7]);
    expect(turnsFor("declared-no-scope")).toEqual([7]);
  });
});
