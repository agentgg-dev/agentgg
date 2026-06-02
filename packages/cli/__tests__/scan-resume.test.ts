import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding, UserConfig } from "@agentgg/core";
import { loadAllFileRecords, readFileRecord, saveUserConfig } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Synthesize a minimal unified agent .md so these tests don't depend on
// whatever the live agentgg-agents catalog ships. The detector is mocked,
// so the prompt body doesn't matter — only the frontmatter shape. `where`
// scopes to `.js`; no preFilter means every matched file is a candidate.
function writeTestAgent(dir: string, slug: string): string {
  const body = `---
slug: ${slug}
name: ${slug}
description: Synthetic agent for scan-resume tests.
where:
  extensions:
    - js
---
Stub agent body. Detector is mocked.
`;
  const path = join(dir, `${slug}.md`);
  writeFileSync(path, body, "utf8");
  return path;
}

function mockFinding(slug: string, filePath: string): Finding {
  return {
    id: `${slug}-${filePath}`,
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

// The unified detector contract: recon + checkPrecondition + runAgent +
// validateFinding. The scope/score passes aren't exercised here, so they
// are omitted from the mock.
const detectorMock = vi.hoisted(() => ({
  recon: vi.fn(async () => ({
    purpose: "test fixture",
    languages: ["javascript"],
    frameworks: [] as string[],
    authModel: null as string | null,
    integrations: [] as string[],
    notableDirs: [] as string[],
    summary: "A small JS test fixture.",
  })),
  checkPrecondition: vi.fn(async () => ({ relevant: true, reason: "stub" })),
  runAgent: vi.fn(
    async (_args: { agent: { slug: string }; candidates: { filePath: string }[] }) =>
      [] as Finding[],
  ),
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
let agentA: string;
let agentB: string;
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  agentggHome = mkdtempSync(join(tmpdir(), "agentgg-home-"));
  projectRoot = mkdtempSync(join(tmpdir(), "agentgg-target-"));
  outputDir = mkdtempSync(join(tmpdir(), "agentgg-out-"));
  agentsDir = mkdtempSync(join(tmpdir(), "agentgg-agents-"));
  agentA = writeTestAgent(agentsDir, "test-detector-a");
  agentB = writeTestAgent(agentsDir, "test-detector-b");
  env = { AGENTGG_HOME: agentggHome };

  writeFileSync(
    join(projectRoot, "server.js"),
    "const x = 'sk-test'; require('cp').exec(process.argv[2]);",
    "utf8",
  );
  writeFileSync(join(projectRoot, "util.js"), "module.exports = (a) => a + 1;", "utf8");

  const cfg: UserConfig = {
    provider: "anthropic",
    anthropic: { apiKey: "sk-ant-test", model: "claude-sonnet-4-6" },
    schemaVersion: 1,
  };
  saveUserConfig(cfg, env);

  detectorMock.recon.mockImplementation(async () => ({
    purpose: "test fixture",
    languages: ["javascript"],
    frameworks: [],
    authModel: null,
    integrations: [],
    notableDirs: [],
    summary: "A small JS test fixture.",
  }));
  detectorMock.checkPrecondition.mockImplementation(async () => ({
    relevant: true,
    reason: "stub",
  }));
  detectorMock.runAgent.mockImplementation(async ({ agent, candidates }) =>
    candidates.map((c) => mockFinding(agent.slug, c.filePath)),
  );
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

function suppressLogs() {
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
}

// Flatten every file path the agent was asked to analyze across all
// runAgent calls — order-independent, batch-size-independent.
type RunAgentCall = { agent: { slug: string }; candidates: { filePath: string }[] };
function ranFiles(): string[] {
  return (detectorMock.runAgent.mock.calls as unknown as [RunAgentCall][]).flatMap(([a]) =>
    a.candidates.map((c) => c.filePath),
  );
}

describe("scan resume — agent level", () => {
  it("runs the agent on the first scan; an unchanged re-run reuses it", async () => {
    suppressLogs();
    await runScan(projectRoot, { template: [agentA], output: outputDir }, env);
    expect(detectorMock.runAgent).toHaveBeenCalled();
    expect(loadAllFileRecords(outputDir).length).toBe(2);

    detectorMock.runAgent.mockClear();
    await runScan(projectRoot, { template: [agentA], output: outputDir }, env);
    expect(detectorMock.runAgent).not.toHaveBeenCalled();
  });

  it("--rescan forces the agent to re-run", async () => {
    suppressLogs();
    await runScan(projectRoot, { template: [agentA], output: outputDir }, env);
    detectorMock.runAgent.mockClear();

    await runScan(projectRoot, { template: [agentA], output: outputDir, rescan: true }, env);
    expect(detectorMock.runAgent).toHaveBeenCalled();
  });

  it("a different agent does not reuse another agent's cache", async () => {
    suppressLogs();
    await runScan(projectRoot, { template: [agentA], output: outputDir }, env);
    detectorMock.runAgent.mockClear();

    await runScan(projectRoot, { template: [agentB], output: outputDir }, env);
    expect(detectorMock.runAgent).toHaveBeenCalled();
  });

  it("a different --output dir is a fresh scan", async () => {
    suppressLogs();
    const secondOut = mkdtempSync(join(tmpdir(), "agentgg-out2-"));
    try {
      await runScan(projectRoot, { template: [agentA], output: outputDir }, env);
      detectorMock.runAgent.mockClear();
      await runScan(projectRoot, { template: [agentA], output: secondOut }, env);
      expect(detectorMock.runAgent).toHaveBeenCalled();
    } finally {
      rmSync(secondOut, { recursive: true, force: true });
    }
  });
});

describe("scan resume — per-file (interrupted agent)", () => {
  // First scan: util.js's batch throws (a non-fatal error → that batch is
  // skipped, the agent gets no completion sidecar), but server.js's batch
  // persists. maxFilesPerBatch: 1 makes each file its own batch.
  async function interruptedFirstScan() {
    detectorMock.runAgent.mockImplementation(async ({ agent, candidates }) => {
      if (candidates.some((c) => c.filePath === "util.js")) {
        throw new Error("simulated interruption");
      }
      return candidates.map((c) => mockFinding(agent.slug, c.filePath));
    });
    await runScan(projectRoot, { template: [agentA], output: outputDir, maxFilesPerBatch: 1 }, env);
  }

  it("re-runs only the files not yet analyzed", async () => {
    suppressLogs();
    await interruptedFirstScan();
    // server.js persisted, util.js did not, no completion sidecar.
    expect(readFileRecord(outputDir, "test-detector-a", "server.js")).not.toBeNull();
    expect(readFileRecord(outputDir, "test-detector-a", "util.js")).toBeNull();

    detectorMock.runAgent.mockClear();
    detectorMock.runAgent.mockImplementation(async ({ agent, candidates }) =>
      candidates.map((c) => mockFinding(agent.slug, c.filePath)),
    );
    await runScan(projectRoot, { template: [agentA], output: outputDir, maxFilesPerBatch: 1 }, env);

    // Only util.js is re-analyzed; server.js is reused from disk.
    expect(ranFiles()).toEqual(["util.js"]);
  });

  it("completing a resumed agent writes the sidecar so a later run reuses it", async () => {
    suppressLogs();
    await interruptedFirstScan();

    detectorMock.runAgent.mockImplementation(async ({ agent, candidates }) =>
      candidates.map((c) => mockFinding(agent.slug, c.filePath)),
    );
    // This run finishes util.js → agent now fully complete.
    await runScan(projectRoot, { template: [agentA], output: outputDir, maxFilesPerBatch: 1 }, env);

    detectorMock.runAgent.mockClear();
    await runScan(projectRoot, { template: [agentA], output: outputDir }, env);
    expect(detectorMock.runAgent).not.toHaveBeenCalled();
  });

  it("re-analyzes a file whose content changed since it was analyzed", async () => {
    suppressLogs();
    await interruptedFirstScan();

    // Change the already-analyzed file: its contentHash no longer matches.
    writeFileSync(join(projectRoot, "server.js"), "const CHANGED = 1;", "utf8");

    detectorMock.runAgent.mockClear();
    detectorMock.runAgent.mockImplementation(async ({ agent, candidates }) =>
      candidates.map((c) => mockFinding(agent.slug, c.filePath)),
    );
    await runScan(projectRoot, { template: [agentA], output: outputDir, maxFilesPerBatch: 1 }, env);

    // Both run: server.js because it changed, util.js because it was pending.
    expect(ranFiles().sort()).toEqual(["server.js", "util.js"]);
  });

  it("--rescan re-analyzes even already-analyzed files", async () => {
    suppressLogs();
    await interruptedFirstScan();

    detectorMock.runAgent.mockClear();
    detectorMock.runAgent.mockImplementation(async ({ agent, candidates }) =>
      candidates.map((c) => mockFinding(agent.slug, c.filePath)),
    );
    await runScan(
      projectRoot,
      { template: [agentA], output: outputDir, maxFilesPerBatch: 1, rescan: true },
      env,
    );

    // --rescan bypasses the per-file skip; server.js (already on disk) re-runs.
    expect(ranFiles().sort()).toEqual(["server.js", "util.js"]);
  });
});

describe("scan resume — validation phase", () => {
  it("skips findings that already have a verdict on disk", async () => {
    suppressLogs();
    await runScan(projectRoot, { template: [agentA], output: outputDir, validate: true }, env);
    expect(detectorMock.validateFinding).toHaveBeenCalled();

    detectorMock.runAgent.mockClear();
    detectorMock.validateFinding.mockClear();
    await runScan(projectRoot, { template: [agentA], output: outputDir, validate: true }, env);
    expect(detectorMock.runAgent).not.toHaveBeenCalled();
    expect(detectorMock.validateFinding).not.toHaveBeenCalled();
  });

  it("--revalidate-all re-runs validation even when verdicts exist", async () => {
    suppressLogs();
    await runScan(projectRoot, { template: [agentA], output: outputDir, validate: true }, env);
    detectorMock.validateFinding.mockClear();

    await runScan(
      projectRoot,
      { template: [agentA], output: outputDir, validate: true, revalidateAll: true },
      env,
    );
    expect(detectorMock.validateFinding).toHaveBeenCalled();
  });

  it("a persisted verdict carries over to a resumed run", async () => {
    suppressLogs();
    detectorMock.validateFinding.mockImplementation(async () => ({
      verdict: "false-positive",
      reasoning: "stub",
    }));
    await runScan(projectRoot, { template: [agentA], output: outputDir, validate: true }, env);

    detectorMock.validateFinding.mockClear();
    await runScan(projectRoot, { template: [agentA], output: outputDir, validate: true }, env);

    const record = readFileRecord(outputDir, "test-detector-a", "server.js");
    expect(record?.findings[0]?.validation?.verdict).toBe("false-positive");
  });
});

describe("scan resume — RunMeta + persistence", () => {
  it("first scan writes a FileRecord; an unchanged re-run preserves it", async () => {
    suppressLogs();
    await runScan(projectRoot, { template: [agentA], output: outputDir }, env);
    const before = readFileRecord(outputDir, "test-detector-a", "server.js");
    expect(before).not.toBeNull();
    expect(before?.findings.length).toBe(1);
    const contentHashBefore = before?.contentHash;

    await runScan(projectRoot, { template: [agentA], output: outputDir }, env);

    const after = readFileRecord(outputDir, "test-detector-a", "server.js");
    expect(after?.findings.length).toBe(1);
    expect(after?.contentHash).toBe(contentHashBefore);
  });

  it("registers a SIGINT handler during the scan and removes it afterwards", async () => {
    suppressLogs();
    const before = process.listenerCount("SIGINT");
    await runScan(projectRoot, { template: [agentA], output: outputDir }, env);
    expect(process.listenerCount("SIGINT")).toBe(before);
  });
});
