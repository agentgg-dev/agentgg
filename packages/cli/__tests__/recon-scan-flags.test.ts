import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding, UserConfig } from "@agentgg/core";
import {
  getOfficialAgentsDir,
  loadAllFileRecords,
  readReconReport,
  readScanPlan,
  saveUserConfig,
} from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// A unified agent .md. `gated: true` adds a prompt precondition so the
// precondition for-loop actually calls the detector's checkPrecondition —
// which is what lets these tests observe whether the loop ran or was
// skipped/reused.
function writeTestAgent(dir: string, slug: string, gated = false): string {
  const pre = gated
    ? `precondition:
  prompt: "Only run if relevant to this repo."
`
    : "";
  const body = `---
slug: ${slug}
name: ${slug}
description: Synthetic agent for recon/scan-flag tests.
${pre}where:
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

const detectorMock = vi.hoisted(() => ({
  recon: vi.fn(async () => ({
    purpose: "test fixture",
    languages: ["javascript"] as string[],
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
    }),
  };
});

import { runReconCommand } from "../src/commands/recon.js";
import { runScan } from "../src/commands/scan.js";

let agentggHome: string;
let projectRoot: string;
let outputDir: string;
let agentsDir: string;
let agentPlain: string;
let agentGated: string;
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  agentggHome = mkdtempSync(join(tmpdir(), "agentgg-home-"));
  projectRoot = mkdtempSync(join(tmpdir(), "agentgg-target-"));
  outputDir = mkdtempSync(join(tmpdir(), "agentgg-out-"));
  agentsDir = mkdtempSync(join(tmpdir(), "agentgg-agents-"));
  agentPlain = writeTestAgent(agentsDir, "plain-agent", false);
  agentGated = writeTestAgent(agentsDir, "gated-agent", true);
  env = { AGENTGG_HOME: agentggHome };

  // Create an (empty) official agents dir so scan/recon skip the
  // network auto-install path entirely. Agents come from -t instead.
  mkdirSync(getOfficialAgentsDir(env), { recursive: true });

  writeFileSync(join(projectRoot, "server.js"), "const x = 1;", "utf8");

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
  for (const h of process.listeners("SIGINT")) {
    process.removeListener("SIGINT", h);
  }
});

function suppressLogs() {
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  vi.spyOn(process.stderr, "write").mockImplementation(() => true);
}

describe("runReconCommand", () => {
  it("writes recon.json + plan.json and runs no detection", async () => {
    suppressLogs();
    await runReconCommand(projectRoot, { template: [agentPlain], output: outputDir }, env);

    const recon = readReconReport(outputDir);
    expect(recon).not.toBeNull();
    expect(recon?.languages).toContain("javascript");

    const plan = readScanPlan(outputDir);
    expect(plan).not.toBeNull();
    expect(plan?.decisions.find((d) => d.slug === "plain-agent")?.queued).toBe(true);

    // recon does not run any agents.
    expect(detectorMock.runAgent).not.toHaveBeenCalled();
  });

  it("records a skipped agent when its prompt gate says no", async () => {
    suppressLogs();
    detectorMock.checkPrecondition.mockImplementation(async () => ({
      relevant: false,
      reason: "not relevant",
    }));
    await runReconCommand(projectRoot, { template: [agentGated], output: outputDir }, env);

    const plan = readScanPlan(outputDir);
    expect(plan?.decisions.find((d) => d.slug === "gated-agent")?.queued).toBe(false);
  });

  it("reuses the cached recon brief on a second run; --re-recon forces a re-survey", async () => {
    suppressLogs();
    await runReconCommand(projectRoot, { template: [agentPlain], output: outputDir }, env);
    expect(detectorMock.recon).toHaveBeenCalledTimes(1);

    await runReconCommand(projectRoot, { template: [agentPlain], output: outputDir }, env);
    expect(detectorMock.recon).toHaveBeenCalledTimes(1); // cached, not re-run

    await runReconCommand(
      projectRoot,
      { template: [agentPlain], output: outputDir, reRecon: true },
      env,
    );
    expect(detectorMock.recon).toHaveBeenCalledTimes(2); // forced re-survey
  });
});

describe("scan --no-recon", () => {
  it("skips the recon survey and the precondition loop, running every -t agent", async () => {
    suppressLogs();
    await runScan(projectRoot, { template: [agentGated], output: outputDir, recon: false }, env);

    expect(detectorMock.recon).not.toHaveBeenCalled();
    expect(detectorMock.checkPrecondition).not.toHaveBeenCalled();
    // The gated agent runs anyway — gating was bypassed.
    expect(detectorMock.runAgent).toHaveBeenCalled();
    // No recon brief is persisted under --no-recon.
    expect(readReconReport(outputDir)).toBeNull();
    // A plan is still written, with the agent queued unconditionally.
    expect(readScanPlan(outputDir)?.decisions.find((d) => d.slug === "gated-agent")?.queued).toBe(
      true,
    );
  });
});

describe("scan --no-summary", () => {
  it("does not write summary.md but still persists findings to state", async () => {
    suppressLogs();
    await runScan(projectRoot, { template: [agentPlain], output: outputDir, summary: false }, env);

    expect(existsSync(join(outputDir, "summary.md"))).toBe(false);
    expect(loadAllFileRecords(outputDir).length).toBeGreaterThan(0);
  });

  it("writes summary.md by default (no flag)", async () => {
    suppressLogs();
    await runScan(projectRoot, { template: [agentPlain], output: outputDir }, env);
    expect(existsSync(join(outputDir, "summary.md"))).toBe(true);
  });
});

describe("scan --max-files-per-agent", () => {
  it("caps the agent to N candidate files, reviewing only N and dropping the rest", async () => {
    suppressLogs();
    // server.js (from beforeEach) + two more → 3 .js candidates for plain-agent.
    writeFileSync(join(projectRoot, "a.js"), "const a = 1;", "utf8");
    writeFileSync(join(projectRoot, "b.js"), "const b = 2;", "utf8");

    await runScan(
      projectRoot,
      { template: [agentPlain], output: outputDir, maxFilesPerAgent: 2 },
      env,
    );

    // The agent still runs, but over at most 2 distinct candidate files.
    expect(detectorMock.runAgent).toHaveBeenCalled();
    const reviewed = new Set(
      detectorMock.runAgent.mock.calls.flatMap((call) => call[0].candidates.map((c) => c.filePath)),
    );
    expect(reviewed.size).toBe(2);
    // Only the 2 reviewed files get persisted records — the 3rd was dropped.
    expect(loadAllFileRecords(outputDir).length).toBe(2);
  });

  it("reviews every candidate when the cap is at or above the candidate count", async () => {
    suppressLogs();
    writeFileSync(join(projectRoot, "a.js"), "const a = 1;", "utf8");
    writeFileSync(join(projectRoot, "b.js"), "const b = 2;", "utf8");

    await runScan(
      projectRoot,
      { template: [agentPlain], output: outputDir, maxFilesPerAgent: 5 },
      env,
    );

    expect(detectorMock.runAgent).toHaveBeenCalled();
    expect(loadAllFileRecords(outputDir).length).toBe(3);
  });
});

describe("scan plan reuse", () => {
  it("reuses a prior plan, skipping the precondition for-loop on the next scan", async () => {
    suppressLogs();
    await runScan(projectRoot, { template: [agentGated], output: outputDir }, env);
    expect(detectorMock.checkPrecondition).toHaveBeenCalled();

    detectorMock.recon.mockClear();
    detectorMock.checkPrecondition.mockClear();
    await runScan(projectRoot, { template: [agentGated], output: outputDir }, env);

    // Recon brief reused (no survey) and plan reused (no re-evaluation).
    expect(detectorMock.recon).not.toHaveBeenCalled();
    expect(detectorMock.checkPrecondition).not.toHaveBeenCalled();
  });

  it("--re-recon forces both a re-survey and a precondition re-evaluation", async () => {
    suppressLogs();
    await runScan(projectRoot, { template: [agentGated], output: outputDir }, env);

    detectorMock.recon.mockClear();
    detectorMock.checkPrecondition.mockClear();
    await runScan(projectRoot, { template: [agentGated], output: outputDir, reRecon: true }, env);

    expect(detectorMock.recon).toHaveBeenCalled();
    expect(detectorMock.checkPrecondition).toHaveBeenCalled();
  });
});
