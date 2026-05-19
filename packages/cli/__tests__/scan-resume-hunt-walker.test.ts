import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding, UserConfig } from "@agentgg/core";
import { getAgentRunPath, readAgentRun, readFileRecord, saveUserConfig } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Detector mock includes every method runScan touches in hunt/walker
// modes — including `investigate`, which the existing scan-resume.test.ts
// omits and which makes any walker-agent run silently swallow its error.
const detectorMock = vi.hoisted(() => ({
  detectFile: vi.fn(async () => [] as Finding[]),
  hunt: vi.fn(async () => [] as Finding[]),
  investigate: vi.fn(async () => [] as Finding[]),
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
      detectFile: detectorMock.detectFile,
      hunt: detectorMock.hunt,
      investigate: detectorMock.investigate,
      validateFinding: detectorMock.validateFinding,
    }),
  };
});

import { runScan } from "../src/commands/scan.js";

let agentggHome: string;
let projectRoot: string;
let outputDir: string;
let env: NodeJS.ProcessEnv;

const HUNT_SLUG = "test-hunt-agent";
const WALKER_SLUG = "test-walker-agent";

function writeHuntAgent() {
  const dir = join(agentggHome, "agents", "custom");
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, `${HUNT_SLUG}.md`),
    `---
slug: ${HUNT_SLUG}
name: Test Hunt Agent
description: Hunt-mode test agent
mode: hunt
filePatterns:
  - "**/*.js"
---

Look for hardcoded secrets across the repo.
`,
    "utf8",
  );
}

function writeWalkerAgent() {
  const dir = join(agentggHome, "agents", "custom");
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, `${WALKER_SLUG}.md`),
    `---
slug: ${WALKER_SLUG}
name: Test Walker Agent
description: Walker-mode test agent
mode: walker
filePatterns:
  - "**/*.js"
preFilter:
  - regex: "exec\\\\("
    label: "exec call"
---

Investigate exec() calls flagged by preFilter.
`,
    "utf8",
  );
}

beforeEach(() => {
  agentggHome = mkdtempSync(join(tmpdir(), "agentgg-home-"));
  projectRoot = mkdtempSync(join(tmpdir(), "agentgg-target-"));
  outputDir = mkdtempSync(join(tmpdir(), "agentgg-out-"));
  env = { AGENTGG_HOME: agentggHome };

  writeFileSync(
    join(projectRoot, "server.js"),
    "const x = 'sk-test'; require('cp').exec(process.argv[2]);",
    "utf8",
  );

  // Pre-create the official agents dir as empty so the scan skips the
  // network install. The custom agents we drop into `<home>/agents/custom/`
  // are enough on their own.
  mkdirSync(join(agentggHome, "agentgg-agents"), { recursive: true });

  const cfg: UserConfig = {
    provider: "anthropic",
    anthropic: { apiKey: "sk-ant-test", model: "claude-sonnet-4-6" },
    schemaVersion: 1,
  };
  saveUserConfig(cfg, env);

  detectorMock.hunt.mockImplementation(async ({ agent }) => [
    {
      id: `${agent.slug}-server.js-finding`,
      agentSlug: agent.slug,
      title: "mock hunt finding",
      vulnSlug: agent.slug,
      filePath: "server.js",
      summary: "s",
      details: "d",
      poc: "p",
      impact: "i",
      references: [],
      confidence: 0.9,
      notifications: [],
    },
  ]);
  detectorMock.investigate.mockImplementation(async ({ agents, candidates }) => {
    const out: Finding[] = [];
    for (const c of candidates) {
      for (const a of agents) {
        out.push({
          id: `${a.slug}-${c.filePath}-finding`,
          agentSlug: a.slug,
          title: "mock walker finding",
          vulnSlug: a.slug,
          filePath: c.filePath,
          summary: "s",
          details: "d",
          poc: "p",
          impact: "i",
          references: [],
          confidence: 0.9,
          notifications: [],
        });
      }
    }
    return out;
  });
});

afterEach(() => {
  rmSync(agentggHome, { recursive: true, force: true });
  rmSync(projectRoot, { recursive: true, force: true });
  rmSync(outputDir, { recursive: true, force: true });
  vi.restoreAllMocks();
  detectorMock.detectFile.mockReset();
  detectorMock.hunt.mockReset();
  detectorMock.investigate.mockReset();
  detectorMock.validateFinding.mockReset();
  for (const h of process.listeners("SIGINT")) {
    process.removeListener("SIGINT", h);
  }
});

function suppressLogs() {
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
}

describe("scan resume — hunt mode", () => {
  it("first scan invokes hunt; second scan with matching scope skips it", async () => {
    suppressLogs();
    writeHuntAgent();

    await runScan(projectRoot, { template: [HUNT_SLUG], output: outputDir }, env);
    expect(detectorMock.hunt).toHaveBeenCalledTimes(1);
    expect(existsSync(getAgentRunPath(outputDir, HUNT_SLUG))).toBe(true);

    detectorMock.hunt.mockClear();
    await runScan(projectRoot, { template: [HUNT_SLUG], output: outputDir }, env);
    expect(detectorMock.hunt).not.toHaveBeenCalled();
  });

  it("lifts cached hunt findings into the in-memory results on resume", async () => {
    suppressLogs();
    writeHuntAgent();

    await runScan(projectRoot, { template: [HUNT_SLUG], output: outputDir }, env);
    detectorMock.hunt.mockClear();

    // Second run: hunt is skipped but the persisted finding should remain
    // readable via the FileRecord we wrote in pass 1.
    await runScan(projectRoot, { template: [HUNT_SLUG], output: outputDir }, env);
    expect(detectorMock.hunt).not.toHaveBeenCalled();

    const record = readFileRecord(outputDir, "server.js");
    expect(record?.findings.some((f) => f.agentSlug === HUNT_SLUG)).toBe(true);
  });

  it("--rescan forces hunt to re-run even when a sidecar exists", async () => {
    suppressLogs();
    writeHuntAgent();

    await runScan(projectRoot, { template: [HUNT_SLUG], output: outputDir }, env);
    detectorMock.hunt.mockClear();

    await runScan(projectRoot, { template: [HUNT_SLUG], output: outputDir, rescan: true }, env);
    expect(detectorMock.hunt).toHaveBeenCalledTimes(1);
  });

  it("scope mismatch (--exclude differs) re-runs hunt even without --rescan", async () => {
    suppressLogs();
    writeHuntAgent();

    await runScan(
      projectRoot,
      { template: [HUNT_SLUG], output: outputDir, exclude: ["foo/**"] },
      env,
    );
    detectorMock.hunt.mockClear();

    // Second run with a different --exclude — sidecar should mismatch.
    await runScan(
      projectRoot,
      { template: [HUNT_SLUG], output: outputDir, exclude: ["bar/**"] },
      env,
    );
    expect(detectorMock.hunt).toHaveBeenCalledTimes(1);
  });

  it("--exclude order doesn't matter for scope match (set comparison)", async () => {
    suppressLogs();
    writeHuntAgent();

    await runScan(
      projectRoot,
      {
        template: [HUNT_SLUG],
        output: outputDir,
        exclude: ["a/**", "b/**"],
      },
      env,
    );
    detectorMock.hunt.mockClear();

    await runScan(
      projectRoot,
      {
        template: [HUNT_SLUG],
        output: outputDir,
        exclude: ["b/**", "a/**"],
      },
      env,
    );
    expect(detectorMock.hunt).not.toHaveBeenCalled();
  });

  it("scope mismatch (--diff differs) re-runs hunt", async () => {
    suppressLogs();
    writeHuntAgent();

    // First run without --diff. (We can't easily pass a real commit in a
    // unit test, so we only assert the "no --diff vs no --diff" baseline
    // skips and a sidecar with diff="HEAD" wouldn't match no --diff.)
    await runScan(projectRoot, { template: [HUNT_SLUG], output: outputDir }, env);
    expect(detectorMock.hunt).toHaveBeenCalledTimes(1);

    // Manually corrupt the sidecar to simulate "prior run was scoped to a
    // specific --diff commit." On the next no-diff run, the scope check
    // should reject the cache and re-invoke hunt.
    const sidecar = readAgentRun(outputDir, HUNT_SLUG);
    if (!sidecar) throw new Error("expected hunt sidecar after first scan");
    writeFileSync(
      getAgentRunPath(outputDir, HUNT_SLUG),
      JSON.stringify({ ...sidecar, scope: { ...sidecar.scope, diff: "abc123" } }, null, 2),
      "utf8",
    );

    detectorMock.hunt.mockClear();
    await runScan(projectRoot, { template: [HUNT_SLUG], output: outputDir }, env);
    expect(detectorMock.hunt).toHaveBeenCalledTimes(1);
  });
});

describe("scan resume — walker mode", () => {
  it("first scan invokes investigate; second scan skips when (file, agent) already analyzed", async () => {
    suppressLogs();
    writeWalkerAgent();

    await runScan(projectRoot, { template: [WALKER_SLUG], output: outputDir }, env);
    expect(detectorMock.investigate).toHaveBeenCalledTimes(1);

    detectorMock.investigate.mockClear();
    await runScan(projectRoot, { template: [WALKER_SLUG], output: outputDir }, env);
    expect(detectorMock.investigate).not.toHaveBeenCalled();
  });

  it("re-investigates when the file content changes (contentHash mismatch)", async () => {
    suppressLogs();
    writeWalkerAgent();

    await runScan(projectRoot, { template: [WALKER_SLUG], output: outputDir }, env);
    detectorMock.investigate.mockClear();

    writeFileSync(
      join(projectRoot, "server.js"),
      "require('cp').exec('different command');",
      "utf8",
    );

    await runScan(projectRoot, { template: [WALKER_SLUG], output: outputDir }, env);
    expect(detectorMock.investigate).toHaveBeenCalledTimes(1);
  });

  it("--rescan forces walker to re-investigate even when the cache hit would apply", async () => {
    suppressLogs();
    writeWalkerAgent();

    await runScan(projectRoot, { template: [WALKER_SLUG], output: outputDir }, env);
    detectorMock.investigate.mockClear();

    await runScan(projectRoot, { template: [WALKER_SLUG], output: outputDir, rescan: true }, env);
    expect(detectorMock.investigate).toHaveBeenCalledTimes(1);
  });

  it("walker resume does NOT write a per-agent sidecar (per-file FileRecord is the cache)", async () => {
    suppressLogs();
    writeWalkerAgent();

    await runScan(projectRoot, { template: [WALKER_SLUG], output: outputDir }, env);
    expect(existsSync(getAgentRunPath(outputDir, WALKER_SLUG))).toBe(false);
  });

  it("walker resume preserves prior findings on the FileRecord", async () => {
    suppressLogs();
    writeWalkerAgent();

    await runScan(projectRoot, { template: [WALKER_SLUG], output: outputDir }, env);
    const before = readFileRecord(outputDir, "server.js");
    expect(before?.findings.some((f) => f.agentSlug === WALKER_SLUG)).toBe(true);

    await runScan(projectRoot, { template: [WALKER_SLUG], output: outputDir }, env);
    const after = readFileRecord(outputDir, "server.js");
    expect(after?.findings.length).toBe(before?.findings.length);
  });
});
