import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CvssScore, Finding, UserConfig } from "@agentgg/core";
import { readFileRecord, saveUserConfig } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const FILE = "app.js";

type Verdict = "confirmed" | "false-positive" | "out-of-scope" | "uncertain";

function writeAgent(dir: string, slug: string): string {
  const body = `---
slug: ${slug}
name: ${slug}
description: Synthetic agent for fix-phase tests.
where:
  extensions:
    - js
  preFilter:
    - regex: TARGET
      label: target
---
Stub agent body. Detector is mocked.
`;
  const path = join(dir, `${slug}.md`);
  writeFileSync(path, body, "utf8");
  return path;
}

function mockFinding(id: string): Finding {
  return {
    id,
    agentSlug: "alpha",
    title: `finding ${id}`,
    vulnSlug: "mock",
    filePath: FILE,
    summary: "s",
    details: "d",
    poc: "p",
    impact: "i",
    references: [],
    confidence: 0.9,
    notifications: [],
  };
}

const CVSS: CvssScore = {
  vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  baseScore: 9.8,
  severity: "CRITICAL",
  metrics: {
    attackVector: "N",
    attackComplexity: "L",
    privilegesRequired: "N",
    userInteraction: "N",
    scope: "U",
    confidentiality: "H",
    integrity: "H",
    availability: "H",
  },
  justification: "stub",
};

const detectorMock = vi.hoisted(() => ({
  recon: vi.fn(),
  checkPrecondition: vi.fn(),
  runAgent: vi.fn(),
  validateFinding: vi.fn(),
  scoreFinding: vi.fn(),
  dedupeFindings: vi.fn(),
  suggestFix: vi.fn(),
}));

vi.mock("../src/llm.js", async () => {
  const actual = await vi.importActual<typeof import("../src/llm.js")>("../src/llm.js");
  return {
    ...actual,
    resolveDetector: () => ({ name: "test-mock", ...detectorMock }),
  };
});

import { runScan } from "../src/commands/scan.js";
import { findingFilename } from "../src/reporters/md.js";

let agentggHome: string;
let projectRoot: string;
let outputDir: string;
let agentsDir: string;
let alphaPath: string;
let env: NodeJS.ProcessEnv;
/** Verdict the mocked validator returns, by finding id. */
let verdicts: Record<string, Verdict>;

beforeEach(() => {
  agentggHome = mkdtempSync(join(tmpdir(), "agentgg-home-"));
  projectRoot = mkdtempSync(join(tmpdir(), "agentgg-target-"));
  outputDir = mkdtempSync(join(tmpdir(), "agentgg-out-"));
  agentsDir = mkdtempSync(join(tmpdir(), "agentgg-agents-"));
  alphaPath = writeAgent(agentsDir, "alpha");
  env = { AGENTGG_HOME: agentggHome };

  writeFileSync(join(projectRoot, FILE), "TARGET one\nTARGET two\n", "utf8");

  const cfg: UserConfig = {
    provider: "anthropic",
    anthropic: { apiKey: "sk-ant-test", model: "claude-sonnet-4-6" },
    schemaVersion: 1,
  };
  saveUserConfig(cfg, env);

  verdicts = {};
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
  detectorMock.dedupeFindings.mockImplementation(async () => []);
  detectorMock.validateFinding.mockImplementation(async ({ finding }: { finding: Finding }) => ({
    verdict: verdicts[finding.id] ?? "confirmed",
    reasoning: "stub",
  }));
  detectorMock.scoreFinding.mockImplementation(async () => CVSS);
  detectorMock.suggestFix.mockImplementation(
    async ({ finding }: { finding: Finding }) => `fix for ${finding.id}`,
  );
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  for (const dir of [agentggHome, projectRoot, outputDir, agentsDir]) {
    rmSync(dir, { recursive: true, force: true });
  }
  vi.restoreAllMocks();
  for (const fn of Object.values(detectorMock)) fn.mockReset();
  for (const h of process.listeners("SIGINT")) {
    process.removeListener("SIGINT", h);
  }
});

const opts = (extra: object = {}) => ({
  template: [alphaPath],
  output: outputDir,
  validate: true,
  score: true,
  dedup: true,
  fix: true,
  ...extra,
});

function report(...ids: string[]) {
  detectorMock.runAgent.mockImplementation(async () => ids.map(mockFinding));
}

function onDisk(id: string): Finding {
  const f = readFileRecord(outputDir, "alpha", FILE)?.findings.find((x) => x.id === id);
  if (!f) throw new Error(`no finding ${id} on disk`);
  return f;
}

function findingMd(id: string): string {
  return readFileSync(join(outputDir, "findings", findingFilename(onDisk(id))), "utf8");
}

const fixedIds = () =>
  detectorMock.suggestFix.mock.calls.map((c) => (c[0] as { finding: Finding }).finding.id);

describe("scan fix phase", () => {
  it("writes a fix for a confirmed finding and shows it in the report", async () => {
    report("a1");

    await runScan(projectRoot, opts(), env);

    expect(onDisk("a1").suggestedFix).toBe("fix for a1");
    expect(findingMd("a1")).toContain("### Suggested fix\nfix for a1");
    const phases = readFileRecord(outputDir, "alpha", FILE)?.analysisHistory.map((h) => h.phase);
    expect(phases?.at(-1)).toBe("fix");
  });

  it.each([
    "uncertain",
    "false-positive",
    "out-of-scope",
  ] as const)("asks for no fix for a %s finding", async (verdict) => {
    report("a1", "a2");
    verdicts = { a2: verdict };

    await runScan(projectRoot, opts(), env);

    expect(fixedIds()).toEqual(["a1"]);
    expect(onDisk("a2").suggestedFix).toBeUndefined();
    expect(findingMd("a2")).not.toContain("Suggested fix");
  });

  it("asks for no fix for a duplicate", async () => {
    report("a1", "a2");
    detectorMock.dedupeFindings.mockImplementation(async () => [
      { primaryId: "a1", duplicateIds: ["a2"], reasoning: "same sink" },
    ]);

    await runScan(projectRoot, opts(), env);

    expect(fixedIds()).toEqual(["a1"]);
    expect(onDisk("a2").suggestedFix).toBeUndefined();
  });

  it("asks for no fix when validation did not run", async () => {
    report("a1");

    await runScan(projectRoot, opts({ validate: false }), env);

    expect(detectorMock.suggestFix).not.toHaveBeenCalled();
    expect(findingMd("a1")).not.toContain("Suggested fix");
  });

  it("skips the phase when fix is off", async () => {
    report("a1");

    await runScan(projectRoot, opts({ fix: false }), env);

    expect(detectorMock.suggestFix).not.toHaveBeenCalled();
    expect(onDisk("a1").suggestedFix).toBeUndefined();
  });

  it("keeps the other fixes when one call fails", async () => {
    report("a1", "a2");
    detectorMock.suggestFix.mockImplementation(async ({ finding }: { finding: Finding }) => {
      if (finding.id === "a1") throw new Error("model unavailable");
      return `fix for ${finding.id}`;
    });

    await runScan(projectRoot, opts(), env);

    expect(onDisk("a1").suggestedFix).toBeUndefined();
    expect(onDisk("a2").suggestedFix).toBe("fix for a2");
    expect(existsSync(join(outputDir, "summary.md"))).toBe(true);
  });

  it("records no fix for a blank answer", async () => {
    report("a1");
    detectorMock.suggestFix.mockImplementation(async () => "  \n");

    await runScan(projectRoot, opts(), env);

    expect(onDisk("a1").suggestedFix).toBeUndefined();
    expect(findingMd("a1")).not.toContain("Suggested fix");
  });

  it("does not ask again for a finding that already has a fix", async () => {
    report("a1");
    await runScan(projectRoot, opts(), env);

    await runScan(projectRoot, opts(), env);

    expect(detectorMock.suggestFix).toHaveBeenCalledTimes(1);
    expect(onDisk("a1").suggestedFix).toBe("fix for a1");
  });

  it("still writes the report when the provider fails fatally in the fix phase", async () => {
    report("a1", "a2");
    detectorMock.suggestFix.mockImplementation(async ({ finding }: { finding: Finding }) => {
      // Classified as fatal: every later call would fail the same way.
      if (finding.id === "a2") {
        throw new Error("No allowed providers are available for the selected model.");
      }
      return `fix for ${finding.id}`;
    });

    await runScan(projectRoot, opts({ concurrency: 1 }), env);

    expect(findingMd("a1")).toContain("### Suggested fix\nfix for a1");
    expect(findingMd("a2")).not.toContain("Suggested fix");
  });

  it("writes a new fix when validation gives the finding a new verdict", async () => {
    report("a1");
    await runScan(projectRoot, opts(), env);
    detectorMock.suggestFix.mockImplementation(async () => "second fix");

    await runScan(projectRoot, opts({ revalidateAll: true }), env);

    expect(onDisk("a1").suggestedFix).toBe("second fix");
  });

  it("removes the fix of a primary that validation demotes to a duplicate", async () => {
    report("a1", "a2");
    detectorMock.dedupeFindings.mockImplementation(async () => [
      { primaryId: "a1", duplicateIds: ["a2"], reasoning: "same sink" },
    ]);
    await runScan(projectRoot, opts(), env);
    expect(onDisk("a1").suggestedFix).toBe("fix for a1");
    detectorMock.validateFinding.mockImplementation(async () => ({
      verdict: "confirmed",
      reasoning: "stub",
      leadId: "a2",
      primaryClaimHolds: false,
    }));

    await runScan(projectRoot, opts({ revalidateAll: true }), env);

    expect(onDisk("a1").dedup?.duplicateOf).toBe("a2");
    expect(onDisk("a1").suggestedFix).toBeUndefined();
    expect(onDisk("a2").suggestedFix).toBe("fix for a2");
  });
});
