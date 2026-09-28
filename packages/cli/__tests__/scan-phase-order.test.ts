import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CvssScore, Finding, UserConfig } from "@agentgg/core";
import { readFileRecord, saveUserConfig } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const FILE = "app.js";

/** An agent that anchors on every `TARGET` line, so the fixture controls
 *  which files reach the detector. */
function writeAgent(dir: string, slug: string): string {
  const body = `---
slug: ${slug}
name: ${slug}
description: Synthetic agent for phase-order tests.
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

function mockFinding(slug: string, id: string): Finding {
  return {
    id,
    agentSlug: slug,
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
  runAgent: vi.fn(async (_args: { agent: { slug: string } }) => [] as Finding[]),
  validateFinding: vi.fn(
    async (_args: {
      finding: Finding;
    }): Promise<{
      verdict: "confirmed" | "false-positive" | "out-of-scope" | "uncertain";
      reasoning: string;
      leadId?: string;
      primaryClaimHolds?: boolean;
    }> => ({ verdict: "confirmed", reasoning: "stub" }),
  ),
  scoreFinding: vi.fn(async (_args: { finding: Finding }) => ({}) as CvssScore),
  dedupeFindings: vi.fn(
    async (_args: { filePath: string; findings: Finding[] }) =>
      [] as { primaryId: string; duplicateIds: string[]; reasoning: string }[],
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
      validateFinding: detectorMock.validateFinding,
      scoreFinding: detectorMock.scoreFinding,
      dedupeFindings: detectorMock.dedupeFindings,
    }),
  };
});

import { runScan } from "../src/commands/scan.js";
import { fitMembers } from "../src/validator.js";

let agentggHome: string;
let projectRoot: string;
let outputDir: string;
let agentsDir: string;
let alphaPath: string;
let betaPath: string;
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  agentggHome = mkdtempSync(join(tmpdir(), "agentgg-home-"));
  projectRoot = mkdtempSync(join(tmpdir(), "agentgg-target-"));
  outputDir = mkdtempSync(join(tmpdir(), "agentgg-out-"));
  agentsDir = mkdtempSync(join(tmpdir(), "agentgg-agents-"));
  alphaPath = writeAgent(agentsDir, "alpha");
  betaPath = writeAgent(agentsDir, "beta");
  env = { AGENTGG_HOME: agentggHome };

  writeFileSync(join(projectRoot, FILE), "TARGET one\nTARGET two\n", "utf8");

  const cfg: UserConfig = {
    provider: "anthropic",
    anthropic: { apiKey: "sk-ant-test", model: "claude-sonnet-4-6" },
    schemaVersion: 1,
  };
  saveUserConfig(cfg, env);

  detectorMock.scoreFinding.mockImplementation(async () => CVSS);
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
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
  detectorMock.scoreFinding.mockReset();
  detectorMock.dedupeFindings.mockReset();
  for (const h of process.listeners("SIGINT")) {
    process.removeListener("SIGINT", h);
  }
});

const opts = () => ({
  template: [alphaPath, betaPath],
  output: outputDir,
  validate: true,
  score: true,
  dedup: true,
});

/** The phase labels a shard recorded, in the order they were appended. */
function phasesOf(agentSlug: string): string[] {
  const record = readFileRecord(outputDir, agentSlug, FILE);
  if (!record) throw new Error(`no record for ${agentSlug}/${FILE}`);
  return record.analysisHistory.map((h) => h.phase);
}

function findingOnDisk(agentSlug: string, id: string): Finding {
  const record = readFileRecord(outputDir, agentSlug, FILE);
  const f = record?.findings.find((x) => x.id === id);
  if (!f) throw new Error(`no finding ${id} in ${agentSlug}/${FILE}`);
  return f;
}

describe("scan phase order", () => {
  it("dedupes before validating, and leaves duplicates unvalidated and unscored", async () => {
    // alpha reports the primary plus one duplicate; beta reports a third
    // finding on the same file. alpha's shard therefore records both the
    // dedup pass (for its duplicate) and the validate pass (for its primary).
    detectorMock.runAgent.mockImplementation(async ({ agent }) =>
      agent.slug === "alpha"
        ? [mockFinding("alpha", "alpha-primary"), mockFinding("alpha", "alpha-dupe")]
        : [mockFinding("beta", "beta-dupe")],
    );
    detectorMock.dedupeFindings.mockImplementation(async () => [
      {
        primaryId: "alpha-primary",
        duplicateIds: ["alpha-dupe", "beta-dupe"],
        reasoning: "same sink",
      },
    ]);

    await runScan(projectRoot, opts(), env);

    const alpha = phasesOf("alpha");
    expect(alpha).toContain("dedup");
    expect(alpha).toContain("validate");
    expect(alpha.indexOf("dedup")).toBeLessThan(alpha.indexOf("validate"));

    for (const [slug, id] of [
      ["alpha", "alpha-dupe"],
      ["beta", "beta-dupe"],
    ] as const) {
      const dupe = findingOnDisk(slug, id);
      expect(dupe.dedup?.duplicateOf).toBe("alpha-primary");
      expect(dupe.validation).toBeUndefined();
      expect(dupe.cvss).toBeUndefined();
    }

    const primary = findingOnDisk("alpha", "alpha-primary");
    expect(primary.validation?.verdict).toBe("confirmed");
    expect(primary.cvss?.baseScore).toBe(9.8);

    // Only the primary cost a validation call.
    expect(detectorMock.validateFinding).toHaveBeenCalledTimes(1);
  });

  it("validates a group once and moves it to the lead when the primary's claim fails", async () => {
    detectorMock.runAgent.mockImplementation(async ({ agent }) =>
      agent.slug === "alpha" ? [mockFinding("alpha", "alpha-1")] : [mockFinding("beta", "beta-1")],
    );
    detectorMock.dedupeFindings.mockImplementation(async () => [
      { primaryId: "alpha-1", duplicateIds: ["beta-1"], reasoning: "same sink" },
    ]);
    detectorMock.validateFinding.mockImplementation(async () => ({
      verdict: "confirmed" as const,
      reasoning: "reachable",
      leadId: "beta-1",
      primaryClaimHolds: false,
    }));

    await runScan(projectRoot, opts(), env);

    const call = detectorMock.validateFinding.mock.calls[0][0] as {
      finding: Finding;
      members?: Finding[];
    };
    expect(detectorMock.validateFinding).toHaveBeenCalledTimes(1);
    expect(call.finding.id).toBe("alpha-1");
    expect(call.members?.map((m) => m.id)).toEqual(["beta-1"]);

    const demoted = findingOnDisk("alpha", "alpha-1");
    expect(demoted.dedup?.duplicateOf).toBe("beta-1");
    expect(demoted.validation).toBeUndefined();
    expect(demoted.cvss).toBeUndefined();

    const heir = findingOnDisk("beta", "beta-1");
    expect(heir.dedup).toBeUndefined();
    expect(heir.validation?.verdict).toBe("confirmed");
    expect(heir.cvss?.baseScore).toBe(9.8);
  });

  it("runs no second wave when a rejected group showed every member", async () => {
    detectorMock.runAgent.mockImplementation(async ({ agent }) =>
      agent.slug === "alpha" ? [mockFinding("alpha", "alpha-1")] : [mockFinding("beta", "beta-1")],
    );
    detectorMock.dedupeFindings.mockImplementation(async () => [
      { primaryId: "alpha-1", duplicateIds: ["beta-1"], reasoning: "same sink" },
    ]);
    detectorMock.validateFinding.mockImplementation(async () => ({
      verdict: "false-positive" as const,
      reasoning: "not reachable",
    }));

    await runScan(projectRoot, opts(), env);

    expect(detectorMock.validateFinding).toHaveBeenCalledTimes(1);
    expect(findingOnDisk("alpha", "alpha-1").dedup).toBeUndefined();
    expect(findingOnDisk("beta", "beta-1").dedup?.duplicateOf).toBe("alpha-1");
  });

  it("validates the members a rejected group left out, and promotes a survivor", async () => {
    // Long enough that the member cap shows only some of them.
    const long = (n: number) => "x".repeat(n);
    const dupes = Array.from({ length: 10 }, (_, i) => ({
      ...mockFinding("beta", `beta-${i}`),
      summary: long(420),
      impact: long(620),
      poc: long(820),
    }));
    detectorMock.runAgent.mockImplementation(async ({ agent }) =>
      agent.slug === "alpha" ? [mockFinding("alpha", "alpha-1")] : dupes,
    );
    detectorMock.dedupeFindings.mockImplementation(async () => [
      { primaryId: "alpha-1", duplicateIds: dupes.map((d) => d.id), reasoning: "same sink" },
    ]);
    detectorMock.validateFinding.mockImplementation(async ({ finding }) =>
      finding.id === "alpha-1"
        ? { verdict: "false-positive" as const, reasoning: "not reachable" }
        : { verdict: "confirmed" as const, reasoning: "reachable" },
    );

    await runScan(projectRoot, opts(), env);

    const calls = detectorMock.validateFinding.mock.calls.map(
      ([args]) => args as { finding: Finding; members?: Finding[] },
    );
    expect(calls[0].finding.id).toBe("alpha-1");
    const { shown, left } = fitMembers(calls[0].members ?? []);
    expect(shown.length).toBeGreaterThan(0);
    expect(left.length).toBeGreaterThan(0);
    expect(new Set(calls.slice(1).map((c) => c.finding.id))).toEqual(
      new Set(left.map((m) => m.id)),
    );

    const heir = findingOnDisk("beta", left[0].id);
    expect(heir.dedup).toBeUndefined();
    expect(heir.validation?.verdict).toBe("confirmed");
    expect(heir.cvss?.baseScore).toBe(9.8);
    expect(findingOnDisk("alpha", "alpha-1").dedup?.duplicateOf).toBe(left[0].id);
  });

  it("keeps the lead under --delete-duplicates and deletes the rest", async () => {
    detectorMock.runAgent.mockImplementation(async ({ agent }) =>
      agent.slug === "alpha"
        ? [mockFinding("alpha", "alpha-1"), mockFinding("alpha", "alpha-2")]
        : [mockFinding("beta", "beta-1")],
    );
    detectorMock.dedupeFindings.mockImplementation(async () => [
      { primaryId: "alpha-1", duplicateIds: ["beta-1", "alpha-2"], reasoning: "same sink" },
    ]);
    detectorMock.validateFinding.mockImplementation(async () => ({
      verdict: "confirmed" as const,
      reasoning: "reachable",
      leadId: "beta-1",
      primaryClaimHolds: false,
    }));

    await runScan(projectRoot, { ...opts(), deleteDuplicates: true }, env);

    // beta-1 became the primary during validation, so it survives deletion.
    const heir = findingOnDisk("beta", "beta-1");
    expect(heir.dedup).toBeUndefined();
    expect(heir.cvss?.baseScore).toBe(9.8);

    // The demoted primary and the remaining duplicate are gone from disk.
    const alpha = readFileRecord(outputDir, "alpha", FILE);
    expect(alpha?.findings.map((f) => f.id)).toEqual([]);
  });
});
