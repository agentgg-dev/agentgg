import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CvssScore, FileRecord, Finding, UserConfig } from "@agentgg/core";
import {
  hashContent,
  loadAllFileRecords,
  saveUserConfig,
  upsertScanMeta,
  writeFileRecord,
} from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type ValidateArgs = { finding: Finding; members?: Finding[] };
type ValidateResult = {
  verdict: "confirmed" | "false-positive" | "out-of-scope" | "uncertain";
  reasoning: string;
  confirmedImpact?: string;
  leadId?: string;
  primaryClaimHolds?: boolean;
};

const detectorMock = vi.hoisted(() => ({
  validateFinding: vi.fn(
    async (_args: ValidateArgs): Promise<ValidateResult> => ({
      verdict: "confirmed",
      reasoning: "default mock",
    }),
  ),
}));

vi.mock("../src/llm.js", async () => {
  const actual = await vi.importActual<typeof import("../src/llm.js")>("../src/llm.js");
  return {
    ...actual,
    resolveDetector: () => ({
      name: "test-mock",
      detectFile: async () => [],
      validateFinding: detectorMock.validateFinding,
    }),
  };
});

import { runRevalidate } from "../src/commands/revalidate.js";
import { fitMembers } from "../src/validator.js";

const FILE = "server.js";

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

let agentggHome: string;
let projectRoot: string;
let outputDir: string;
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  agentggHome = mkdtempSync(join(tmpdir(), "agentgg-home-"));
  projectRoot = mkdtempSync(join(tmpdir(), "agentgg-project-"));
  outputDir = mkdtempSync(join(tmpdir(), "agentgg-out-"));
  env = { AGENTGG_HOME: agentggHome };
  const cfg: UserConfig = {
    provider: "anthropic",
    anthropic: { apiKey: "sk-ant-test", model: "claude-sonnet-4-6" },
    schemaVersion: 1,
  };
  saveUserConfig(cfg, env);
  upsertScanMeta(outputDir, projectRoot);
  mkdirSync(projectRoot, { recursive: true });
  writeFileSync(join(projectRoot, FILE), "const x = 1;", "utf8");
});

afterEach(() => {
  rmSync(agentggHome, { recursive: true, force: true });
  rmSync(projectRoot, { recursive: true, force: true });
  rmSync(outputDir, { recursive: true, force: true });
  vi.restoreAllMocks();
  detectorMock.validateFinding.mockReset();
});

function makeFinding(id: string, agentSlug: string, overrides: Partial<Finding> = {}): Finding {
  return {
    id,
    agentSlug,
    title: id,
    vulnSlug: "sql-injection",
    filePath: FILE,
    summary: "s",
    details: "d",
    poc: "p",
    impact: "i",
    references: [],
    confidence: 0.8,
    notifications: [],
    ...overrides,
  };
}

function writeRecord(agentSlug: string, findings: Finding[]): void {
  const record: FileRecord = {
    agentSlug,
    filePath: FILE,
    contentHash: hashContent("dummy"),
    candidates: [],
    findings,
    analysisHistory: [],
    scope: { outOfScope: false },
    status: "validated",
  };
  writeFileRecord(outputDir, record);
}

const dupeOf = (primaryId: string) => ({ dedup: { duplicateOf: primaryId, reasoning: "same" } });

function writeThreeAgentGroup(): void {
  writeRecord("sql-a", [
    makeFinding("p1", "sql-a", {
      validation: { verdict: "uncertain", reasoning: "old" },
      cvss: CVSS,
      severity: "CRITICAL",
      live: { result: "reproduced", reasoning: "old", counterevidence: "" },
    }),
  ]);
  writeRecord("sql-b", [makeFinding("d1", "sql-b", dupeOf("p1"))]);
  writeRecord("sql-c", [makeFinding("d2", "sql-c", dupeOf("p1"))]);
}

function findingsById(): Map<string, Finding> {
  const onDisk = loadAllFileRecords(outputDir).flatMap((r) => r.findings);
  return new Map(onDisk.map((x) => [x.id, x]));
}

const calls = () => detectorMock.validateFinding.mock.calls.map(([args]) => args);

describe("group validation in revalidate", () => {
  it("validates a group once, swaps to the lead, and clears the old primary's stale results on disk", async () => {
    writeThreeAgentGroup();
    detectorMock.validateFinding.mockImplementation(async () => ({
      verdict: "confirmed",
      reasoning: "r",
      confirmedImpact: "ci",
      leadId: "d1",
      primaryClaimHolds: false,
    }));
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args) => {
      logs.push(args.join(" "));
    });

    await runRevalidate(outputDir, { force: true, concurrency: 1, summary: false }, env);

    expect(calls()).toHaveLength(1);
    expect(calls()[0].finding.id).toBe("p1");
    expect(calls()[0].members?.map((m) => m.id)).toEqual(["d1", "d2"]);

    const byId = findingsById();
    expect(byId.get("d1")?.dedup).toBeUndefined();
    expect(byId.get("d1")?.validation?.confirmedImpact).toBe("ci");
    expect(byId.get("p1")?.dedup?.duplicateOf).toBe("d1");
    expect(byId.get("p1")?.validation).toBeUndefined();
    expect(byId.get("p1")?.cvss).toBeUndefined();
    expect(byId.get("p1")?.severity).toBeUndefined();
    expect(byId.get("p1")?.live).toBeUndefined();
    expect(byId.get("d2")?.dedup?.duplicateOf).toBe("d1");
    expect(logs.join("\n")).toContain(`agentgg score ${outputDir}`);
  });

  it("keeps the specialist primary when its claim holds", async () => {
    writeThreeAgentGroup();
    detectorMock.validateFinding.mockImplementation(async () => ({
      verdict: "confirmed",
      reasoning: "r",
      confirmedImpact: "ci",
      leadId: "d1",
      primaryClaimHolds: true,
    }));
    vi.spyOn(console, "log").mockImplementation(() => {});

    await runRevalidate(outputDir, { force: true, concurrency: 1, summary: false }, env);

    const byId = findingsById();
    expect(byId.get("p1")?.dedup).toBeUndefined();
    expect(byId.get("p1")?.validation?.confirmedImpact).toBe("ci");
    expect(byId.get("d1")?.dedup?.duplicateOf).toBe("p1");
  });

  it("validates the members a rejected group left out, and promotes a survivor", async () => {
    // Long enough that the member cap shows only some of them.
    const long = (n: number) => "x".repeat(n);
    const dupes = Array.from({ length: 10 }, (_, i) =>
      makeFinding(`d${i}`, "sql-b", {
        ...dupeOf("p1"),
        summary: long(420),
        impact: long(620),
        poc: long(820),
      }),
    );
    writeRecord("sql-a", [makeFinding("p1", "sql-a")]);
    writeRecord("sql-b", dupes);
    detectorMock.validateFinding.mockImplementation(async ({ finding }) =>
      finding.id === "p1"
        ? { verdict: "false-positive", reasoning: "no" }
        : { verdict: "confirmed", reasoning: "r" },
    );
    vi.spyOn(console, "log").mockImplementation(() => {});

    await runRevalidate(outputDir, { force: true, concurrency: 1, summary: false }, env);

    const { shown, left } = fitMembers(dupes);
    expect(shown.length).toBeGreaterThan(0);
    expect(left.length).toBeGreaterThan(0);
    const calledIds = calls().map((c) => c.finding.id);
    expect(calledIds[0]).toBe("p1");
    expect(new Set(calledIds.slice(1))).toEqual(new Set(left.map((m) => m.id)));

    const byId = findingsById();
    const heir = byId.get(left[0].id);
    expect(heir?.dedup).toBeUndefined();
    expect(heir?.validation?.verdict).toBe("confirmed");
    expect(byId.get("p1")?.dedup?.duplicateOf).toBe(left[0].id);
  });

  it("runs no second wave when the rejected group showed every member", async () => {
    writeRecord("sql-a", [makeFinding("p1", "sql-a")]);
    writeRecord("sql-b", [makeFinding("d1", "sql-b", dupeOf("p1"))]);
    detectorMock.validateFinding.mockImplementation(async () => ({
      verdict: "false-positive",
      reasoning: "no",
    }));
    vi.spyOn(console, "log").mockImplementation(() => {});

    await runRevalidate(outputDir, { force: true, concurrency: 1, summary: false }, env);

    expect(calls().map((c) => c.finding.id)).toEqual(["p1"]);
    const byId = findingsById();
    expect(byId.get("p1")?.dedup).toBeUndefined();
    expect(byId.get("d1")?.dedup?.duplicateOf).toBe("p1");
  });
});
