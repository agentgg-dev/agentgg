import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CvssScore, FileRecord, Finding, UserConfig } from "@agentgg/core";
import {
  hashContent,
  readFileRecord,
  saveUserConfig,
  upsertScanMeta,
  writeFileRecord,
} from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const detectorMock = vi.hoisted(() => ({
  scoreFinding: vi.fn(
    async (): Promise<CvssScore> => ({
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      baseScore: 9.8,
      severity: "CRITICAL" as const,
      metrics: {
        attackVector: "N" as const,
        attackComplexity: "L" as const,
        privilegesRequired: "N" as const,
        userInteraction: "N" as const,
        scope: "U" as const,
        confidentiality: "H" as const,
        integrity: "H" as const,
        availability: "H" as const,
      },
      justification: "stub",
    }),
  ),
}));

vi.mock("../src/llm.js", async () => {
  const actual = await vi.importActual<typeof import("../src/llm.js")>("../src/llm.js");
  return {
    ...actual,
    resolveDetector: () => ({
      name: "test-mock",
      scoreFinding: detectorMock.scoreFinding,
    }),
  };
});

import { runScore } from "../src/commands/score.js";

let agentggHome: string;
let projectRoot: string;
let outputDir: string;
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  agentggHome = mkdtempSync(join(tmpdir(), "agentgg-home-"));
  projectRoot = mkdtempSync(join(tmpdir(), "agentgg-project-"));
  outputDir = mkdtempSync(join(tmpdir(), "agentgg-out-"));
  env = { AGENTGG_HOME: agentggHome };

  writeFileSync(join(projectRoot, "server.js"), "const x = 1;", "utf8");
  const cfg: UserConfig = {
    provider: "anthropic",
    anthropic: { apiKey: "sk-ant-test", model: "claude-sonnet-4-6" },
    schemaVersion: 1,
  };
  saveUserConfig(cfg, env);
  detectorMock.scoreFinding.mockClear();
});

afterEach(() => {
  rmSync(agentggHome, { recursive: true, force: true });
  rmSync(projectRoot, { recursive: true, force: true });
  rmSync(outputDir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: `id-${Math.random().toString(36).slice(2, 10)}`,
    agentSlug: "sql-injection",
    title: "SQLi",
    vulnSlug: "sql-injection",
    filePath: "server.js",
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

function makeRecord(findings: Finding[]): FileRecord {
  return {
    agentSlug: "sql-injection",
    filePath: "server.js",
    contentHash: hashContent("dummy"),
    candidates: [],
    findings,
    analysisHistory: [],
    scope: { outOfScope: false },
    status: "analyzed",
  };
}

describe("runScore --no-summary", () => {
  it("re-renders summary.md by default and persists the CVSS score", async () => {
    upsertScanMeta(outputDir, projectRoot);
    writeFileRecord(outputDir, makeRecord([makeFinding()]));
    vi.spyOn(console, "log").mockImplementation(() => {});

    await runScore(outputDir, {}, env);

    expect(detectorMock.scoreFinding).toHaveBeenCalled();
    expect(existsSync(join(outputDir, "summary.md"))).toBe(true);
    const reloaded = readFileRecord(outputDir, "sql-injection", "server.js");
    expect(reloaded?.findings[0].severity).toBe("CRITICAL");
  });

  it("skips the report render with --no-summary but still persists the score", async () => {
    upsertScanMeta(outputDir, projectRoot);
    writeFileRecord(outputDir, makeRecord([makeFinding()]));
    vi.spyOn(console, "log").mockImplementation(() => {});

    await runScore(outputDir, { summary: false }, env);

    expect(existsSync(join(outputDir, "summary.md"))).toBe(false);
    const reloaded = readFileRecord(outputDir, "sql-injection", "server.js");
    expect(reloaded?.findings[0].cvss?.baseScore).toBe(9.8);
  });
});
