import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FileRecord, Finding } from "@agentgg/core";
import { hashContent, upsertScanMeta, writeFileRecord } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { runSummary } from "../src/commands/summary.js";

let projectRoot: string;
let outputDir: string;
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  projectRoot = mkdtempSync(join(tmpdir(), "agentgg-project-"));
  outputDir = mkdtempSync(join(tmpdir(), "agentgg-out-"));
  env = {};
});

afterEach(() => {
  rmSync(projectRoot, { recursive: true, force: true });
  rmSync(outputDir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: `id-${Math.random().toString(36).slice(2, 10)}`,
    agentSlug: "sql-injection",
    title: "SQLi in handler",
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

function makeRecord(filePath: string, findings: Finding[] = []): FileRecord {
  return {
    agentSlug: findings[0]?.agentSlug ?? "sql-injection",
    filePath,
    contentHash: hashContent("dummy"),
    candidates: [],
    findings,
    analysisHistory: [],
    scope: { outOfScope: false },
    status: findings.length > 0 ? "analyzed" : "pending",
  };
}

describe("runSummary", () => {
  it("errors when no scan state exists at the output dir", async () => {
    await expect(runSummary(outputDir, {}, env)).rejects.toThrow(/No scan state/);
  });

  it("prints a 'no FileRecords' message when state exists but nothing was scanned", async () => {
    upsertScanMeta(outputDir, projectRoot);
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args) => {
      logs.push(args.join(" "));
    });
    await runSummary(outputDir, {}, env);
    expect(logs.join("\n")).toContain("No FileRecords");
    // No report rendered when there's nothing to report.
    expect(existsSync(join(outputDir, "summary.md"))).toBe(false);
  });

  it("renders summary.md + one .md per finding from persisted records", async () => {
    upsertScanMeta(outputDir, projectRoot);
    writeFileRecord(outputDir, makeRecord("server.js", [makeFinding()]));
    vi.spyOn(console, "log").mockImplementation(() => {});

    await runSummary(outputDir, {}, env);

    const summaryPath = join(outputDir, "summary.md");
    expect(existsSync(summaryPath)).toBe(true);
    const summary = readFileSync(summaryPath, "utf8");
    expect(summary).toContain("# Scan summary");
    expect(summary).toContain("SQLi in handler");
    expect(summary).toContain("Total findings:** 1");
  });

  it("respects --exclude-false-positives when rendering per-finding files", async () => {
    upsertScanMeta(outputDir, projectRoot);
    const fp = makeFinding({
      title: "false alarm",
      validation: { verdict: "false-positive", reasoning: "not exploitable" },
    });
    writeFileRecord(outputDir, makeRecord("server.js", [fp]));
    vi.spyOn(console, "log").mockImplementation(() => {});

    await runSummary(outputDir, { excludeFalsePositives: true }, env);

    // The FP is dropped from the per-finding list, but still counted in totals.
    const summary = readFileSync(join(outputDir, "summary.md"), "utf8");
    expect(summary).toContain("Total findings:** 1");
    expect(summary).not.toContain("[false alarm]");
  });
});
