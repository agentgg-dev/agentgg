import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FileRecord, Finding, UserConfig } from "@agentgg/core";
import {
  hashContent,
  listRuns,
  readFileRecord,
  saveUserConfig,
  upsertScanMeta,
  writeFileRecord,
} from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const detectorMock = vi.hoisted(() => ({
  suggestFix: vi.fn(),
  /** The options each `resolveDetector` call received. */
  resolved: [] as Record<string, unknown>[],
}));

vi.mock("../src/llm.js", async () => {
  const actual = await vi.importActual<typeof import("../src/llm.js")>("../src/llm.js");
  return {
    ...actual,
    resolveDetector: (_config: unknown, options: Record<string, unknown>) => {
      detectorMock.resolved.push(options);
      return { name: "test-mock", suggestFix: detectorMock.suggestFix };
    },
  };
});

import { runFix } from "../src/commands/fix.js";
import { FatalScanError } from "../src/diagnostics.js";
import { findingFilename } from "../src/reporters/md.js";

const CONFIRMED = { verdict: "confirmed", reasoning: "r" } as const;

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
  detectorMock.resolved.length = 0;
  detectorMock.suggestFix.mockReset();
  detectorMock.suggestFix.mockImplementation(
    async ({ finding }: { finding: Finding }) => `fix for ${finding.id}`,
  );
  vi.spyOn(console, "log").mockImplementation(() => {});
});

afterEach(() => {
  rmSync(agentggHome, { recursive: true, force: true });
  rmSync(projectRoot, { recursive: true, force: true });
  rmSync(outputDir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

function makeFinding(id: string, overrides: Partial<Finding> = {}): Finding {
  return {
    id,
    agentSlug: "sql-injection",
    title: `SQLi ${id}`,
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

function seed(findings: Finding[]): void {
  const record: FileRecord = {
    agentSlug: "sql-injection",
    filePath: "server.js",
    contentHash: hashContent("dummy"),
    candidates: [],
    findings,
    analysisHistory: [],
    scope: { outOfScope: false },
    status: "validated",
  };
  upsertScanMeta(outputDir, projectRoot);
  writeFileRecord(outputDir, record);
}

function onDisk(id: string): Finding {
  const f = readFileRecord(outputDir, "sql-injection", "server.js")?.findings.find(
    (x) => x.id === id,
  );
  if (!f) throw new Error(`no finding ${id} on disk`);
  return f;
}

const fixedIds = () =>
  detectorMock.suggestFix.mock.calls.map((c) => (c[0] as { finding: Finding }).finding.id);

describe("runFix", () => {
  it("writes a fix for a confirmed finding and renders it in the report", async () => {
    seed([makeFinding("a1", { validation: CONFIRMED })]);

    await runFix(outputDir, {}, env);

    expect(onDisk("a1").suggestedFix).toBe("fix for a1");
    const md = readFileSync(join(outputDir, "findings", findingFilename(onDisk("a1"))), "utf8");
    expect(md).toContain("### Suggested fix\nfix for a1");
  });

  it("writes a fix for a finding only a live run confirmed", async () => {
    seed([
      makeFinding("a1", {
        validation: { verdict: "uncertain", reasoning: "r" },
        live: { result: "reproduced", reasoning: "r", counterevidence: "" },
      }),
    ]);

    await runFix(outputDir, {}, env);

    expect(onDisk("a1").suggestedFix).toBe("fix for a1");
  });

  it("asks for a fix only for confirmed primaries", async () => {
    seed([
      makeFinding("a1", { validation: CONFIRMED }),
      makeFinding("a2", { validation: { verdict: "uncertain", reasoning: "r" } }),
      makeFinding("a3", { validation: { verdict: "false-positive", reasoning: "r" } }),
      makeFinding("a4"),
      makeFinding("a5", { dedup: { duplicateOf: "a1", reasoning: "same" } }),
    ]);

    await runFix(outputDir, { force: true }, env);

    expect(fixedIds()).toEqual(["a1"]);
    for (const id of ["a2", "a3", "a4", "a5"]) expect(onDisk(id).suggestedFix).toBeUndefined();
  });

  it("skips a finding that already has a fix", async () => {
    seed([makeFinding("a1", { validation: CONFIRMED, suggestedFix: "old fix" })]);

    await runFix(outputDir, {}, env);

    expect(detectorMock.suggestFix).not.toHaveBeenCalled();
    expect(onDisk("a1").suggestedFix).toBe("old fix");
  });

  it("writes the fix again with --force", async () => {
    seed([makeFinding("a1", { validation: CONFIRMED, suggestedFix: "old fix" })]);

    await runFix(outputDir, { force: true }, env);

    expect(onDisk("a1").suggestedFix).toBe("fix for a1");
  });

  it("keeps the old fix when a --force call returns nothing", async () => {
    seed([makeFinding("a1", { validation: CONFIRMED, suggestedFix: "old fix" })]);
    detectorMock.suggestFix.mockImplementation(async () => "");

    await runFix(outputDir, { force: true }, env);

    expect(onDisk("a1").suggestedFix).toBe("old fix");
  });

  it("skips the report render with --no-summary but still persists the fix", async () => {
    seed([makeFinding("a1", { validation: CONFIRMED })]);

    await runFix(outputDir, { summary: false }, env);

    expect(existsSync(join(outputDir, "summary.md"))).toBe(false);
    expect(onDisk("a1").suggestedFix).toBe("fix for a1");
  });

  it("keeps and renders the fixes written before a fatal provider error, then fails", async () => {
    seed([
      makeFinding("a1", { validation: CONFIRMED }),
      makeFinding("a2", { validation: CONFIRMED }),
    ]);
    vi.spyOn(console, "warn").mockImplementation(() => {});
    detectorMock.suggestFix.mockImplementation(async ({ finding }: { finding: Finding }) => {
      // Classified as fatal: every later call would fail the same way.
      if (finding.id === "a2") {
        throw new Error("No allowed providers are available for the selected model.");
      }
      return `fix for ${finding.id}`;
    });

    await expect(runFix(outputDir, { concurrency: 1 }, env)).rejects.toBeInstanceOf(FatalScanError);

    expect(onDisk("a1").suggestedFix).toBe("fix for a1");
    const md = readFileSync(join(outputDir, "findings", findingFilename(onDisk("a1"))), "utf8");
    expect(md).toContain("### Suggested fix\nfix for a1");
    expect(listRuns(outputDir)[0].phase).toBe("error");
  });

  it("gives the detector the same credentials and routing the other commands do", async () => {
    seed([makeFinding("a1", { validation: CONFIRMED })]);

    await runFix(outputDir, { apiKey: "sk-test", openrouterRouting: '{"sort":"price"}' }, env);

    expect(detectorMock.resolved[0]).toMatchObject({
      credentials: { openrouterApiKey: "sk-test" },
      openrouterRouting: '{"sort":"price"}',
    });
  });

  it("rejects a credential flag the active provider does not take", async () => {
    seed([makeFinding("a1", { validation: CONFIRMED })]);

    await expect(runFix(outputDir, { region: "us-east-1" }, env)).rejects.toThrow(
      /not valid for provider 'anthropic'/,
    );
  });

  it("fails when the output directory holds no scan", async () => {
    await expect(runFix(outputDir, {}, env)).rejects.toThrow(/No scan state/);
  });
});
