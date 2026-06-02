import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { FileRecord, Finding, UserConfig } from "@agentgg/core";
import {
  completeRun,
  createRunMeta,
  hashContent,
  listRuns,
  readFileRecord,
  saveUserConfig,
  upsertScanMeta,
  writeFileRecord,
  writeRunMeta,
} from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Hoisted mock so it's in place before revalidate.ts pulls in
// `resolveDetector`. A single mutable stub the tests can reconfigure.
const detectorMock = vi.hoisted(() => ({
  validateFinding: vi.fn(async () => ({
    verdict: "confirmed" as const,
    reasoning: "default mock",
  })),
}));

vi.mock("../src/llm.js", async () => {
  const actual = await vi.importActual<typeof import("../src/llm.js")>("../src/llm.js");
  return {
    ...actual,
    resolveDetector: () => ({
      name: "test-mock",
      detectFile: async () => [],
      hunt: async () => [],
      validateFinding: detectorMock.validateFinding,
    }),
  };
});

import { runRevalidate } from "../src/commands/revalidate.js";
import { runStatus } from "../src/commands/status.js";

let agentggHome: string;
let projectRoot: string;
let outputDir: string;
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  agentggHome = mkdtempSync(join(tmpdir(), "agentgg-home-"));
  projectRoot = mkdtempSync(join(tmpdir(), "agentgg-project-"));
  outputDir = mkdtempSync(join(tmpdir(), "agentgg-out-"));
  env = { AGENTGG_HOME: agentggHome };
});

afterEach(() => {
  rmSync(agentggHome, { recursive: true, force: true });
  rmSync(projectRoot, { recursive: true, force: true });
  rmSync(outputDir, { recursive: true, force: true });
  vi.restoreAllMocks();
  detectorMock.validateFinding.mockReset();
  detectorMock.validateFinding.mockImplementation(async () => ({
    verdict: "confirmed",
    reasoning: "default mock",
  }));
});

function writeFile(rel: string, content: string): void {
  const abs = join(projectRoot, rel);
  mkdirSync(join(abs, ".."), { recursive: true });
  writeFileSync(abs, content, "utf8");
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: `id-${Math.random().toString(36).slice(2, 10)}`,
    agentSlug: "sql-injection",
    title: "test",
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

function saveAnthropicConfig(): void {
  const cfg: UserConfig = {
    provider: "anthropic",
    anthropic: { apiKey: "sk-ant-test", model: "claude-sonnet-4-6" },
    schemaVersion: 1,
  };
  saveUserConfig(cfg, env);
}

// ---------- status ----------

describe("runStatus", () => {
  it("prints a helpful 'no scan state' message when nothing exists on disk", async () => {
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args) => {
      logs.push(args.join(" "));
    });
    await runStatus(outputDir, {});
    const out = logs.join("\n");
    expect(out).toContain("No scan state");
    expect(out).toContain("agentgg scan");
  });

  it("emits raw JSON with exists: false when --json + no state", async () => {
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args) => {
      logs.push(args.join(" "));
    });
    await runStatus(outputDir, { json: true });
    const out = JSON.parse(logs[0]);
    expect(out.exists).toBe(false);
    expect(out.outputDir).toBe(resolve(outputDir));
  });

  it("renders status counts and verdict breakdown when records exist", async () => {
    upsertScanMeta(outputDir, projectRoot);
    const confirmed = makeFinding({
      validation: { verdict: "confirmed", reasoning: "x" },
    });
    const fp = makeFinding({
      validation: { verdict: "false-positive", reasoning: "y" },
    });
    const unvalidated = makeFinding();
    const rec = makeRecord("server.js", [confirmed, fp, unvalidated]);
    rec.status = "validated";
    writeFileRecord(outputDir, rec);

    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args) => {
      logs.push(args.join(" "));
    });
    await runStatus(outputDir, {});
    const out = logs.join("\n");
    expect(out).toContain("Scan state");
    expect(out).toContain("Files tracked:  1");
    expect(out).toContain("validated:  1");
    expect(out).toContain("total:      3");
    expect(out).toContain("validated:  2/3");
    expect(out).toContain("confirmed=1");
    expect(out).toContain("false-positive=1");
  });

  it("lists recent runs newest-first", async () => {
    upsertScanMeta(outputDir, projectRoot);
    const r1 = createRunMeta({ type: "scan" });
    writeRunMeta(outputDir, r1);
    completeRun(outputDir, r1.runId, "done", { filesScanned: 5, findingsCount: 2 });
    const r2 = { ...createRunMeta({ type: "validate" }) };
    r2.startedAt = new Date(Date.now() + 1000).toISOString();
    writeRunMeta(outputDir, r2);

    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args) => {
      logs.push(args.join(" "));
    });
    await runStatus(outputDir, {});
    const out = logs.join("\n");
    const idx1 = out.indexOf(r1.runId);
    const idx2 = out.indexOf(r2.runId);
    expect(idx2).toBeGreaterThan(-1);
    expect(idx1).toBeGreaterThan(-1);
    expect(idx2).toBeLessThan(idx1);
  });

  it("--json includes filesTracked, statusCounts, verdict counts, runs", async () => {
    upsertScanMeta(outputDir, projectRoot);
    writeFileRecord(outputDir, makeRecord("a.ts", [makeFinding()]));
    const run = createRunMeta({ type: "scan" });
    writeRunMeta(outputDir, run);
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args) => {
      logs.push(args.join(" "));
    });
    await runStatus(outputDir, { json: true });
    const out = JSON.parse(logs[0]);
    expect(out.outputDir).toBe(resolve(outputDir));
    expect(out.filesTracked).toBe(1);
    expect(out.findings.total).toBe(1);
    expect(out.recentRuns).toHaveLength(1);
    expect(out.recentRuns[0].runId).toBe(run.runId);
  });
});

// ---------- revalidate ----------

describe("runRevalidate", () => {
  it("errors when no scan state exists at the output dir", async () => {
    saveAnthropicConfig();
    await expect(runRevalidate(outputDir, {}, env)).rejects.toThrow(/No scan state/);
  });

  it("errors when no config exists", async () => {
    upsertScanMeta(outputDir, projectRoot);
    await expect(runRevalidate(outputDir, {}, env)).rejects.toThrow(/No agentgg config/);
  });

  it("returns early when nothing needs revalidating (no --force)", async () => {
    saveAnthropicConfig();
    upsertScanMeta(outputDir, projectRoot);
    writeFile("server.js", "const x = 1;");
    const already = makeFinding({
      validation: { verdict: "confirmed", reasoning: "x" },
    });
    writeFileRecord(outputDir, makeRecord("server.js", [already]));

    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args) => {
      logs.push(args.join(" "));
    });
    await runRevalidate(outputDir, {}, env);
    const out = logs.join("\n");
    expect(out).toContain("Nothing to revalidate");
  });

  it("validates pending findings via the detector and writes verdicts back to disk", async () => {
    saveAnthropicConfig();
    upsertScanMeta(outputDir, projectRoot);
    writeFile("server.js", "const x = 1;");
    writeFileRecord(outputDir, makeRecord("server.js", [makeFinding()]));

    detectorMock.validateFinding.mockImplementation(async () => ({
      verdict: "false-positive",
      reasoning: "stub said so",
    }));

    await runRevalidate(outputDir, { concurrency: 1 }, env);

    const reloaded = readFileRecord(outputDir, "sql-injection", "server.js");
    expect(reloaded?.findings[0].validation?.verdict).toBe("false-positive");
    expect(reloaded?.findings[0].validation?.reasoning).toBe("stub said so");
    expect(reloaded?.status).toBe("validated");
    const validateEntries = reloaded?.analysisHistory.filter((a) => a.phase === "validate");
    expect(validateEntries?.length).toBe(1);
    expect(validateEntries?.[0].provider).toBe("test-mock");
  });

  it("--force re-validates findings that already have a verdict", async () => {
    saveAnthropicConfig();
    upsertScanMeta(outputDir, projectRoot);
    writeFile("server.js", "const x = 1;");
    const f = makeFinding({
      validation: { verdict: "uncertain", reasoning: "old" },
    });
    writeFileRecord(outputDir, makeRecord("server.js", [f]));

    detectorMock.validateFinding.mockImplementation(async () => ({
      verdict: "confirmed",
      reasoning: "new",
    }));

    await runRevalidate(outputDir, { force: true, concurrency: 1 }, env);

    const reloaded = readFileRecord(outputDir, "sql-injection", "server.js");
    expect(reloaded?.findings[0].validation?.verdict).toBe("confirmed");
    expect(reloaded?.findings[0].validation?.reasoning).toBe("new");
  });

  it("creates a RunMeta of type 'validate' and marks it done", async () => {
    saveAnthropicConfig();
    upsertScanMeta(outputDir, projectRoot);
    writeFile("server.js", "const x = 1;");
    writeFileRecord(outputDir, makeRecord("server.js", [makeFinding()]));

    await runRevalidate(outputDir, { concurrency: 1 }, env);

    const runs = listRuns(outputDir);
    const validateRuns = runs.filter((r) => r.type === "validate");
    expect(validateRuns.length).toBe(1);
    expect(validateRuns[0].phase).toBe("done");
    expect(validateRuns[0].completedAt).toBeDefined();
  });

  it("skips findings whose file no longer exists on disk", async () => {
    saveAnthropicConfig();
    upsertScanMeta(outputDir, projectRoot);
    // File never written — readFileSync should fail.
    writeFileRecord(
      outputDir,
      makeRecord("vanished.ts", [makeFinding({ filePath: "vanished.ts" })]),
    );

    await runRevalidate(outputDir, { concurrency: 1 }, env);

    expect(detectorMock.validateFinding).not.toHaveBeenCalled();
    const reloaded = readFileRecord(outputDir, "sql-injection", "vanished.ts");
    expect(reloaded?.findings[0].validation).toBeUndefined();
  });

  it("errors when --scope points at a missing file", async () => {
    saveAnthropicConfig();
    upsertScanMeta(outputDir, projectRoot);
    writeFile("server.js", "x");
    writeFileRecord(outputDir, makeRecord("server.js", [makeFinding()]));
    await expect(
      runRevalidate(outputDir, { scope: resolve(projectRoot, "no-scope.md") }, env),
    ).rejects.toThrow(/--scope:/);
  });

  it("uses --root override when the scanned root has moved", async () => {
    saveAnthropicConfig();
    // scan.json points at the original path, but pass a different
    // --root with a real file present.
    upsertScanMeta(outputDir, "/nonexistent/old/root");
    writeFile("server.js", "const real = 1;");
    writeFileRecord(outputDir, makeRecord("server.js", [makeFinding()]));

    await runRevalidate(outputDir, { root: projectRoot, concurrency: 1 }, env);

    const reloaded = readFileRecord(outputDir, "sql-injection", "server.js");
    expect(reloaded?.findings[0].validation?.verdict).toBe("confirmed");
  });

  it("re-renders summary.md by default after validation", async () => {
    saveAnthropicConfig();
    upsertScanMeta(outputDir, projectRoot);
    writeFile("server.js", "const x = 1;");
    writeFileRecord(outputDir, makeRecord("server.js", [makeFinding()]));
    vi.spyOn(console, "log").mockImplementation(() => {});

    await runRevalidate(outputDir, { concurrency: 1 }, env);

    expect(existsSync(join(outputDir, "summary.md"))).toBe(true);
  });

  it("--no-summary skips the report render but still persists verdicts", async () => {
    saveAnthropicConfig();
    upsertScanMeta(outputDir, projectRoot);
    writeFile("server.js", "const x = 1;");
    writeFileRecord(outputDir, makeRecord("server.js", [makeFinding()]));
    detectorMock.validateFinding.mockImplementation(async () => ({
      verdict: "false-positive",
      reasoning: "stub",
    }));
    vi.spyOn(console, "log").mockImplementation(() => {});

    await runRevalidate(outputDir, { concurrency: 1, summary: false }, env);

    // No report file written…
    expect(existsSync(join(outputDir, "summary.md"))).toBe(false);
    // …but the verdict landed on disk.
    const reloaded = readFileRecord(outputDir, "sql-injection", "server.js");
    expect(reloaded?.findings[0].validation?.verdict).toBe("false-positive");
  });
});
