import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { FileRecord, Finding } from "@agentgg/core";
import { hashContent, readFileRecord, writeFileRecord } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Detector } from "../src/detect.js";
import { FatalScanError } from "../src/diagnostics.js";
import { runFixPhase, selectForFix } from "../src/fix-phase.js";

const CONFIRMED = { verdict: "confirmed", reasoning: "r" } as const;
// Classified as fatal: every later call would fail the same way.
const FATAL = "No allowed providers are available for the selected model.";

let root: string;
let outDir: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "agentgg-project-"));
  outDir = mkdtempSync(join(tmpdir(), "agentgg-out-"));
  writeFileSync(join(root, "server.js"), "const x = 1;", "utf8");
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
  rmSync(outDir, { recursive: true, force: true });
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
    validation: CONFIRMED,
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
  writeFileRecord(outDir, record);
}

const onDisk = (id: string) =>
  readFileRecord(outDir, "sql-injection", "server.js")?.findings.find((f) => f.id === id);

function run(findings: Finding[], suggestFix: Detector["suggestFix"], signal?: AbortSignal) {
  return runFixPhase({
    findings,
    detector: { name: "test-mock", suggestFix } as Detector,
    outDir,
    root,
    runId: "run-1",
    concurrency: 1,
    signal,
  });
}

describe("selectForFix", () => {
  it("leaves out a finding whose path is absolute, because its fix has no record to go to", () => {
    const abs = makeFinding("a1", { filePath: resolve(root, "server.js") });
    expect(selectForFix([abs, makeFinding("a2")]).map((f) => f.id)).toEqual(["a2"]);
  });
});

describe("runFixPhase", () => {
  it("writes each fix to disk before it starts the next call", async () => {
    const findings = [makeFinding("a1"), makeFinding("a2")];
    seed(findings);
    const seenAtSecondCall: (string | undefined)[] = [];

    const result = await run(findings, async ({ finding }) => {
      if (finding.id === "a2") seenAtSecondCall.push(onDisk("a1")?.suggestedFix);
      return `fix for ${finding.id}`;
    });

    expect(seenAtSecondCall).toEqual(["fix for a1"]);
    expect(result).toEqual({ written: 2, total: 2 });
  });

  it("stops at a fatal provider error, keeps the fixes already written, and does not throw", async () => {
    const findings = [makeFinding("a1"), makeFinding("a2"), makeFinding("a3")];
    seed(findings);
    const called: string[] = [];
    const scan = new AbortController();

    const result = await run(
      findings,
      async ({ finding }) => {
        called.push(finding.id);
        if (finding.id === "a2") throw new Error(FATAL);
        return `fix for ${finding.id}`;
      },
      scan.signal,
    );

    expect(called).toEqual(["a1", "a2"]);
    expect(result.written).toBe(1);
    expect(result.total).toBe(3);
    expect(result.fatal).toBeInstanceOf(FatalScanError);
    expect(onDisk("a1")?.suggestedFix).toBe("fix for a1");
    // The phase is optional: its failure must not cancel the rest of the scan.
    expect(scan.signal.aborted).toBe(false);
  });

  it("records no fix when the model refuses", async () => {
    const findings = [makeFinding("a1")];
    seed(findings);

    const result = await run(findings, async () => "I can't help with this request.");

    expect(result.written).toBe(0);
    expect(onDisk("a1")?.suggestedFix).toBeUndefined();
  });

  it("gives the detector the recon brief", async () => {
    const findings = [makeFinding("a1")];
    seed(findings);
    const recon = {
      purpose: "p",
      languages: [],
      frameworks: ["express"],
      integrations: [],
      notableDirs: [],
      summary: "An Express API.",
      reconHash: "h",
      generatedAt: "2026-01-01T00:00:00.000Z",
    };
    const suggestFix = vi.fn(async () => "fix");

    await runFixPhase({
      findings,
      detector: { name: "test-mock", suggestFix } as unknown as Detector,
      outDir,
      root,
      runId: "run-1",
      concurrency: 1,
      recon,
    });

    expect(suggestFix.mock.calls[0]).toMatchObject([{ recon }]);
  });

  it("makes no call for a finding with no record on disk", async () => {
    const suggestFix = vi.fn(async () => "fix");

    const result = await run([makeFinding("a1")], suggestFix);

    expect(suggestFix).not.toHaveBeenCalled();
    expect(result).toEqual({ written: 0, total: 1 });
    expect(vi.mocked(console.warn).mock.calls.flat().join(" ")).toContain("a1");
  });
});
