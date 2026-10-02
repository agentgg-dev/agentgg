import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { FileRecord, Finding } from "@agentgg/core";
import { getEvidenceDir, hashContent, readFileRecord, writeFileRecord } from "@agentgg/core";
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

  describe("edit check", () => {
    // The seeded file is `const x = 1;`.
    const GOOD = "Use two.\n\n<<<<<<< SEARCH\nconst x = 1;\n=======\nconst x = 2;\n>>>>>>> REPLACE";
    const BAD = "Use two.\n\n<<<<<<< SEARCH\nconst y = 1;\n=======\nconst y = 2;\n>>>>>>> REPLACE";
    type Args = { retry?: { answer: string; problems: string[] } };

    it("stores the checked diff, not the model's blocks", async () => {
      const findings = [makeFinding("a1")];
      seed(findings);

      await run(findings, async () => GOOD);

      const fix = onDisk("a1")?.suggestedFix ?? "";
      expect(fix).toContain("```diff\n--- a/server.js\n+++ b/server.js\n@@ -1,1 +1,1 @@");
      expect(fix).toContain("-const x = 1;\n+const x = 2;");
      expect(fix).not.toContain("<<<<<<<");
    });

    it("asks once more, with the problems, when the code does not match the file", async () => {
      const findings = [makeFinding("a1")];
      seed(findings);
      const suggestFix = vi.fn(async (args: Args) => (args.retry ? GOOD : BAD));

      const result = await run(findings, suggestFix as Detector["suggestFix"]);

      expect(suggestFix).toHaveBeenCalledTimes(2);
      const retry = suggestFix.mock.calls[1][0].retry;
      expect(retry?.answer).toBe(BAD);
      expect(retry?.problems.join(" ")).toContain("do not occur in server.js");
      expect(result.written).toBe(1);
      expect(onDisk("a1")?.suggestedFix).toContain("+const x = 2;");
    });

    it("records no fix when the second answer does not match the file either", async () => {
      const findings = [makeFinding("a1")];
      seed(findings);
      const suggestFix = vi.fn(async () => BAD);

      const result = await run(findings, suggestFix);

      expect(suggestFix).toHaveBeenCalledTimes(2);
      expect(result.written).toBe(0);
      expect(onDisk("a1")?.suggestedFix).toBeUndefined();
      expect(vi.mocked(console.warn).mock.calls.flat().join(" ")).toContain("a1");
    });

    it("prints one line for each fix with verbose on", async () => {
      const findings = [makeFinding("a1")];
      seed(findings);

      await runFixPhase({
        findings,
        detector: { name: "test-mock", suggestFix: async () => GOOD } as unknown as Detector,
        outDir,
        root,
        runId: "run-1",
        concurrency: 1,
        verbose: true,
      });

      const lines = vi.mocked(console.log).mock.calls.map((c) => String(c[0]));
      expect(lines.filter((l) => l.includes("a1"))).toEqual([
        expect.stringMatching(/a1.*1 edit.*server\.js/),
      ]);
    });
  });

  describe("other files of the repository", () => {
    const inLib = (path: string) =>
      `Fix the helper.\n\n${path}\n<<<<<<< SEARCH\nexport const y = 1;\n=======\nexport const y = 2;\n>>>>>>> REPLACE`;

    beforeEach(() => {
      writeFileSync(join(root, "lib.js"), "export const y = 1;", "utf8");
    });

    it("gives the detector the repository root and the scan's file limits, for its read tools", async () => {
      const findings = [makeFinding("a1")];
      seed(findings);
      const suggestFix = vi.fn(async () => "fix");

      await runFixPhase({
        findings,
        detector: { name: "test-mock", suggestFix } as unknown as Detector,
        outDir,
        root,
        runId: "run-1",
        concurrency: 1,
        excludePatterns: ["vendor/**"],
        maxFileSizeKb: 256,
      });

      expect(suggestFix.mock.calls[0]).toMatchObject([
        { root, excludePatterns: ["vendor/**"], maxFileSizeKb: 256 },
      ]);
    });

    it("stores an edit to another file as a diff of that file", async () => {
      const findings = [makeFinding("a1")];
      seed(findings);

      await run(findings, async () => inLib("lib.js"));

      const fix = onDisk("a1")?.suggestedFix ?? "";
      expect(fix).toContain("**Location:** `lib.js`, line 1");
      expect(fix).toContain("--- a/lib.js\n+++ b/lib.js");
    });

    it.each([
      ["above the repository", "../outside.js"],
      ["given as an absolute path", "ABSOLUTE"],
    ])("rejects an edit to a file %s", async (_where, path) => {
      const outside = join(root, "..", "outside.js");
      writeFileSync(outside, "export const y = 1;", "utf8");
      const findings = [makeFinding("a1")];
      seed(findings);
      const suggestFix = vi.fn(async () => inLib(path === "ABSOLUTE" ? outside : path));

      try {
        const result = await run(findings, suggestFix);
        expect(result.written).toBe(0);
        expect(onDisk("a1")?.suggestedFix).toBeUndefined();
      } finally {
        rmSync(outside, { force: true });
      }
    });
  });

  describe("live evidence", () => {
    const SCRIPT = "test('exploit', async ({ page }) => { await page.goto('/'); });";
    const reproduced = (script?: { path: string; executed: boolean; passed: boolean }) =>
      makeFinding("a1", {
        live: {
          result: "reproduced",
          reasoning: "r",
          counterevidence: "",
          negativeControl: "c",
          evidence: {
            screenshots: [],
            requests: [{ method: "GET", url: "http://app.test/", status: 200 }],
            ...(script ? { script } : {}),
          },
        },
      });
    const liveScriptOf = async (finding: Finding) => {
      seed([finding]);
      const suggestFix = vi.fn(async () => "fix");
      await run([finding], suggestFix as Detector["suggestFix"]);
      return (suggestFix.mock.calls[0] as unknown as [{ liveScript?: unknown }])[0].liveScript;
    };
    const writeScript = (finding: Finding) => {
      const dir = getEvidenceDir(outDir, finding.agentSlug, finding.id);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "repro.spec.ts"), SCRIPT, "utf8");
    };

    it("gives the detector the reproduction script and whether its replay passed", async () => {
      const finding = reproduced({ path: "repro.spec.ts", executed: true, passed: false });
      writeScript(finding);
      expect(await liveScriptOf(finding)).toEqual({ source: SCRIPT, passed: false });
    });

    it("gives no script when the evidence file is gone", async () => {
      const finding = reproduced({ path: "repro.spec.ts", executed: true, passed: true });
      expect(await liveScriptOf(finding)).toBeUndefined();
    });

    it("gives no script for a finding the live run did not reproduce", async () => {
      const finding = reproduced({ path: "repro.spec.ts", executed: true, passed: true });
      writeScript(finding);
      if (finding.live) finding.live.result = "error";
      expect(await liveScriptOf(finding)).toBeUndefined();
    });
  });

  it("makes no call for a finding with no record on disk", async () => {
    const suggestFix = vi.fn(async () => "fix");

    const result = await run([makeFinding("a1")], suggestFix);

    expect(suggestFix).not.toHaveBeenCalled();
    expect(result).toEqual({ written: 0, total: 1 });
    expect(vi.mocked(console.warn).mock.calls.flat().join(" ")).toContain("a1");
  });
});
