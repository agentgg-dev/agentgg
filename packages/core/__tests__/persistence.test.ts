import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  assertSafeFilePath,
  assertSafeSegment,
  completeRun,
  createRunMeta,
  generateRunId,
  getFileRecordPath,
  getRunMetaPath,
  getScanMetaPath,
  getStateDir,
  getStateFilesDir,
  getStateRunsDir,
  hashContent,
  listRuns,
  loadAllFileRecords,
  readFileRecord,
  readRunMeta,
  readScanMeta,
  stateDirHasFiles,
  upsertScanMeta,
  writeFileRecord,
  writeRunMeta,
} from "../src/index.js";
import type { FileRecord, RunMeta } from "../src/types.js";

let outputDir: string;

beforeEach(() => {
  outputDir = mkdtempSync(join(tmpdir(), "agentgg-state-"));
});

afterEach(() => {
  rmSync(outputDir, { recursive: true, force: true });
});

function makeRecord(filePath: string): FileRecord {
  return {
    filePath,
    contentHash: hashContent("hello"),
    candidates: [],
    findings: [],
    analysisHistory: [],
    scope: { outOfScope: false },
    status: "pending",
  };
}

describe("generateRunId", () => {
  it("produces sortable timestamped ids", () => {
    expect(generateRunId()).toMatch(/^\d{14}-[0-9a-f]{16}$/);
  });

  it("is unique across back-to-back calls", () => {
    expect(generateRunId()).not.toBe(generateRunId());
  });
});

describe("hashContent", () => {
  it("is deterministic", () => {
    expect(hashContent("hello")).toBe(hashContent("hello"));
  });

  it("differs for different content", () => {
    expect(hashContent("hello")).not.toBe(hashContent("world"));
  });

  it("is a sha256 hex string (64 chars)", () => {
    expect(hashContent("x")).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("path safety asserts", () => {
  it("assertSafeSegment rejects `..`, separators, null bytes, absolute", () => {
    expect(() => assertSafeSegment("")).toThrow();
    expect(() => assertSafeSegment("..")).toThrow();
    expect(() => assertSafeSegment(".")).toThrow();
    expect(() => assertSafeSegment("a/b")).toThrow();
    expect(() => assertSafeSegment("a\\b")).toThrow();
    expect(() => assertSafeSegment("a\0b")).toThrow();
    expect(() => assertSafeSegment("/abs")).toThrow();
    expect(() => assertSafeSegment("ok")).not.toThrow();
  });

  it("assertSafeFilePath rejects backslashes but allows POSIX dirs", () => {
    expect(() => assertSafeFilePath("")).toThrow();
    expect(() => assertSafeFilePath("a/../b")).toThrow();
    expect(() => assertSafeFilePath("a\\b")).toThrow();
    expect(() => assertSafeFilePath("a\0b")).toThrow();
    expect(() => assertSafeFilePath("/abs.ts")).toThrow();
    expect(() => assertSafeFilePath("src/a.ts")).not.toThrow();
    expect(() => assertSafeFilePath("a.ts")).not.toThrow();
  });
});

describe("path helpers", () => {
  it("nest state under <outputDir>/state/", () => {
    expect(getStateDir(outputDir)).toBe(join(outputDir, "state"));
    expect(getScanMetaPath(outputDir)).toBe(
      join(outputDir, "state", "scan.json"),
    );
    expect(getStateFilesDir(outputDir)).toBe(
      join(outputDir, "state", "files"),
    );
    expect(getStateRunsDir(outputDir)).toBe(
      join(outputDir, "state", "runs"),
    );
    expect(getRunMetaPath(outputDir, "20260513120000-aaaaaaaaaaaaaaaa")).toBe(
      join(outputDir, "state", "runs", "20260513120000-aaaaaaaaaaaaaaaa.json"),
    );
    expect(getFileRecordPath(outputDir, "src/foo.ts")).toBe(
      join(outputDir, "state", "files", "src/foo.ts.json"),
    );
  });

  it("getFileRecordPath rejects unsafe relative file paths", () => {
    expect(() => getFileRecordPath(outputDir, "../escape.ts")).toThrow();
    expect(() => getFileRecordPath(outputDir, "C:\\abs.ts")).toThrow();
  });

  it("getRunMetaPath rejects unsafe runIds", () => {
    expect(() => getRunMetaPath(outputDir, "../escape")).toThrow();
  });
});

describe("upsertScanMeta + readScanMeta", () => {
  it("writes scan.json on first call and stamps createdAt + updatedAt", () => {
    const meta = upsertScanMeta(outputDir, "/repo/a");
    expect(meta.root).toBe(resolve("/repo/a"));
    expect(meta.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}/);
    expect(meta.updatedAt).toBe(meta.createdAt);
    expect(existsSync(getScanMetaPath(outputDir))).toBe(true);
  });

  it("preserves createdAt on subsequent calls but refreshes updatedAt + root", async () => {
    const first = upsertScanMeta(outputDir, "/repo/a");
    await new Promise((r) => setTimeout(r, 5));
    const second = upsertScanMeta(outputDir, "/repo/a/moved");
    expect(second.createdAt).toBe(first.createdAt);
    expect(second.updatedAt).not.toBe(first.updatedAt);
    expect(second.root).toBe(resolve("/repo/a/moved"));
  });

  it("returns null when no scan-meta exists", () => {
    expect(readScanMeta(outputDir)).toBeNull();
  });

  it("returns null on malformed scan.json (rewritten on next upsert)", () => {
    upsertScanMeta(outputDir, "/repo/a");
    writeFileSync(getScanMetaPath(outputDir), "not json{");
    expect(readScanMeta(outputDir)).toBeNull();
    // Next upsert recovers.
    const recovered = upsertScanMeta(outputDir, "/repo/a");
    expect(recovered.root).toBe(resolve("/repo/a"));
  });
});

describe("FileRecord round-trip", () => {
  it("write then read returns the same record", () => {
    const rec = makeRecord("src/foo.ts");
    writeFileRecord(outputDir, rec);
    const loaded = readFileRecord(outputDir, "src/foo.ts");
    expect(loaded).toEqual(rec);
  });

  it("creates the nested directory structure on first write", () => {
    const rec = makeRecord("deep/nested/path/file.ts");
    writeFileRecord(outputDir, rec);
    expect(existsSync(getFileRecordPath(outputDir, "deep/nested/path/file.ts"))).toBe(true);
  });

  it("readFileRecord returns null for a missing record", () => {
    expect(readFileRecord(outputDir, "never-written.ts")).toBeNull();
  });

  it("readFileRecord returns null on malformed JSON instead of throwing", () => {
    const rec = makeRecord("src/bad.ts");
    writeFileRecord(outputDir, rec);
    writeFileSync(getFileRecordPath(outputDir, "src/bad.ts"), "not json{");
    expect(readFileRecord(outputDir, "src/bad.ts")).toBeNull();
  });
});

describe("loadAllFileRecords", () => {
  it("returns [] when the files dir doesn't exist yet", () => {
    expect(loadAllFileRecords(outputDir)).toEqual([]);
  });

  it("walks nested dirs and returns all valid records", () => {
    writeFileRecord(outputDir, makeRecord("a.ts"));
    writeFileRecord(outputDir, makeRecord("src/b.ts"));
    writeFileRecord(outputDir, makeRecord("src/sub/c.ts"));
    const loaded = loadAllFileRecords(outputDir);
    expect(loaded).toHaveLength(3);
    expect(loaded.map((r) => r.filePath).sort()).toEqual([
      "a.ts",
      "src/b.ts",
      "src/sub/c.ts",
    ]);
  });

  it("skips malformed JSON without throwing", () => {
    writeFileRecord(outputDir, makeRecord("good.ts"));
    writeFileSync(join(getStateFilesDir(outputDir), "bad.json"), "garbage");
    const loaded = loadAllFileRecords(outputDir);
    expect(loaded.map((r) => r.filePath)).toEqual(["good.ts"]);
  });
});

describe("RunMeta lifecycle", () => {
  it("createRunMeta starts with phase: running and no completedAt", () => {
    const run = createRunMeta({ type: "scan" });
    expect(run.phase).toBe("running");
    expect(run.completedAt).toBeUndefined();
    expect(run.runId).toMatch(/^\d{14}-[0-9a-f]{16}$/);
  });

  it("write then read round-trips", () => {
    const run = createRunMeta({ type: "scan" });
    writeRunMeta(outputDir, run);
    const loaded = readRunMeta(outputDir, run.runId);
    expect(loaded).toEqual(run);
  });

  it("completeRun stamps phase + completedAt + stats", () => {
    const run = createRunMeta({ type: "scan" });
    writeRunMeta(outputDir, run);
    completeRun(outputDir, run.runId, "done", {
      filesScanned: 7,
      findingsCount: 3,
    });
    const loaded = readRunMeta(outputDir, run.runId);
    expect(loaded?.phase).toBe("done");
    expect(loaded?.completedAt).toBeDefined();
    expect(loaded?.stats.filesScanned).toBe(7);
    expect(loaded?.stats.findingsCount).toBe(3);
  });

  it("completeRun is a no-op when the run doesn't exist on disk", () => {
    expect(() =>
      completeRun(outputDir, "missing-run-id-aaaaaaaaaaaaaaaa", "done", {}),
    ).not.toThrow();
  });
});

describe("listRuns", () => {
  it("returns [] when the runs dir doesn't exist", () => {
    expect(listRuns(outputDir)).toEqual([]);
  });

  it("returns runs newest-first (sorted by startedAt desc)", () => {
    const r1: RunMeta = {
      runId: "20260513120000-aaaaaaaaaaaaaaaa",
      type: "scan",
      phase: "done",
      startedAt: "2026-05-13T12:00:00.000Z",
      stats: {},
    };
    const r2: RunMeta = {
      runId: "20260513130000-bbbbbbbbbbbbbbbb",
      type: "scan",
      phase: "done",
      startedAt: "2026-05-13T13:00:00.000Z",
      stats: {},
    };
    writeRunMeta(outputDir, r1);
    writeRunMeta(outputDir, r2);
    const runs = listRuns(outputDir);
    expect(runs.map((r) => r.runId)).toEqual([r2.runId, r1.runId]);
  });

  it("skips malformed JSON files in the runs dir", () => {
    const run = createRunMeta({ type: "scan" });
    writeRunMeta(outputDir, run);
    writeFileSync(join(getStateRunsDir(outputDir), "bad.json"), "{not json");
    const runs = listRuns(outputDir);
    expect(runs.map((r) => r.runId)).toEqual([run.runId]);
  });
});

describe("stateDirHasFiles", () => {
  it("returns false when the state dir is missing", () => {
    expect(stateDirHasFiles(outputDir)).toBe(false);
  });

  it("returns false when only scan.json exists, no records", () => {
    upsertScanMeta(outputDir, "/repo/a");
    expect(stateDirHasFiles(outputDir)).toBe(false);
  });

  it("returns true once a FileRecord is written", () => {
    writeFileRecord(outputDir, makeRecord("src/foo.ts"));
    expect(stateDirHasFiles(outputDir)).toBe(true);
  });
});

describe("on-disk JSON shape", () => {
  it("scan.json is pretty-printed and ends with a newline", () => {
    upsertScanMeta(outputDir, "/repo/a");
    const raw = readFileSync(getScanMetaPath(outputDir), "utf8");
    expect(raw.endsWith("\n")).toBe(true);
    expect(raw).toContain("\n  ");
    const parsed = JSON.parse(raw);
    expect(parsed.root).toBe(resolve("/repo/a"));
  });
});
