/*
 * Per-scan on-disk state for agentgg.
 *
 * Nuclei-style: state lives **inside the scan's --output directory**,
 * not in a global cache. No `projectId` abstraction — the output dir
 * is the unit of identity. Re-running `scan` with the same `--output`
 * resumes from this state; using a different `--output` is a fresh
 * scan.
 *
 * Layout:
 *
 *   <outputDir>/
 *     summary.md
 *     findings/...                    human-facing markdown report
 *     state/
 *       scan.json                     ScanMeta (root path + timestamps)
 *       runs/<runId>.json             RunMeta (one per scan / revalidate)
 *       files/<relativePath>.json     FileRecord (one per scanned source file)
 */

import { createHash, randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import {
  getAgentRunPath,
  getFileRecordPath,
  getPlanPath,
  getReconPath,
  getRunMetaPath,
  getScanMetaPath,
  getStateFilesDir,
  getStateRunsDir,
} from "./paths.js";
import { AgentRun, FileRecord, ReconReport, RunMeta, ScanMeta, ScanPlan } from "./types.js";

export function generateRunId(): string {
  const now = new Date();
  const ts = now.toISOString().replace(/[-:T]/g, "").slice(0, 14);
  const suffix = randomBytes(8).toString("hex");
  return `${ts}-${suffix}`;
}

// ---------------------------------------------------------------------------
// ScanMeta sidecar — one per output dir
// ---------------------------------------------------------------------------

/**
 * Create or refresh `<outputDir>/state/scan.json`. The first call
 * stamps `createdAt`; every call updates `updatedAt` and the `root`
 * (so a moved working copy doesn't orphan its state).
 */
export function upsertScanMeta(outputDir: string, rootPath: string): ScanMeta {
  const path = getScanMetaPath(outputDir);
  const root = resolve(rootPath);
  const now = new Date().toISOString();
  if (existsSync(path)) {
    try {
      const parsed = ScanMeta.parse(JSON.parse(readFileSync(path, "utf8")));
      const updated: ScanMeta = { ...parsed, root, updatedAt: now };
      writeFileAtomic(path, `${JSON.stringify(updated, null, 2)}\n`);
      return updated;
    } catch {
      // corrupt sidecar — fall through and rewrite
    }
  }
  const meta: ScanMeta = { root, createdAt: now, updatedAt: now };
  writeFileAtomic(path, `${JSON.stringify(meta, null, 2)}\n`);
  return meta;
}

export function readScanMeta(outputDir: string): ScanMeta | null {
  const path = getScanMetaPath(outputDir);
  if (!existsSync(path)) return null;
  try {
    return ScanMeta.parse(JSON.parse(readFileSync(path, "utf8")));
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// ReconReport sidecar — one per output dir
// ---------------------------------------------------------------------------

/** Persist the recon brief to `<outputDir>/state/recon.json`. */
export function writeReconReport(outputDir: string, report: ReconReport): void {
  writeFileAtomic(getReconPath(outputDir), `${JSON.stringify(report, null, 2)}\n`);
}

/** Read the recon brief, or null when absent / corrupt. */
export function readReconReport(outputDir: string): ReconReport | null {
  const path = getReconPath(outputDir);
  if (!existsSync(path)) return null;
  try {
    return ReconReport.parse(JSON.parse(readFileSync(path, "utf8")));
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// ScanPlan sidecar — precondition decisions, one per output dir
// ---------------------------------------------------------------------------

/** Persist the precondition plan to `<outputDir>/state/plan.json`. */
export function writeScanPlan(outputDir: string, plan: ScanPlan): void {
  writeFileAtomic(getPlanPath(outputDir), `${JSON.stringify(plan, null, 2)}\n`);
}

/** Read the precondition plan, or null when absent / corrupt. */
export function readScanPlan(outputDir: string): ScanPlan | null {
  const path = getPlanPath(outputDir);
  if (!existsSync(path)) return null;
  try {
    return ScanPlan.parse(JSON.parse(readFileSync(path, "utf8")));
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// RunMeta
// ---------------------------------------------------------------------------

export function createRunMeta(params: {
  type: RunMeta["type"];
  invocation?: RunMeta["invocation"];
}): RunMeta {
  return {
    runId: generateRunId(),
    type: params.type,
    phase: "running",
    startedAt: new Date().toISOString(),
    ...(params.invocation ? { invocation: params.invocation } : {}),
    stats: {},
  };
}

export function writeRunMeta(outputDir: string, meta: RunMeta): void {
  writeFileAtomic(getRunMetaPath(outputDir, meta.runId), `${JSON.stringify(meta, null, 2)}\n`);
}

export function readRunMeta(outputDir: string, runId: string): RunMeta | null {
  const p = getRunMetaPath(outputDir, runId);
  if (!existsSync(p)) return null;
  try {
    return RunMeta.parse(JSON.parse(readFileSync(p, "utf8")));
  } catch {
    return null;
  }
}

export function completeRun(
  outputDir: string,
  runId: string,
  phase: "done" | "error",
  stats: Partial<RunMeta["stats"]> = {},
): void {
  const meta = readRunMeta(outputDir, runId);
  if (!meta) return;
  const updated: RunMeta = {
    ...meta,
    phase,
    completedAt: new Date().toISOString(),
    stats: { ...meta.stats, ...stats },
  };
  writeRunMeta(outputDir, updated);
}

/**
 * All runs in an output dir, newest-first. Malformed JSON is skipped
 * so a single corrupt file doesn't break `status`.
 */
export function listRuns(outputDir: string): RunMeta[] {
  const dir = getStateRunsDir(outputDir);
  if (!existsSync(dir)) return [];
  const out: RunMeta[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
    try {
      out.push(RunMeta.parse(JSON.parse(readFileSync(join(dir, entry.name), "utf8"))));
    } catch {
      // skip
    }
  }
  return out.sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
}

// ---------------------------------------------------------------------------
// FileRecord
// ---------------------------------------------------------------------------

export function readFileRecord(
  outputDir: string,
  agentSlug: string,
  filePath: string,
): FileRecord | null {
  const p = getFileRecordPath(outputDir, agentSlug, filePath);
  if (!existsSync(p)) return null;
  try {
    return FileRecord.parse(JSON.parse(readFileSync(p, "utf8")));
  } catch {
    return null;
  }
}

export function writeFileRecord(outputDir: string, record: FileRecord): void {
  const p = getFileRecordPath(outputDir, record.agentSlug, record.filePath);
  writeFileAtomic(p, `${JSON.stringify(record, null, 2)}\n`);
}

/**
 * Recursively load every FileRecord in an output dir. Malformed JSON
 * is skipped silently. Used by `status` and `revalidate`.
 */
export function loadAllFileRecords(outputDir: string): FileRecord[] {
  const dir = getStateFilesDir(outputDir);
  if (!existsSync(dir)) return [];
  const out: FileRecord[] = [];
  walk(dir, (p) => {
    if (!p.endsWith(".json")) return;
    try {
      out.push(FileRecord.parse(JSON.parse(readFileSync(p, "utf8"))));
    } catch {
      // skip
    }
  });
  return out;
}

function walk(dir: string, visit: (filePath: string) => void): void {
  if (!existsSync(dir)) return;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, visit);
    } else if (entry.isFile()) {
      visit(full);
    }
  }
}

// ---------------------------------------------------------------------------
// AgentRun (per-agent resume sidecar)
// ---------------------------------------------------------------------------

export function readAgentRun(outputDir: string, agentSlug: string): AgentRun | null {
  const p = getAgentRunPath(outputDir, agentSlug);
  if (!existsSync(p)) return null;
  try {
    return AgentRun.parse(JSON.parse(readFileSync(p, "utf8")));
  } catch {
    return null;
  }
}

export function writeAgentRun(outputDir: string, record: AgentRun): void {
  writeFileAtomic(
    getAgentRunPath(outputDir, record.agentSlug),
    `${JSON.stringify(record, null, 2)}\n`,
  );
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/**
 * Write through a temp file + rename. A crashed write produces a stray
 * `.tmp` next to the target instead of a half-written record that
 * fails the next `JSON.parse`.
 */
function writeFileAtomic(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(tmp, content);
  // On Windows, fs.renameSync over an existing file may fail with
  // EPERM in rare cases (AV scanner holding the handle). Fall back to
  // a best-effort write-in-place if rename trips.
  try {
    renameSync(tmp, path);
  } catch {
    writeFileSync(path, content);
    try {
      unlinkSync(tmp);
    } catch {
      // leave the .tmp; next successful write will replace target either way
    }
  }
}

/**
 * Compute the same content hash the scanner stamps on FileRecord, so
 * callers can decide "this file changed since the last scan." sha256
 * hex of the UTF-8 bytes.
 */
export function hashContent(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

/**
 * Quick check used by `status` to detect a state dir that exists but
 * holds no records yet (a scan that crashed before writing anything,
 * or a fresh `init`-style placeholder).
 */
export function stateDirHasFiles(outputDir: string): boolean {
  const dir = getStateFilesDir(outputDir);
  if (!existsSync(dir)) return false;
  try {
    return statSync(dir).isDirectory() && readdirSync(dir).length > 0;
  } catch {
    return false;
  }
}
