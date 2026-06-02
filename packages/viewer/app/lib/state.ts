import "server-only";
import { resolve } from "node:path";
import {
  type FileRecord,
  type Finding,
  listRuns,
  loadAllFileRecords,
  type RunMeta,
  readScanMeta,
  type ScanMeta,
} from "@agentgg/core";

// AGENTGG_RESULTS_DIR is set by the CLI when it spawns this server.
// In standalone `next dev` we fall back to ./scan-results so the viewer
// is still usable for local hacking.
export function getResultsDir(): string {
  const fromEnv = process.env.AGENTGG_RESULTS_DIR;
  if (fromEnv && fromEnv.trim().length > 0) return resolve(fromEnv);
  return resolve(process.cwd(), "scan-results");
}

export type AgentSummary = {
  slug: string;
  count: number;
};

export type VerdictSummary = {
  verdict: string;
  count: number;
};

export type ViewerState = {
  outputDir: string;
  scan: ScanMeta | null;
  files: FileRecord[];
  runs: RunMeta[];
  findings: Finding[];
  counts: {
    files: number;
    analyzed: number;
    validated: number;
    pending: number;
    findings: number;
    findingsValidated: number;
    findingsByVerdict: Record<string, number>;
    findingsByAgent: AgentSummary[];
    findingsBySeverity: Record<string, number>;
  };
};

export function loadViewerState(): ViewerState {
  const outputDir = getResultsDir();
  const scan = readScanMeta(outputDir);
  const files = loadAllFileRecords(outputDir);
  const runs = listRuns(outputDir);

  const findings = files.flatMap((f) => f.findings);
  const findingsValidated = findings.filter((f) => f.validation).length;

  const findingsByVerdict: Record<string, number> = {};
  for (const f of findings) {
    if (!f.validation) continue;
    findingsByVerdict[f.validation.verdict] = (findingsByVerdict[f.validation.verdict] ?? 0) + 1;
  }

  const agentCounts: Record<string, number> = {};
  for (const f of findings) {
    agentCounts[f.agentSlug] = (agentCounts[f.agentSlug] ?? 0) + 1;
  }
  const findingsByAgent: AgentSummary[] = Object.entries(agentCounts)
    .map(([slug, count]) => ({ slug, count }))
    .sort((a, b) => b.count - a.count);

  const findingsBySeverity: Record<string, number> = {};
  for (const f of findings) {
    const key = f.severity ?? "UNSCORED";
    findingsBySeverity[key] = (findingsBySeverity[key] ?? 0) + 1;
  }

  const statusCounts = { analyzed: 0, validated: 0, pending: 0 };
  for (const r of files) statusCounts[r.status]++;

  // `files` holds one record per (agent, file) since the state is
  // sharded by agent — so a source file scanned by N agents appears N
  // times. Report distinct source paths, not raw record count.
  const distinctFiles = new Set(files.map((r) => r.filePath)).size;

  return {
    outputDir,
    scan,
    files,
    runs,
    findings,
    counts: {
      files: distinctFiles,
      analyzed: statusCounts.analyzed,
      validated: statusCounts.validated,
      pending: statusCounts.pending,
      findings: findings.length,
      findingsValidated,
      findingsByVerdict,
      findingsByAgent,
      findingsBySeverity,
    },
  };
}

export function findFindingById(id: string): { finding: Finding; file: FileRecord } | null {
  const state = loadViewerState();
  for (const file of state.files) {
    const finding = file.findings.find((f) => f.id === id);
    if (finding) return { finding, file };
  }
  return null;
}
