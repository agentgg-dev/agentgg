import 'server-only';
import { resolve } from 'node:path';
import {
  type FileRecord,
  type Finding,
  type RunMeta,
  type ScanMeta,
  type Surface,
  listRuns,
  loadAllFileRecords,
  readScanMeta,
} from '@agentgg/core';

// AGENTGG_RESULTS_DIR is set by the CLI when it spawns this server.
// In standalone `next dev` we fall back to ./scan-results so the viewer
// is still usable for local hacking.
export function getResultsDir(): string {
  const fromEnv = process.env.AGENTGG_RESULTS_DIR;
  if (fromEnv && fromEnv.trim().length > 0) return resolve(fromEnv);
  return resolve(process.cwd(), 'scan-results');
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
  /**
   * Surfaces from recon agents (`agent.outputType === "surface"`).
   * Loaded alongside findings but kept separate so the existing
   * Findings UI doesn't have to filter them out — they're a different
   * artifact type with no severity / no verdict.
   */
  surfaces: Surface[];
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
    surfaces: number;
    surfacesByAgent: AgentSummary[];
  };
};

export function loadViewerState(): ViewerState {
  const outputDir = getResultsDir();
  const scan = readScanMeta(outputDir);
  const files = loadAllFileRecords(outputDir);
  const runs = listRuns(outputDir);

  const allFindings = files.flatMap((f) => f.findings);
  // FileRecord.surfaces is optional on older records — coalesce so the
  // viewer renders cleanly against scans created before surfaces shipped.
  const allSurfaces = files.flatMap((f) => f.surfaces ?? []);

  // Scope the dashboard to the latest run so the numbers match
  // `summary.md` and `findings/*.md` (which only reflect that one run).
  // State still accumulates findings/surfaces across runs — the audit
  // trail is intact — we just don't render the cumulative union here.
  // Pre-fix records won't have a runId stamp; fall back to "show
  // everything" when nothing in state carries one so legacy result
  // dirs keep rendering.
  const lastRunId = runs[0]?.runId;
  const anyFindingHasRunId = allFindings.some((f) => f.runId);
  const anySurfaceHasRunId = allSurfaces.some((s) => s.runId);
  const findings =
    lastRunId && anyFindingHasRunId
      ? allFindings.filter((f) => f.runId === lastRunId)
      : allFindings;
  const surfaces =
    lastRunId && anySurfaceHasRunId
      ? allSurfaces.filter((s) => s.runId === lastRunId)
      : allSurfaces;
  const findingsValidated = findings.filter((f) => f.validation).length;

  const findingsByVerdict: Record<string, number> = {};
  for (const f of findings) {
    if (!f.validation) continue;
    findingsByVerdict[f.validation.verdict] =
      (findingsByVerdict[f.validation.verdict] ?? 0) + 1;
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
    const key = f.severity ?? 'UNSCORED';
    findingsBySeverity[key] = (findingsBySeverity[key] ?? 0) + 1;
  }

  const surfaceAgentCounts: Record<string, number> = {};
  for (const s of surfaces) {
    surfaceAgentCounts[s.agentSlug] = (surfaceAgentCounts[s.agentSlug] ?? 0) + 1;
  }
  const surfacesByAgent: AgentSummary[] = Object.entries(surfaceAgentCounts)
    .map(([slug, count]) => ({ slug, count }))
    .sort((a, b) => b.count - a.count);

  const statusCounts = { analyzed: 0, validated: 0, pending: 0 };
  for (const r of files) statusCounts[r.status]++;

  return {
    outputDir,
    scan,
    files,
    runs,
    findings,
    surfaces,
    counts: {
      files: files.length,
      analyzed: statusCounts.analyzed,
      validated: statusCounts.validated,
      pending: statusCounts.pending,
      findings: findings.length,
      findingsValidated,
      findingsByVerdict,
      findingsByAgent,
      findingsBySeverity,
      surfaces: surfaces.length,
      surfacesByAgent,
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
