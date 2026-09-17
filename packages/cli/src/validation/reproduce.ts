// Live-validation "reproduce" sub-phase. Runs after dedup, over PRIMARY
// web-reachable findings only, serially, inside a time + count budget. For
// each finding it asks the backend to reproduce the exploit against a running
// target (through the sandbox's Playwright MCP server), runs the generated
// script once, copies the trace/video/screenshots out of the sandbox, and
// persists the dynamic verdict incrementally so a killed run resumes.

import { randomUUID } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import type { Finding } from "@agentgg/core";
import { getEvidenceDir, readFileRecord, writeFileRecord } from "@agentgg/core";
import type { Detector } from "../detect.js";
import { logWarn } from "../log.js";
import { runReproScript } from "./repro-script.js";
import { dockerAvailable, type Sandbox, startLocalDockerSandbox } from "./sandbox.js";
import { redact, type TargetAuth } from "./target-auth.js";
import { logSkips, selectWebReachable } from "./web-reachable.js";

type Dynamic = NonNullable<Finding["validation"]>["dynamic"];
type Evidence = NonNullable<NonNullable<Dynamic>["evidence"]>;

/**
 * Findings eligible for reproduction: PRIMARY + web-reachable, minus any that
 * already carry a dynamic verdict. That last filter is the resume key — a
 * re-run skips findings a prior run already reproduced.
 */
export function selectForReproduce(findings: Finding[]): Finding[] {
  return selectWebReachable(findings).selected.filter((f) => !f.validation?.dynamic);
}

export async function runReproducePhase(args: {
  findings: Finding[];
  detector: Detector;
  outDir: string;
  targetUrl: string;
  auth: TargetAuth;
  context?: string;
  image: string;
  timeoutMs: number;
  budgetMs: number;
  max: number;
  signal: AbortSignal;
}): Promise<void> {
  const { findings, detector, outDir, targetUrl, auth, context, image, signal } = args;

  if (!(await dockerAvailable())) {
    console.log("  live validation: Docker not found, skipping (keeping static verdicts)");
    return;
  }

  const work = selectForReproduce(findings);
  logSkips(selectWebReachable(findings).skipped);
  if (work.length === 0) {
    console.log("  live validation: no web-reachable findings to reproduce");
    return;
  }

  if (!detector.reproduceFinding) {
    console.log("  live validation: backend does not support live validation, skipping");
    return;
  }

  if (!(await probe(targetUrl))) {
    console.log(`  live validation: target ${targetUrl} did not respond, skipping`);
    return;
  }

  console.log(`  live validation: reproducing ${work.length} finding(s) against ${targetUrl}`);

  const runId = `reproduce-${randomUUID()}`;
  const sandbox = await startLocalDockerSandbox({ image });
  const phaseStart = Date.now();
  let done = 0;
  try {
    for (const finding of work) {
      if (signal.aborted) break;
      if (Date.now() - phaseStart >= args.budgetMs) {
        console.log(`  live validation: budget reached, stopping after ${done} finding(s)`);
        break;
      }
      if (done >= args.max) {
        console.log(`  live validation: max (${args.max}) reached, stopping`);
        break;
      }
      done++;

      // Per-finding timeout, linked to the scan-wide abort signal.
      const ac = new AbortController();
      const onAbort = () => ac.abort();
      const timer = setTimeout(() => ac.abort(), args.timeoutMs);
      signal.addEventListener("abort", onAbort);
      try {
        const res = await detector.reproduceFinding({
          finding,
          baseUrl: targetUrl,
          auth,
          browserEndpoint: sandbox.browserEndpoint(),
          context,
          signal: ac.signal,
        });

        let evidence: Evidence | undefined;
        if (res.verdict === "confirmed" && res.script) {
          const script = await runReproScript(sandbox, res.script);
          evidence = await copyEvidence(
            sandbox,
            getEvidenceDir(outDir, finding.agentSlug, finding.id),
          );
          evidence.script = { path: script.path, executed: script.executed, passed: script.passed };
        }

        const dynamic: Dynamic = {
          verdict: res.verdict,
          reasoning: redact(res.reasoning, auth),
          ...(res.refused ? { refused: true } : {}),
          baseUrl: targetUrl,
          ...(evidence ? { evidence } : {}),
        };
        finding.validation = {
          ...(finding.validation ?? {
            verdict: "uncertain",
            reasoning: "not statically validated",
          }),
          dynamic,
        };
        persistFinding(outDir, finding, detector.name, runId);
        console.log(`    ${finding.id}: ${res.verdict}`);
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        logWarn(`[reproduce:${finding.id}] ${redact(reason, auth)}`);
        if (signal.aborted) break;
        // A timeout or reproduction failure records not-reproduced rather than
        // crashing the scan; the static verdict is preserved underneath.
        finding.validation = {
          ...(finding.validation ?? {
            verdict: "uncertain",
            reasoning: "not statically validated",
          }),
          dynamic: {
            verdict: "not-reproduced",
            reasoning: redact(reason, auth),
            baseUrl: targetUrl,
          },
        };
        try {
          persistFinding(outDir, finding, detector.name, runId);
        } catch (persistErr) {
          logWarn(`[reproduce:${finding.id}] persist failed: ${(persistErr as Error).message}`);
        }
      } finally {
        clearTimeout(timer);
        signal.removeEventListener("abort", onAbort);
      }
    }
  } finally {
    await sandbox.dispose();
  }
}

/** Fetch the target once with a short timeout. Any HTTP response counts as
 *  answering; only a network error or timeout means "did not respond". */
async function probe(url: string, timeoutMs = 5_000): Promise<boolean> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    await fetch(url, { signal: ac.signal });
    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(t);
  }
}

/**
 * Copy every artifact the sandbox wrote under /out into the finding's local
 * evidence dir, classifying by extension. The exact /out filenames are set by
 * @playwright/mcp; this enumerates whatever is there rather than assuming
 * names. HAR is embedded in the Playwright trace, so `evidence.har` stays
 * unset. Per-file read failures are skipped so one bad artifact never drops
 * the whole confirmation.
 */
async function copyEvidence(sandbox: Sandbox, evidenceDir: string): Promise<Evidence> {
  const evidence: Evidence = { screenshots: [] };
  mkdirSync(evidenceDir, { recursive: true });
  const { code, stdout } = await sandbox.exec(["ls", "/out"]);
  if (code !== 0) return evidence;
  const names = stdout
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
  for (const name of names) {
    try {
      const buf = await sandbox.readFile(`/out/${name}`);
      writeFileSync(join(evidenceDir, name), buf);
    } catch {
      // Likely a subdirectory or unreadable entry; skip it.
      continue;
    }
    const lower = name.toLowerCase();
    if (lower.endsWith(".zip")) {
      evidence.trace ??= name;
    } else if (lower.endsWith(".webm") || lower.endsWith(".mp4")) {
      evidence.video ??= name;
    } else if (lower.endsWith(".png") || lower.endsWith(".jpg") || lower.endsWith(".jpeg")) {
      evidence.screenshots.push(name);
    }
  }
  return evidence;
}

/** Read the finding's FileRecord, replace the finding by id, append a
 *  `reproduce` AnalysisRun, and write it back. Mirrors the dedup persistence
 *  in scan.ts. State is local-only, so the redacted reasoning stays off the
 *  client-mirrored surface. */
function persistFinding(outDir: string, finding: Finding, provider: string, runId: string): void {
  const filePath = finding.filePath.replace(/\\/g, "/");
  if (isAbsolute(filePath)) return;
  const record = readFileRecord(outDir, finding.agentSlug, filePath);
  if (!record) return;
  record.findings = record.findings.map((rec) => (rec.id === finding.id ? finding : rec));
  record.analysisHistory.push({
    runId,
    phase: "reproduce",
    ranAt: new Date().toISOString(),
    durationMs: 0,
    provider,
    agentSlugs: [finding.agentSlug],
    findingCount: record.findings.length,
  });
  writeFileRecord(outDir, record);
}
