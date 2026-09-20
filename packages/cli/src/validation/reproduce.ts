// Live-validation "reproduce" sub-phase. Runs after dedup, over PRIMARY
// web-reachable findings only, serially, inside a time + count budget. For
// each finding it asks the backend to reproduce the exploit against a running
// target (through the sandbox's Playwright MCP server), runs the generated
// script once, copies the trace/video/screenshots out of the sandbox, and
// persists the live result incrementally so a killed run resumes.

import { randomUUID } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import type { Finding, LiveResult } from "@agentgg/core";
import { getEvidenceDir, readFileRecord, writeFileRecord } from "@agentgg/core";
import AdmZip from "adm-zip";
import type { Detector } from "../detect.js";
import { logWarn } from "../log.js";
import { ensureSandboxImage } from "./image.js";
import { runReproScript } from "./repro-script.js";
import { type Sandbox, startLocalDockerSandbox } from "./sandbox.js";
import { redact, type TargetAuth } from "./target-auth.js";
import { parseTraceRequests, renderRequestsHttp } from "./trace-requests.js";
import { logSkips, selectWebReachable } from "./web-reachable.js";

type Evidence = NonNullable<NonNullable<Finding["live"]>["evidence"]>;

const ORDER: Record<string, number> = {
  uncertain: 0,
  confirmed: 1,
  "false-positive": 2,
};

/** Primaries a live run may test, best use of the budget first. `out-of-scope`
 *  comes from the user's scope file, so it never reaches the browser. */
export function selectForReproduce(findings: Finding[], force = false): Finding[] {
  const reachable = selectWebReachable(findings).selected.filter(
    (f) => f.validation?.verdict !== "out-of-scope",
  );
  // Default resume key: skip findings that already carry a live result.
  // `force` re-reproduces every web-reachable primary (like revalidate --revalidate-all).
  const work = force ? reachable : reachable.filter((f) => !f.live);
  return [...work].sort(
    (a, b) => (ORDER[a.validation?.verdict ?? ""] ?? 3) - (ORDER[b.validation?.verdict ?? ""] ?? 3),
  );
}

/** A live claim must point at traffic that was really captured. */
export function gradeLiveResult(raw: LiveResult, evidence?: Evidence): LiveResult {
  if (raw !== "reproduced") return raw;
  return (evidence?.requests?.length ?? 0) > 0 ? "reproduced" : "inconclusive";
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
  /** Per-finding browser turn cap. Threaded to the detector; when unset the
   *  detector's own default applies. */
  reproduceMaxTurns?: number;
  /** Re-reproduce web-reachable findings that already have a live result. */
  force?: boolean;
  signal: AbortSignal;
}): Promise<void> {
  const { findings, detector, outDir, targetUrl, auth, context, image, signal } = args;

  // Duplicates are collapsed out of the report, so exclude them here too; the
  // live-validation counts then reconcile with the findings/ directory.
  const primaries = findings.filter((f) => !f.dedup);
  const work = selectForReproduce(primaries, args.force ?? false);
  logSkips(selectWebReachable(primaries).skipped);
  const rejected = selectWebReachable(primaries).selected.filter(
    (f) => f.validation?.verdict === "out-of-scope",
  ).length;
  if (rejected > 0) {
    console.log(`  live validation: skipped ${rejected} finding(s) validation marked out-of-scope`);
  }
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

  // Preflight Docker and the image here, not at phase entry: a target that
  // never answered should not cost a multi-minute image build. Must also run
  // before the "reproducing N finding(s)" log below, so a skip is never
  // announced as work already under way.
  const preflight = await ensureSandboxImage(image);
  if (!preflight.ok) {
    console.log(`  live validation: skipping, keeping static verdicts.\n  ${preflight.reason}`);
    return;
  }

  console.log(`  live validation: reproducing ${work.length} finding(s) against ${targetUrl}`);

  // The browser runs inside the container, so a target the host publishes on
  // localhost must be reached via host.docker.internal. Probing stays on the
  // host-side URL; the agent (and the recorded baseUrl) gets the container one.
  const agentBaseUrl = toContainerBaseUrl(targetUrl);

  const runId = `reproduce-${randomUUID()}`;
  let sandbox: Sandbox;
  try {
    sandbox = await startLocalDockerSandbox({ image });
  } catch (err) {
    // The preflight above already built a missing image, so this now only
    // catches port conflicts or other docker/SSE failures.
    const msg = err instanceof Error ? err.message : String(err);
    console.log(
      `  live validation: could not start the sandbox, keeping static verdicts.\n  ${msg}`,
    );
    return;
  }

  const phaseStart = Date.now();
  let done = 0;
  const counts: Record<LiveResult, number> = { reproduced: 0, refuted: 0, inconclusive: 0 };
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

      // Announce the finding BEFORE reproducing it, not only its verdict after,
      // so a run that vanishes names the finding it died on.
      console.log(
        `    [${done}/${work.length}] ${finding.id} (${finding.vulnSlug}): reproducing...`,
      );

      // Per-finding timeout, linked to the scan-wide abort signal.
      const ac = new AbortController();
      const onAbort = () => ac.abort();
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        ac.abort();
      }, args.timeoutMs);
      signal.addEventListener("abort", onAbort);
      try {
        const res = await detector.reproduceFinding({
          finding,
          baseUrl: agentBaseUrl,
          auth,
          browserEndpoint: sandbox.browserEndpoint(),
          context,
          maxTurns: args.reproduceMaxTurns,
          staticVerdict: finding.validation?.verdict,
          staticReasoning: finding.validation?.reasoning,
          signal: ac.signal,
        });

        let evidence: Evidence | undefined;
        if (res.result === "reproduced" && res.script) {
          const script = await runReproScript(sandbox, res.script);
          const evidenceDir = getEvidenceDir(outDir, finding.agentSlug, finding.id);
          evidence = await copyEvidence(sandbox, evidenceDir);
          // Save the generated script next to the trace/video so the report's
          // evidence.script.path link resolves.
          mkdirSync(evidenceDir, { recursive: true });
          writeFileSync(join(evidenceDir, "repro.spec.ts"), res.script);
          evidence.script = { path: script.path, executed: script.executed, passed: script.passed };
        }

        const graded = gradeLiveResult(res.result, evidence);
        finding.live = {
          result: graded,
          reasoning: redact(res.reasoning, auth),
          counterevidence: redact(res.counterevidence, auth),
          ...(res.refused ? { refused: true } : {}),
          baseUrl: agentBaseUrl,
          ...(evidence ? { evidence } : {}),
          runId,
        };
        persistFinding(outDir, finding, detector.name, runId);
        counts[graded]++;
        console.log(`    ${finding.id}: ${graded}`);
      } catch (err) {
        let reason: string;
        if (timedOut) {
          reason = `reproduction timed out after ${Math.round(args.timeoutMs / 1000)}s`;
        } else {
          reason = err instanceof Error ? err.message : String(err);
        }
        logWarn(`[reproduce:${finding.id}] ${redact(reason, auth)}`);
        if (signal.aborted) break;
        // A timeout or crash records inconclusive rather than crashing the
        // scan; the static verdict is preserved underneath.
        finding.live = {
          result: "inconclusive",
          reasoning: redact(reason, auth),
          counterevidence: "",
          baseUrl: agentBaseUrl,
          runId,
        };
        counts.inconclusive++;
        try {
          persistFinding(outDir, finding, detector.name, runId);
        } catch (persistErr) {
          logWarn(`[reproduce:${finding.id}] persist failed: ${(persistErr as Error).message}`);
        }
      } finally {
        clearTimeout(timer);
        signal.removeEventListener("abort", onAbort);
        // Every finding, not just the confirmed ones: /out is shared for the
        // whole phase, so anything left behind lands in the next finding's
        // evidence.
        try {
          await clearSandboxOut(sandbox);
        } catch (clearErr) {
          logWarn(`[reproduce:${finding.id}] could not clear /out: ${(clearErr as Error).message}`);
        }
      }
    }
    if (done > 0) {
      console.log(
        `  live validation: ${counts.reproduced} reproduced, ${counts.refuted} refuted, ${counts.inconclusive} inconclusive`,
      );
    }
    if (counts.reproduced === 0 && done > 0) {
      const tail = (await sandbox.logs())
        .split("\n")
        .map((l) => `    ${l}`)
        .join("\n");
      console.log("  live validation: 0 reproduced. Sandbox MCP server logs (tail):");
      console.log(tail);
    }
  } catch (err) {
    // An infrastructure failure that escaped the per-finding handler (docker or
    // the SSE server going away mid-run): keep static verdicts and let the scan
    // finish rather than aborting after detect/validate/score/dedup succeeded.
    const msg = err instanceof Error ? err.message : String(err);
    logWarn(`live validation: stopped early, keeping static verdicts: ${redact(msg, auth)}`);
  } finally {
    await sandbox.dispose();
  }
}

/** Rewrite a host-local target URL to the container-facing host.docker.internal
 *  so the browser inside the sandbox can reach a target the host publishes on
 *  localhost. Non-local URLs (and anything unparseable) pass through unchanged. */
export function toContainerBaseUrl(targetUrl: string): string {
  try {
    const u = new URL(targetUrl);
    if (u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "::1") {
      u.hostname = "host.docker.internal";
      return u.toString();
    }
    return targetUrl;
  } catch {
    return targetUrl;
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

/** How long to wait for Playwright to flush the session video. It writes the
 *  file when the page closes, which can land after the agent's turn returns. */
const VIDEO_WAIT_MS = 10_000;
const VIDEO_POLL_MS = 250;

/**
 * Copy the artifacts the sandbox wrote under /out into the finding's evidence
 * dir, classifying by extension. Names come from @playwright/mcp, so this
 * enumerates what is there rather than assuming them. Exported for the
 * fake-sandbox tests.
 */
export async function copyEvidence(
  sandbox: Sandbox,
  evidenceDir: string,
  opts: { videoWaitMs?: number; pollMs?: number } = {},
): Promise<Evidence> {
  const evidence: Evidence = { screenshots: [] };
  mkdirSync(evidenceDir, { recursive: true });

  const names = await listOut(
    sandbox,
    opts.videoWaitMs ?? VIDEO_WAIT_MS,
    opts.pollMs ?? VIDEO_POLL_MS,
  );
  for (const name of names) {
    let buf: Buffer;
    try {
      buf = await sandbox.readFile(`/out/${name}`);
    } catch {
      // A subdirectory (traces/) or an unreadable entry; skip it.
      continue;
    }
    writeFileSync(join(evidenceDir, name), buf);
    const lower = name.toLowerCase();
    if (lower.endsWith(".webm") || lower.endsWith(".mp4")) {
      // `ls -1t` is newest first, so this keeps THIS finding's recording even
      // if an earlier one's file is still in /out.
      evidence.video ??= name;
    } else if (lower.endsWith(".png") || lower.endsWith(".jpg") || lower.endsWith(".jpeg")) {
      evidence.screenshots.push(name);
    }
  }

  const traced = await copyTrace(sandbox, evidenceDir);
  if (traced?.trace) evidence.trace = traced.trace;
  if (traced?.networkText) {
    const requests = parseTraceRequests(traced.networkText);
    if (requests.length > 0) {
      writeFileSync(join(evidenceDir, "requests.http"), renderRequestsHttp(requests));
      evidence.requests = requests.map((r) => ({ method: r.method, url: r.url, status: r.status }));
      evidence.requestsFile = "requests.http";
    }
  }
  return evidence;
}

/** Empty /out so the next finding cannot inherit these artifacts. /out itself
 *  stays: it is the MCP server's configured output dir. */
export async function clearSandboxOut(sandbox: Sandbox): Promise<void> {
  await sandbox.exec(["sh", "-c", "rm -rf /out/* /out/.[!.]* 2>/dev/null || true"]);
}

/** List /out newest-first, waiting for a video to appear. */
async function listOut(sandbox: Sandbox, waitMs: number, pollMs: number): Promise<string[]> {
  const deadline = Date.now() + waitMs;
  for (;;) {
    const { code, stdout } = await sandbox.exec(["ls", "-1t", "/out"]);
    const names =
      code === 0
        ? stdout
            .split(/\r?\n/)
            .map((s) => s.trim())
            .filter(Boolean)
        : [];
    const hasVideo = names.some((n) => /\.(webm|mp4)$/i.test(n));
    if (hasVideo || Date.now() >= deadline) return names;
    await delay(pollMs);
  }
}

/**
 * Zip the Playwright trace. `--save-trace` writes a traces/ DIRECTORY
 * (`*.trace`, `*.network`, `resources/`), not a zip, and the trace viewer
 * takes a zip, so build one on the host.
 */
async function copyTrace(
  sandbox: Sandbox,
  evidenceDir: string,
): Promise<{ trace?: string; networkText?: string } | undefined> {
  const { code, stdout } = await sandbox.exec(["sh", "-c", "find /out/traces -type f 2>/dev/null"]);
  if (code !== 0) return undefined;
  const paths = stdout
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (paths.length === 0) return undefined;

  const prefix = "/out/traces/";
  const zip = new AdmZip();
  let networkText: string | undefined;
  for (const path of paths) {
    if (!path.startsWith(prefix)) continue;
    let buf: Buffer;
    try {
      buf = await sandbox.readFile(path);
    } catch {
      continue;
    }
    zip.addFile(path.slice(prefix.length), buf);
    // The .network file carries the request/response snapshots for the report.
    if (path.endsWith(".network")) networkText = buf.toString("utf8");
  }
  if (zip.getEntries().length === 0) return undefined;
  zip.writeZip(join(evidenceDir, "trace.zip"));
  return { trace: "trace.zip", networkText };
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Read the finding's FileRecord, replace the finding by id, append a
 *  `reproduce` AnalysisRun, and write it back. Mirrors the dedup persistence
 *  in scan.ts. State is local-only, so the redacted reasoning stays off the
 *  client-mirrored surface. */
function persistFinding(outDir: string, finding: Finding, provider: string, runId: string): void {
  const filePath = finding.filePath.replace(/\\/g, "/");
  if (isAbsolute(filePath)) {
    logWarn(
      `[reproduce:${finding.id}] live result not persisted (non-relative filePath "${finding.filePath}"); it will re-run next scan`,
    );
    return;
  }
  const record = readFileRecord(outDir, finding.agentSlug, filePath);
  if (!record) {
    logWarn(
      `[reproduce:${finding.id}] live result not persisted (no file record for "${filePath}"); it will re-run next scan`,
    );
    return;
  }
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
