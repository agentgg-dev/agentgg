// Live-validation "reproduce" sub-phase. Runs after dedup, over PRIMARY
// findings of any class, serially. Each finding is bounded by its own turn cap
// and timeout; the phase itself ends only when the work or the run does. For
// each finding it asks the backend to reproduce the exploit against a running
// target (through the sandbox's Playwright MCP server), replays the generated
// script once if it reproduced, copies the artifacts out of the sandbox for a
// reproduced or refuted verdict, and persists the live result incrementally so
// a killed run resumes.

import { randomUUID } from "node:crypto";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import type { Finding, LiveResult } from "@agentgg/core";
import { getEvidenceDir, readFileRecord, updateRunStage, writeFileRecord } from "@agentgg/core";
import AdmZip from "adm-zip";
import type { Detector } from "../detect.js";
import { logWarn } from "../log.js";
import { ensureSandboxImage } from "./image.js";
import { runProofScript, scriptProved } from "./proof-script.js";
import { runReproScript } from "./repro-script.js";
import { type Sandbox, startAttachedSandbox, startLocalDockerSandbox } from "./sandbox.js";
import { redact, redactBytes, type TargetAuth } from "./target-auth.js";
import {
  parseTraceRequests,
  renderRequestsHttp,
  requestBodyPreview,
  type TraceResources,
} from "./trace-requests.js";

type Evidence = NonNullable<NonNullable<Finding["live"]>["evidence"]>;

/** The finding record is mirrored to a client-readable store, so the payload
 *  it carries stays short. `requests.http` keeps the full body, locally. */
const MAX_RECORD_BODY = 512;

const ORDER: Record<string, number> = {
  uncertain: 0,
  confirmed: 1,
  "false-positive": 2,
};

/** A finding that names an HTTP way in. This orders the queue and never
 *  filters it: the signal is weak, and a weak signal must not drop a real
 *  finding the way a class allowlist did. */
const HTTP_ENTRY = /\b(?:GET|POST|PUT|PATCH|DELETE)\s+\/|https?:\/\/|\bendpoints?\b|\broutes?\b/i;

function namesHttpEntry(f: Finding): boolean {
  return HTTP_ENTRY.test(`${f.poc}\n${f.summary}\n${f.impact}`);
}

/** Primaries a live run may test, best use of the budget first. `out-of-scope`
 *  comes from the user's scope file, so it never reaches the browser. No class
 *  is excluded: the reproduce agent decides reachability against the running
 *  app, and a finding the budget never reached stays honestly untested. */
export function selectForReproduce(findings: Finding[], force = false): Finding[] {
  const eligible = findings.filter((f) => !f.dedup && f.validation?.verdict !== "out-of-scope");
  // Default resume key: skip findings that already carry a live result.
  // `force` re-reproduces every primary (like revalidate --revalidate-all).
  const work = force ? eligible : eligible.filter((f) => !f.live);
  return [...work].sort((a, b) => {
    const byVerdict =
      (ORDER[a.validation?.verdict ?? ""] ?? 3) - (ORDER[b.validation?.verdict ?? ""] ?? 3);
    return byVerdict !== 0 ? byVerdict : Number(namesHttpEntry(b)) - Number(namesHttpEntry(a));
  });
}

/** What the script-first path produces when it proves a finding outright. */
interface ScriptFirstProof {
  res: {
    result: LiveResult;
    reasoning: string;
    counterevidence: string;
    negativeControl?: string;
    /** Never set here. Declared so this shares one type with the agent path. */
    refused?: boolean;
    script?: string;
  };
  evidence: Evidence;
}

/**
 * Generate one proof spec and run it. Returns a proof only when BOTH tests
 * passed: the effect happened, and it did not happen without the attacker's
 * input. On anything else it clears /out and returns undefined, so the agent
 * path starts clean instead of inheriting this attempt's artifacts.
 */
async function tryScriptFirst(a: {
  finding: Finding;
  detector: Detector;
  sandbox: Sandbox;
  outDir: string;
  baseUrl: string;
  auth: TargetAuth;
  context?: string;
  proofRule?: string;
  timeoutMs: number;
  signal: AbortSignal;
}): Promise<ScriptFirstProof | undefined> {
  if (!a.detector.generateReproScript) return undefined;
  let script: string;
  let run: Awaited<ReturnType<typeof runProofScript>>;
  try {
    script = await a.detector.generateReproScript({
      finding: a.finding,
      baseUrl: a.baseUrl,
      auth: a.auth,
      context: a.context,
      proofRule: a.proofRule,
      staticVerdict: a.finding.validation?.verdict,
      staticReasoning: a.finding.validation?.reasoning,
      signal: a.signal,
    });
    run = await runProofScript(a.sandbox, script, a.timeoutMs);
  } catch (err) {
    // A failed generation is not a verdict. Say so and let the agent try.
    logWarn(
      `[script-first:${a.finding.id}] ${redact(err instanceof Error ? err.message : String(err), a.auth)}`,
    );
    return undefined;
  }

  if (!scriptProved(run)) {
    console.log(
      `      script-first: exploit ${run.exploit}, control ${run.control}; handing to the browser agent`,
    );
    await clearSandboxOut(a.sandbox).catch(() => {});
    return undefined;
  }

  const evidenceDir = getEvidenceDir(a.outDir, a.finding.agentSlug, a.finding.id);
  const evidence = await copyEvidence(a.sandbox, evidenceDir, { auth: a.auth });
  mkdirSync(evidenceDir, { recursive: true });
  writeFileSync(join(evidenceDir, run.path), redact(script, a.auth));
  writeFileSync(join(evidenceDir, "proof-run.log"), redact(run.output, a.auth));
  evidence.script = { path: run.path, executed: true, passed: true };
  console.log("      script-first: exploit and control both passed");

  return {
    res: {
      result: "reproduced",
      reasoning:
        "A generated Playwright spec drove the PoC against the running target and asserted the vulnerable effect. Both of its tests passed.",
      counterevidence:
        "The spec was written without sight of the application, so it asserts what the finding claims rather than what a reviewer might check independently.",
      negativeControl: `The 'control' test in ${run.path} repeated the steps with the attacker's input removed and asserted the effect did not happen. It passed.`,
    },
    evidence,
  };
}

/**
 * Whether a rejection is the expected debris of an aborted request, not a real
 * fault. When a per-finding timeout fires, the in-flight provider or MCP fetch
 * rejects asynchronously (undici surfaces `terminated` / `UND_ERR_BODY_TIMEOUT`).
 * That rejection has no owner to catch it, so without this it reaches
 * `unhandledRejection` and Node ends the whole scan.
 */
export function isAbortNoise(reason: unknown): boolean {
  if (!(reason instanceof Error)) return false;
  if (reason.name === "AbortError") return true;
  const cause = (reason as { cause?: { code?: unknown } }).cause;
  if (cause && typeof cause === "object" && "code" in cause) {
    const code = String((cause as { code?: unknown }).code ?? "");
    if (code === "UND_ERR_BODY_TIMEOUT" || code === "UND_ERR_ABORTED") return true;
  }
  return /\b(terminated|aborted|body timeout error)\b/i.test(reason.message);
}

/** Split the queue on whether a browser can prove the class at all. The fact
 *  comes from the reporting agent, which owns the class, so a new agent is
 *  always testable unless its author opts out. */
export function splitLiveReproducible(
  findings: Finding[],
  notLiveReproducible: ReadonlySet<string>,
): { testable: Finding[]; skipped: Finding[] } {
  const testable: Finding[] = [];
  const skipped: Finding[] = [];
  for (const f of findings) (notLiveReproducible.has(f.agentSlug) ? skipped : testable).push(f);
  return { testable, skipped };
}

/** Whether the copy produced anything worth linking. An evidence block with
 *  no files renders an empty panel, which promises artifacts that are absent. */
function hasArtifacts(e: Evidence): boolean {
  return Boolean(e.trace || e.video || e.script || e.requestsFile || e.screenshots.length > 0);
}

/** A live claim must point at traffic that was really captured, and at a
 *  control that separates the effect from the agent's own setup. Prose alone
 *  is not proof, so both are checked here rather than asked for in the prompt. */
export function gradeLiveResult(
  raw: LiveResult,
  evidence?: Evidence,
  negativeControl?: string,
): LiveResult {
  if (raw !== "reproduced") return raw;
  const captured = (evidence?.requests?.length ?? 0) > 0;
  return captured && (negativeControl?.trim().length ?? 0) > 0 ? "reproduced" : "inconclusive";
}

export async function runReproducePhase(args: {
  findings: Finding[];
  detector: Detector;
  outDir: string;
  /** The scan's run id, so live-validation progress lands in the same run sidecar. */
  runId: string;
  targetUrl: string;
  auth: TargetAuth;
  context?: string;
  image: string;
  timeoutMs: number;
  /** Per-finding browser turn cap. Threaded to the detector; when unset the
   *  detector's own default applies. */
  reproduceMaxTurns?: number;
  /** Each reporting agent's `liveProofRule`, keyed by slug. A slug with no
   *  entry leaves the finding on the proof principle alone. */
  agentProofRules?: ReadonlyMap<string, string>;
  /** Agents whose class reports a missing control, so a browser has nothing to
   *  reproduce. Their findings are answered without a run. */
  notLiveReproducible?: ReadonlySet<string>;
  /** Re-reproduce findings that already have a live result. */
  force?: boolean;
  /** Attach to a sandbox something else already started (a Cloud Run
   *  sidecar) instead of starting Docker locally. */
  attach?: { endpoint: string; controlUrl: string; token: string };
  signal: AbortSignal;
}): Promise<void> {
  const {
    findings,
    detector,
    outDir,
    runId: scanRunId,
    targetUrl,
    auth,
    context,
    image,
    signal,
  } = args;

  // Duplicates are collapsed out of the report, so exclude them here too; the
  // live-validation counts then reconcile with the findings/ directory.
  const primaries = findings.filter((f) => !f.dedup);
  const selected = selectForReproduce(primaries, args.force ?? false);
  const rejected = primaries.filter((f) => f.validation?.verdict === "out-of-scope").length;
  if (rejected > 0) {
    console.log(`  live validation: skipped ${rejected} finding(s) validation marked out-of-scope`);
  }

  // Classes that report a missing control have no effect to cause, so they are
  // answered here rather than by a browser run that could only borrow another
  // finding's effect. Recorded, not dropped: the reader sees why.
  const { testable: work, skipped } = splitLiveReproducible(
    selected,
    args.notLiveReproducible ?? new Set(),
  );
  for (const finding of skipped) {
    finding.live = {
      result: "not-reproducible",
      reasoning:
        "This finding reports a missing control, not an effect an attacker can cause, so no live run was attempted.",
      counterevidence: "",
    };
    persistFinding(outDir, finding, detector.name, `reproduce-skip-${finding.agentSlug}`);
  }
  if (skipped.length > 0) {
    console.log(
      `  live validation: ${skipped.length} finding(s) report a missing control, nothing to reproduce`,
    );
  }

  if (work.length === 0) {
    console.log("  live validation: no findings to reproduce");
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
  // announced as work already under way. Skipped when attaching: the sandbox
  // is already running and its image is the platform's concern, not ours.
  if (!args.attach) {
    const preflight = await ensureSandboxImage(image);
    if (!preflight.ok) {
      console.log(`  live validation: skipping, keeping static verdicts.\n  ${preflight.reason}`);
      return;
    }
  }

  console.log(`  live validation: reproducing ${work.length} finding(s) against ${targetUrl}`);
  updateRunStage(outDir, scanRunId, "live", { done: 0, total: work.length });

  const runId = `reproduce-${randomUUID()}`;
  let sandbox: Sandbox;
  let agentBaseUrl: string;
  try {
    if (args.attach) {
      // Attached mode: no container to redirect a localhost target into, so
      // the target is reached exactly as given.
      agentBaseUrl = targetUrl;
      sandbox = await startAttachedSandbox(args.attach);
    } else {
      // The browser runs inside the container, so a target the host
      // publishes on localhost must be reached via host.docker.internal.
      // Probing stays on the host-side URL; the agent (and the recorded
      // baseUrl) gets the container one.
      agentBaseUrl = toContainerBaseUrl(targetUrl);
      sandbox = await startLocalDockerSandbox({ image });
    }
  } catch (err) {
    // The preflight above already built a missing image, so this now only
    // catches port conflicts or other docker/SSE failures.
    const msg = err instanceof Error ? err.message : String(err);
    console.log(
      `  live validation: could not start the sandbox, keeping static verdicts.\n  ${msg}`,
    );
    return;
  }

  let done = 0;
  const counts: Record<LiveResult, number> = {
    reproduced: 0,
    refuted: 0,
    inconclusive: 0,
    error: 0,
    // Answered before the loop, so the run's own tally never increments it.
    "not-reproducible": 0,
  };
  // Aborting a per-finding timeout leaves the provider/MCP fetch to reject on a
  // later tick with no owner. During this phase those are expected, so swallow
  // them; a rejection that is NOT abort debris is re-thrown to keep crashing.
  const onUnhandled = (reason: unknown) => {
    if (isAbortNoise(reason)) {
      logWarn(`live validation: ignored a late abort rejection: ${(reason as Error).message}`);
      return;
    }
    throw reason;
  };
  process.on("unhandledRejection", onUnhandled);
  try {
    for (const finding of work) {
      if (signal.aborted) break;
      done++;
      updateRunStage(outDir, scanRunId, "live", { done, total: work.length });

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
        // Script-first: one call, no browser loop. A spec whose exploit AND
        // control both pass settles the finding in seconds. Anything else hands
        // it to the agent, which can look around.
        const fromScript = await tryScriptFirst({
          finding,
          detector,
          sandbox,
          outDir,
          baseUrl: agentBaseUrl,
          auth,
          context,
          proofRule: args.agentProofRules?.get(finding.agentSlug),
          timeoutMs: args.timeoutMs,
          signal: ac.signal,
        });

        const res =
          fromScript?.res ??
          (await detector.reproduceFinding({
            finding,
            baseUrl: agentBaseUrl,
            auth,
            browserEndpoint: sandbox.browserEndpoint(),
            context,
            maxTurns: args.reproduceMaxTurns,
            staticVerdict: finding.validation?.verdict,
            staticReasoning: finding.validation?.reasoning,
            staticConfirmedImpact: finding.validation?.confirmedImpact,
            proofRule: args.agentProofRules?.get(finding.agentSlug),
            signal: ac.signal,
          }));

        let evidence: Evidence | undefined = fromScript?.evidence;
        if (fromScript) {
          // Already proved and collected; skip the agent path's replay.
        } else if (res.result === "reproduced" && res.script) {
          const script = await runReproScript(sandbox, res.script);
          const evidenceDir = getEvidenceDir(outDir, finding.agentSlug, finding.id);
          evidence = await copyEvidence(sandbox, evidenceDir, { auth });
          // Save the generated script next to the trace/video so the report's
          // evidence.script.path link resolves.
          mkdirSync(evidenceDir, { recursive: true });
          writeFileSync(join(evidenceDir, "repro.spec.ts"), redact(res.script, auth));
          // The runner's own words, next to the script. Without them a replay
          // that never started looks the same as an exploit that stopped working.
          writeFileSync(join(evidenceDir, "repro-run.log"), redact(script.output, auth));
          if (!script.passed) {
            logWarn(
              `[reproduce:${finding.id}] the replay ${script.executed ? "did not pass" : "never ran"}: ${redact(script.output.split("\n")[0] ?? "", auth)}`,
            );
          }
          evidence.script = { path: script.path, executed: script.executed, passed: script.passed };
        } else if (res.result === "refuted") {
          // A refutation is a claim too, so it keeps the artifacts a triager
          // needs to check it. Not the video: its value is the "watch it fire"
          // moment, and it is the one artifact that costs tens of megabytes.
          const evidenceDir = getEvidenceDir(outDir, finding.agentSlug, finding.id);
          const captured = await copyEvidence(sandbox, evidenceDir, { keepVideo: false, auth });
          if (res.script) {
            writeFileSync(join(evidenceDir, "repro.spec.ts"), redact(res.script, auth));
            // Never replayed: a negative control that passes contradicts the
            // verdict it was written to support.
            captured.script = { path: "repro.spec.ts", executed: false, passed: false };
          }
          if (hasArtifacts(captured)) evidence = captured;
          else rmSync(evidenceDir, { recursive: true, force: true });
        }

        const graded = gradeLiveResult(res.result, evidence, res.negativeControl);
        finding.live = {
          result: graded,
          reasoning: redact(res.reasoning, auth),
          counterevidence: redact(res.counterevidence, auth),
          ...(res.negativeControl ? { negativeControl: redact(res.negativeControl, auth) } : {}),
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
        // A timeout spent the whole budget without proof, so it counts
        // against the finding; a crash says nothing about the code.
        const result: LiveResult = timedOut ? "inconclusive" : "error";
        finding.live = {
          result,
          reasoning: redact(reason, auth),
          counterevidence: "",
          baseUrl: agentBaseUrl,
          runId,
        };
        counts[result]++;
        try {
          persistFinding(outDir, finding, detector.name, runId);
        } catch (persistErr) {
          logWarn(`[reproduce:${finding.id}] persist failed: ${(persistErr as Error).message}`);
        }
      } finally {
        clearTimeout(timer);
        signal.removeEventListener("abort", onAbort);
        // Every finding, not just the reproduced ones: /out is shared for the
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
        `  live validation: ${counts.reproduced} reproduced, ${counts.refuted} refuted, ${counts.inconclusive} inconclusive${counts.error > 0 ? `, ${counts.error} error` : ""}`,
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
    try {
      await clearSandboxOut(sandbox);
    } catch (clearErr) {
      logWarn(`live validation: could not clear /out: ${(clearErr as Error).message}`);
    }
    await sandbox.dispose();
    // Give any in-flight aborted fetch a tick to reject while our guard is still
    // installed, then remove it so it never masks a later, real rejection.
    await new Promise((r) => setTimeout(r, 0));
    process.off("unhandledRejection", onUnhandled);
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
  opts: { videoWaitMs?: number; pollMs?: number; keepVideo?: boolean; auth?: TargetAuth } = {},
): Promise<Evidence> {
  const keepVideo = opts.keepVideo ?? true;
  const evidence: Evidence = { screenshots: [] };
  mkdirSync(evidenceDir, { recursive: true });

  const names = await listOut(
    sandbox,
    // The wait exists to let Playwright flush the video. A caller that drops
    // the video has nothing to wait for.
    keepVideo ? (opts.videoWaitMs ?? VIDEO_WAIT_MS) : 0,
    opts.pollMs ?? VIDEO_POLL_MS,
  );
  for (const name of names) {
    const lower = name.toLowerCase();
    const isVideo = lower.endsWith(".webm") || lower.endsWith(".mp4");
    if (isVideo && !keepVideo) continue;
    let buf: Buffer;
    try {
      buf = await sandbox.readFile(`/out/${name}`);
    } catch {
      // A subdirectory (traces/) or an unreadable entry; skip it.
      continue;
    }
    writeFileSync(join(evidenceDir, name), buf);
    if (isVideo) {
      // `ls -1t` is newest first, so this keeps THIS finding's recording even
      // if an earlier one's file is still in /out.
      evidence.video ??= name;
    } else if (lower.endsWith(".png") || lower.endsWith(".jpg") || lower.endsWith(".jpeg")) {
      evidence.screenshots.push(name);
    }
  }

  const traced = await copyTrace(sandbox, evidenceDir, opts.auth);
  if (traced?.trace) evidence.trace = traced.trace;
  if (traced?.networkText) {
    const requests = parseTraceRequests(traced.networkText, traced.resources);
    if (requests.length > 0) {
      const http = renderRequestsHttp(requests);
      writeFileSync(
        join(evidenceDir, "requests.http"),
        // Redacted already at the byte level in copyTrace; a second guard here
        // catches anything a codec boundary let through.
        opts.auth ? redact(http, opts.auth) : http,
      );
      evidence.requests = requests.map((r) => ({
        method: r.method,
        url: r.url,
        status: r.status,
        requestBody: requestBodyPreview(r, MAX_RECORD_BODY),
      }));
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
/** Take a trace.zip the test runner already assembled, wherever under /out it
 *  landed, and read its network log without unpacking it to disk. */
async function copyTraceZip(
  sandbox: Sandbox,
  evidenceDir: string,
  _auth?: TargetAuth,
): Promise<{ trace?: string; networkText?: string; resources?: TraceResources } | undefined> {
  const { code, stdout } = await sandbox.exec([
    "sh",
    "-c",
    "find /out -name trace.zip -type f 2>/dev/null",
  ]);
  if (code !== 0) return undefined;
  const found = stdout
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean)[0];
  if (!found) return undefined;

  let buf: Buffer;
  try {
    buf = await sandbox.readFile(found);
  } catch {
    return undefined;
  }
  writeFileSync(join(evidenceDir, "trace.zip"), buf);

  let networkText: string | undefined;
  const resources: TraceResources = new Map();
  try {
    for (const entry of new AdmZip(buf).getEntries()) {
      if (entry.entryName.endsWith(".network")) networkText = entry.getData().toString("utf8");
      else if (entry.entryName.startsWith("resources/"))
        resources.set(entry.entryName.slice("resources/".length), entry.getData());
    }
  } catch {
    // A truncated zip still travels with the evidence; it just carries no
    // parsed requests.
  }
  return { trace: "trace.zip", networkText, resources };
}

async function copyTrace(
  sandbox: Sandbox,
  evidenceDir: string,
  auth?: TargetAuth,
): Promise<{ trace?: string; networkText?: string; resources?: TraceResources } | undefined> {
  const { code, stdout } = await sandbox.exec(["sh", "-c", "find /out/traces -type f 2>/dev/null"]);
  const paths =
    code === 0
      ? stdout
          .split(/\r?\n/)
          .map((s) => s.trim())
          .filter(Boolean)
      : [];
  // The MCP server writes a traces/ DIRECTORY; `playwright test` writes a
  // finished trace.zip instead. Both have to reach the same evidence record.
  if (paths.length === 0) return await copyTraceZip(sandbox, evidenceDir, auth);

  const prefix = "/out/traces/";
  const zip = new AdmZip();
  let networkText: string | undefined;
  const resources: TraceResources = new Map();
  for (const path of paths) {
    if (!path.startsWith(prefix)) continue;
    let buf: Buffer;
    try {
      buf = await sandbox.readFile(path);
    } catch {
      continue;
    }
    const name = path.slice(prefix.length);
    // .trace files can carry typed input, so every file added to the zip is
    // redacted, not just the request/response log.
    const safe = auth ? redactBytes(buf, auth) : buf;
    zip.addFile(name, safe);
    // The .network file carries the request/response snapshots for the report.
    if (path.endsWith(".network")) networkText = safe.toString("utf8");
    // Bodies live here; the snapshots only point at them by sha1 name.
    else if (name.startsWith("resources/")) resources.set(name.slice("resources/".length), safe);
  }
  if (zip.getEntries().length === 0) return undefined;
  zip.writeZip(join(evidenceDir, "trace.zip"));
  return { trace: "trace.zip", networkText, resources };
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
