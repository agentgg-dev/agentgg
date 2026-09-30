// Script-first reproduction: run one generated Playwright spec that carries
// both halves of a proof, instead of driving the browser turn by turn. The spec
// declares `exploit` (the effect) and `control` (the effect absent without the
// attacker's input); a claim needs both.

import type { Sandbox } from "./sandbox.js";

/** Titles the generated spec must use. The prompt names them, and the outcome
 *  is read back by title, so a renamed test reads as missing rather than pass. */
export const EXPLOIT_TEST = "exploit";
export const CONTROL_TEST = "control";

export type TestOutcome = "passed" | "failed" | "missing";

/** How much runner output travels with the evidence. */
const OUTPUT_TAIL = 4000;

interface JsonSpec {
  title?: unknown;
  ok?: unknown;
}
interface JsonSuite {
  specs?: unknown;
  suites?: unknown;
}

function collectSpecs(node: JsonSuite, into: Map<string, boolean>): void {
  if (Array.isArray(node.specs)) {
    for (const s of node.specs as JsonSpec[]) {
      if (typeof s?.title === "string" && !into.has(s.title)) into.set(s.title, s.ok === true);
    }
  }
  if (Array.isArray(node.suites)) {
    for (const child of node.suites as JsonSuite[]) collectSpecs(child, into);
  }
}

/**
 * Read the per-test outcomes out of Playwright's JSON report. The exit code
 * cannot tell a failed exploit from a failed control, and those mean opposite
 * things, so the report is parsed rather than the status.
 */
export function parseProofReport(stdout: string): {
  exploit: TestOutcome;
  control: TestOutcome;
} {
  const specs = new Map<string, boolean>();
  try {
    const start = stdout.indexOf("{");
    const parsed = start >= 0 ? JSON.parse(stdout.slice(start)) : undefined;
    if (parsed && typeof parsed === "object") collectSpecs(parsed as JsonSuite, specs);
  } catch {
    // Not a report: a crash, a syntax error, or "no tests found".
  }
  const outcome = (title: string): TestOutcome =>
    specs.has(title) ? (specs.get(title) ? "passed" : "failed") : "missing";
  return { exploit: outcome(EXPLOIT_TEST), control: outcome(CONTROL_TEST) };
}

export interface ProofScriptRun {
  path: string;
  executed: boolean;
  exploit: TestOutcome;
  control: TestOutcome;
  output: string;
}

/**
 * Run a generated proof spec in the sandbox with tracing on, writing artifacts
 * where `copyEvidence` already looks. Tracing is what makes the captured
 * request available, and a claim with no captured request is not a proof.
 */
export async function runProofScript(
  sandbox: Sandbox,
  script: string,
  timeoutMs = 120_000,
): Promise<ProofScriptRun> {
  const path = "/srv/proof.spec.ts";
  await sandbox.writeFile(path, script);
  const { stdout, stderr } = await sandbox.exec(
    [
      "npx",
      "playwright",
      "test",
      path,
      "--reporter=json",
      "--output=/out",
      "--trace=on",
      "--workers=1",
    ],
    { timeoutMs },
  );
  const { exploit, control } = parseProofReport(stdout);
  return {
    path: "proof.spec.ts",
    executed: exploit !== "missing" || control !== "missing",
    exploit,
    control,
    output: `${stdout}\n${stderr}`.trim().slice(-OUTPUT_TAIL),
  };
}

/** A generated script proves the finding only when the effect happened AND the
 *  same steps without the attacker's input did not produce it. */
export function scriptProved(run: ProofScriptRun): boolean {
  return run.exploit === "passed" && run.control === "passed";
}
