import type { Sandbox } from "./sandbox.js";

/** The line reporter's tally. Absent when the run never reached a test: a
 *  missing dependency, a syntax error, or "No tests found". */
const RAN_A_TEST = /\d+ (passed|failed|flaky|skipped|did not run)/;

/** How much of the runner output travels with the evidence. */
const OUTPUT_TAIL = 4000;

export async function runReproScript(sandbox: Sandbox, script: string) {
  const path = "/srv/repro.spec.ts";
  await sandbox.writeFile(path, script);
  const { code, stdout, stderr } = await sandbox.exec(
    ["npx", "playwright", "test", path, "--reporter=line"],
    { timeoutMs: 120_000 },
  );
  const output = `${stdout}\n${stderr}`.trim();
  // `executed` was hardcoded true, so a run that died on its first import still
  // reported a replay, and only the exit code survived to say otherwise.
  const executed = RAN_A_TEST.test(output);
  return {
    path: "repro.spec.ts",
    executed,
    passed: executed && code === 0,
    output: output.slice(-OUTPUT_TAIL),
  };
}
