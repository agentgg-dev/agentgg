import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createRunMeta, readRunMeta, updateRunStage, writeRunMeta } from "../src/index.js";

let outputDir: string;
let runId: string;

beforeEach(() => {
  outputDir = mkdtempSync(join(tmpdir(), "agentgg-run-stage-"));
  const run = createRunMeta({ type: "scan" });
  writeRunMeta(outputDir, run);
  runId = run.runId;
});

afterEach(() => {
  rmSync(outputDir, { recursive: true, force: true });
});

describe("updateRunStage", () => {
  it("writes the stage and throttles the progress writes", () => {
    updateRunStage(outputDir, runId, "validate", { done: 1, total: 10 });
    updateRunStage(outputDir, runId, "validate", { done: 2, total: 10 });
    expect(readRunMeta(outputDir, runId)?.progress).toEqual({ done: 1, total: 10 });
    updateRunStage(outputDir, runId, "live", { done: 0, total: 3 });
    expect(readRunMeta(outputDir, runId)?.stage).toBe("live");
  });

  it("does not throw when the run doesn't exist on disk", () => {
    expect(() => updateRunStage(outputDir, "missing-run-id", "detect")).not.toThrow();
  });

  it("clears a prior stage's progress when the new stage call passes none, and a same-stage call inside the throttle window does not leak it back", () => {
    updateRunStage(outputDir, runId, "detect", { done: 5, total: 5 });
    updateRunStage(outputDir, runId, "report");
    const meta = readRunMeta(outputDir, runId);
    expect(meta?.stage).toBe("report");
    expect(meta?.progress).toBeUndefined();

    // Same stage, well inside the 2s throttle window: this write is
    // swallowed, but it must not resurrect the "detect" progress cleared
    // above — the on-disk state should stay exactly what it was.
    updateRunStage(outputDir, runId, "report", { done: 1, total: 2 });
    const afterThrottled = readRunMeta(outputDir, runId);
    expect(afterThrottled?.stage).toBe("report");
    expect(afterThrottled?.progress).toBeUndefined();
  });
});
