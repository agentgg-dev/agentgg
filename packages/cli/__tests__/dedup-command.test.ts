import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FileRecord, Finding, UserConfig } from "@agentgg/core";
import { readFileRecord, saveUserConfig, upsertScanMeta, writeFileRecord } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const FILE = "src/app.js";

// Hoisted so it is in place before dedup.ts pulls in `resolveDetector`.
const detectorMock = vi.hoisted(() => ({
  dedupeFindings: vi.fn(
    async (_args: { filePath: string; findings: { id: string }[] }) =>
      [] as { primaryId: string; duplicateIds: string[]; reasoning: string }[],
  ),
}));

vi.mock("../src/llm.js", async () => {
  const actual = await vi.importActual<typeof import("../src/llm.js")>("../src/llm.js");
  return {
    ...actual,
    resolveDetector: () => ({ name: "test-mock", dedupeFindings: detectorMock.dedupeFindings }),
  };
});

import { runDedup } from "../src/commands/dedup.js";

let agentggHome: string;
let projectRoot: string;
let outputDir: string;
let env: NodeJS.ProcessEnv;

function finding(id: string, agentSlug: string, extra: Partial<Finding> = {}): Finding {
  return {
    id,
    agentSlug,
    title: `finding ${id}`,
    vulnSlug: "sql-injection",
    filePath: FILE,
    lineRange: [10, 12],
    summary: "s",
    details: "d",
    poc: "p",
    impact: "i",
    references: [],
    confidence: 0.8,
    notifications: [],
    ...extra,
  };
}

function seed(...findings: Finding[]): void {
  const byAgent = new Map<string, Finding[]>();
  for (const f of findings) {
    const bucket = byAgent.get(f.agentSlug);
    if (bucket) bucket.push(f);
    else byAgent.set(f.agentSlug, [f]);
  }
  for (const [agentSlug, group] of byAgent) {
    writeFileRecord(outputDir, {
      agentSlug,
      filePath: FILE,
      contentHash: "h",
      findings: group,
      analysisHistory: [],
      candidates: [],
      status: "validated",
    } as FileRecord);
  }
}

function onDisk(agentSlug: string, id: string): Finding {
  const record = readFileRecord(outputDir, agentSlug, FILE);
  const f = record?.findings.find((x) => x.id === id);
  if (!f) throw new Error(`no finding ${id} in ${agentSlug}/${FILE}`);
  return f;
}

beforeEach(() => {
  agentggHome = mkdtempSync(join(tmpdir(), "agentgg-home-"));
  projectRoot = mkdtempSync(join(tmpdir(), "agentgg-project-"));
  outputDir = mkdtempSync(join(tmpdir(), "agentgg-out-"));
  env = { AGENTGG_HOME: agentggHome };
  const cfg: UserConfig = {
    provider: "anthropic",
    anthropic: { apiKey: "sk-ant-test", model: "claude-sonnet-4-6" },
    schemaVersion: 1,
  };
  saveUserConfig(cfg, env);
  upsertScanMeta(outputDir, projectRoot);
  vi.spyOn(console, "log").mockImplementation(() => {});
});

afterEach(() => {
  rmSync(agentggHome, { recursive: true, force: true });
  rmSync(projectRoot, { recursive: true, force: true });
  rmSync(outputDir, { recursive: true, force: true });
  vi.restoreAllMocks();
  detectorMock.dedupeFindings.mockReset();
  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    for (const h of process.listeners(signal)) process.removeListener(signal, h);
  }
});

describe("agentgg dedup over findings that already carry verdicts", () => {
  it("compares every verdict, then promotes out from under a rejected primary", async () => {
    // The platform runs this command after the agent container validated
    // everything, so both candidates arrive with a verdict.
    seed(
      finding("fp-1", "alpha", {
        validation: { verdict: "false-positive", reasoning: "not reachable" },
      }),
      finding("real-1", "beta", {
        validation: { verdict: "confirmed", reasoning: "reachable" },
      }),
    );
    detectorMock.dedupeFindings.mockImplementation(async () => [
      { primaryId: "fp-1", duplicateIds: ["real-1"], reasoning: "same sink" },
    ]);

    await runDedup(outputDir, { summary: false }, env);

    // Neither verdict kept a finding out of the candidate set.
    const compared = detectorMock.dedupeFindings.mock.calls[0]?.[0].findings.map((f) => f.id);
    expect(compared?.sort()).toEqual(["fp-1", "real-1"]);

    // The confirmed finding must not stay folded under the false positive:
    // the dashboard hides a row that is a duplicate OR is rejected, so it
    // would vanish from every default view.
    const real = onDisk("beta", "real-1");
    expect(real.dedup).toBeUndefined();
    const fp = onDisk("alpha", "fp-1");
    expect(fp.dedup?.duplicateOf).toBe("real-1");
    expect(fp.validation?.verdict).toBe("false-positive");
  });

  it("leaves a cluster alone when the primary's verdict kept it", async () => {
    seed(
      finding("real-1", "alpha", {
        validation: { verdict: "confirmed", reasoning: "reachable" },
      }),
      finding("dupe-1", "beta", {
        validation: { verdict: "confirmed", reasoning: "reachable" },
      }),
    );
    detectorMock.dedupeFindings.mockImplementation(async () => [
      { primaryId: "real-1", duplicateIds: ["dupe-1"], reasoning: "same sink" },
    ]);

    await runDedup(outputDir, { summary: false }, env);

    expect(onDisk("alpha", "real-1").dedup).toBeUndefined();
    expect(onDisk("beta", "dupe-1").dedup?.duplicateOf).toBe("real-1");
  });
});
