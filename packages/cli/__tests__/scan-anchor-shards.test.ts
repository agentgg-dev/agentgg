import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding, UserConfig } from "@agentgg/core";
import { readFileRecord, saveUserConfig, writeFileRecord } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// An agent whose preFilter puts one anchor on every `TARGET` line, so the
// fixture below controls the anchor count exactly.
function writeAnchorAgent(dir: string, slug: string): string {
  const body = `---
slug: ${slug}
name: ${slug}
description: Synthetic agent for anchor-shard tests.
where:
  extensions:
    - js
  preFilter:
    - regex: TARGET
      label: target
---
Stub agent body. Detector is mocked.
`;
  const path = join(dir, `${slug}.md`);
  writeFileSync(path, body, "utf8");
  return path;
}

function mockFinding(slug: string, filePath: string): Finding {
  return {
    id: `${slug}-${filePath}`,
    agentSlug: slug,
    title: "mock finding",
    vulnSlug: slug,
    filePath,
    summary: "s",
    details: "d",
    poc: "p",
    impact: "i",
    references: [],
    confidence: 0.9,
    notifications: [],
  };
}

const detectorMock = vi.hoisted(() => ({
  recon: vi.fn(async () => ({
    purpose: "test fixture",
    languages: ["javascript"],
    frameworks: [] as string[],
    authModel: null as string | null,
    integrations: [] as string[],
    notableDirs: [] as string[],
    summary: "A small JS test fixture.",
  })),
  checkPrecondition: vi.fn(async () => ({ relevant: true, reason: "stub" })),
  runAgent: vi.fn(
    async (_args: {
      agent: { slug: string };
      candidates: { filePath: string; hits: { line: number }[] }[];
    }) => [] as Finding[],
  ),
  validateFinding: vi.fn(async () => ({
    verdict: "confirmed" as const,
    reasoning: "default",
  })),
}));

vi.mock("../src/llm.js", async () => {
  const actual = await vi.importActual<typeof import("../src/llm.js")>("../src/llm.js");
  return {
    ...actual,
    resolveDetector: () => ({
      name: "test-mock",
      recon: detectorMock.recon,
      checkPrecondition: detectorMock.checkPrecondition,
      runAgent: detectorMock.runAgent,
      validateFinding: detectorMock.validateFinding,
    }),
  };
});

import { runScan } from "../src/commands/scan.js";

const SLUG = "test-anchor-agent";
// 12 anchored lines: at a cap of 4 that is exactly 3 shards.
const ANCHORS = 12;

let agentggHome: string;
let projectRoot: string;
let outputDir: string;
let agentsDir: string;
let agentPath: string;
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  agentggHome = mkdtempSync(join(tmpdir(), "agentgg-home-"));
  projectRoot = mkdtempSync(join(tmpdir(), "agentgg-target-"));
  outputDir = mkdtempSync(join(tmpdir(), "agentgg-out-"));
  agentsDir = mkdtempSync(join(tmpdir(), "agentgg-agents-"));
  agentPath = writeAnchorAgent(agentsDir, SLUG);
  env = { AGENTGG_HOME: agentggHome };

  writeFileSync(
    join(projectRoot, "dense.js"),
    Array.from({ length: ANCHORS }, (_, i) => `TARGET route ${i + 1}`).join("\n"),
    "utf8",
  );

  const cfg: UserConfig = {
    provider: "anthropic",
    anthropic: { apiKey: "sk-ant-test", model: "claude-sonnet-4-6" },
    schemaVersion: 1,
  };
  saveUserConfig(cfg, env);

  detectorMock.recon.mockImplementation(async () => ({
    purpose: "test fixture",
    languages: ["javascript"],
    frameworks: [],
    authModel: null,
    integrations: [],
    notableDirs: [],
    summary: "A small JS test fixture.",
  }));
  detectorMock.checkPrecondition.mockImplementation(async () => ({
    relevant: true,
    reason: "stub",
  }));
  detectorMock.runAgent.mockImplementation(async ({ agent, candidates }) =>
    candidates.map((c) => mockFinding(agent.slug, c.filePath)),
  );
  detectorMock.validateFinding.mockImplementation(async () => ({
    verdict: "confirmed",
    reasoning: "default",
  }));
});

afterEach(() => {
  rmSync(agentggHome, { recursive: true, force: true });
  rmSync(projectRoot, { recursive: true, force: true });
  rmSync(outputDir, { recursive: true, force: true });
  rmSync(agentsDir, { recursive: true, force: true });
  vi.restoreAllMocks();
  detectorMock.recon.mockReset();
  detectorMock.checkPrecondition.mockReset();
  detectorMock.runAgent.mockReset();
  detectorMock.validateFinding.mockReset();
  for (const h of process.listeners("SIGINT")) {
    process.removeListener("SIGINT", h);
  }
});

function suppressLogs() {
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
}

type RunAgentCall = {
  agent: { slug: string };
  candidates: { filePath: string; hits: { line: number }[] }[];
};

/** The anchor lines each runAgent call was given, one array per call. */
function promptedLines(): number[][] {
  return (detectorMock.runAgent.mock.calls as unknown as [RunAgentCall][]).map(([a]) =>
    a.candidates.flatMap((c) => c.hits.map((h) => h.line)),
  );
}

const base = () => ({ template: [agentPath], output: outputDir });

describe("anchor cap — splitting", () => {
  it("splits an anchor-dense file into one prompt per shard", async () => {
    suppressLogs();
    await runScan(projectRoot, { ...base(), maxAnchorsPerBatch: 4 }, env);

    const lines = promptedLines();
    expect(lines.length).toBe(3);
    for (const l of lines) expect(l.length).toBe(4);
    // Contiguous and disjoint: every anchor reviewed exactly once.
    expect(lines.flat().sort((a, b) => a - b)).toEqual(
      Array.from({ length: ANCHORS }, (_, i) => i + 1),
    );
  });

  it("leaves the file whole when the cap is disabled", async () => {
    suppressLogs();
    await runScan(projectRoot, { ...base(), maxAnchorsPerBatch: false }, env);

    const lines = promptedLines();
    expect(lines.length).toBe(1);
    expect(lines[0].length).toBe(ANCHORS);
  });

  it("leaves the file whole when its anchors sit under the cap", async () => {
    suppressLogs();
    await runScan(projectRoot, { ...base(), maxAnchorsPerBatch: 150 }, env);
    expect(promptedLines().length).toBe(1);
  });
});

describe("anchor cap — per-shard resume", () => {
  it("records a key per shard and re-runs nothing on a clean re-run", async () => {
    suppressLogs();
    await runScan(projectRoot, { ...base(), maxAnchorsPerBatch: 4 }, env);

    const rec = readFileRecord(outputDir, SLUG, "dense.js");
    expect(rec?.shards?.length).toBe(3);
    expect(rec?.shards).toContain("1-4:4");

    detectorMock.runAgent.mockClear();
    await runScan(projectRoot, { ...base(), maxAnchorsPerBatch: 4 }, env);
    expect(detectorMock.runAgent).not.toHaveBeenCalled();
  });

  it("re-runs only the failed shard, and does not skip it", async () => {
    suppressLogs();
    // Fail the middle shard. Without per-shard resume, the sibling shards
    // would stamp the file as analyzed and this one would never re-run.
    detectorMock.runAgent.mockImplementation(async ({ agent, candidates }) => {
      if (candidates.some((c) => c.hits.some((h) => h.line === 5))) {
        throw new Error("boom");
      }
      return candidates.map((c) => mockFinding(agent.slug, c.filePath));
    });
    await runScan(projectRoot, { ...base(), maxAnchorsPerBatch: 4 }, env);

    const rec = readFileRecord(outputDir, SLUG, "dense.js");
    expect(rec?.shards?.sort()).toEqual(["1-4:4", "9-12:4"]);

    detectorMock.runAgent.mockClear();
    detectorMock.runAgent.mockImplementation(async ({ agent, candidates }) =>
      candidates.map((c) => mockFinding(agent.slug, c.filePath)),
    );
    await runScan(projectRoot, { ...base(), maxAnchorsPerBatch: 4 }, env);

    expect(promptedLines()).toEqual([[5, 6, 7, 8]]);
  });

  it("lifts a resumed file's findings once, not once per shard", async () => {
    suppressLogs();
    detectorMock.runAgent.mockImplementation(async ({ agent, candidates }) => {
      if (candidates.some((c) => c.hits.some((h) => h.line === 5))) {
        throw new Error("boom");
      }
      return candidates.map((c) => mockFinding(agent.slug, c.filePath));
    });
    await runScan(projectRoot, { ...base(), maxAnchorsPerBatch: 4 }, env);

    // Second run: shards 1 and 3 resume from one shared record, shard 2 runs.
    detectorMock.runAgent.mockClear();
    detectorMock.runAgent.mockImplementation(async ({ agent, candidates }) =>
      candidates.map((c) => mockFinding(agent.slug, c.filePath)),
    );
    await runScan(projectRoot, { ...base(), maxAnchorsPerBatch: 4 }, env);

    // The mock returns one finding per file with a stable id, so the record
    // holds exactly one however many shards reported it.
    const rec = readFileRecord(outputDir, SLUG, "dense.js");
    expect(rec?.findings.length).toBe(1);
  });

  it("treats a record written before the cap existed as complete", async () => {
    suppressLogs();
    detectorMock.runAgent.mockImplementation(async ({ agent, candidates }) => {
      if (candidates.some((c) => c.hits.some((h) => h.line === 5))) {
        throw new Error("boom");
      }
      return candidates.map((c) => mockFinding(agent.slug, c.filePath));
    });
    await runScan(projectRoot, { ...base(), maxAnchorsPerBatch: 4 }, env);

    // Strip the field, as a record written by an older build would look.
    const rec = readFileRecord(outputDir, SLUG, "dense.js");
    if (!rec) throw new Error("expected a file record");
    rec.shards = undefined;
    writeFileRecord(outputDir, rec);

    detectorMock.runAgent.mockClear();
    await runScan(projectRoot, { ...base(), maxAnchorsPerBatch: 4 }, env);
    expect(detectorMock.runAgent).not.toHaveBeenCalled();
  });

  it("drops keys from a prior cut when the file changes under it", async () => {
    suppressLogs();
    // Fail one shard so no agent sidecar is written. Without that, agent-level
    // resume serves the whole agent from cache and per-file resume never runs.
    detectorMock.runAgent.mockImplementation(async ({ agent, candidates }) => {
      if (candidates.some((c) => c.hits.some((h) => h.line === 5))) {
        throw new Error("boom");
      }
      return candidates.map((c) => mockFinding(agent.slug, c.filePath));
    });
    await runScan(projectRoot, { ...base(), maxAnchorsPerBatch: 4 }, env);
    expect(readFileRecord(outputDir, SLUG, "dense.js")?.shards?.sort()).toEqual([
      "1-4:4",
      "9-12:4",
    ]);

    // A leading blank line shifts every anchor down one, so the new cut has
    // different keys. A stale key that survived could silently match a new
    // shard and skip it.
    writeFileSync(
      join(projectRoot, "dense.js"),
      `\n${Array.from({ length: ANCHORS }, (_, i) => `TARGET route ${i + 1}`).join("\n")}`,
      "utf8",
    );
    detectorMock.runAgent.mockClear();
    detectorMock.runAgent.mockImplementation(async ({ agent, candidates }) =>
      candidates.map((c) => mockFinding(agent.slug, c.filePath)),
    );
    await runScan(projectRoot, { ...base(), maxAnchorsPerBatch: 4 }, env);

    expect(promptedLines().length).toBe(3);
    expect(readFileRecord(outputDir, SLUG, "dense.js")?.shards?.sort()).toEqual([
      "10-13:4",
      "2-5:4",
      "6-9:4",
    ]);
  });
});

describe("incidental writes must not claim completeness", () => {
  it("does not skip a file whose only record came from another batch's finding", async () => {
    suppressLogs();
    // Two candidate files, one batch each. The batch for the first reports a
    // finding located in the second, which persists a record for a file that
    // was never reviewed. `--max-batches 1` then drops the second file's own
    // batch, so nothing corrects that record before the next run.
    writeFileSync(
      join(projectRoot, "aaa.js"),
      Array.from({ length: ANCHORS }, (_, i) => `TARGET a ${i + 1}`).join("\n"),
      "utf8",
    );
    writeFileSync(
      join(projectRoot, "zzz.js"),
      Array.from({ length: ANCHORS }, (_, i) => `TARGET z ${i + 1}`).join("\n"),
      "utf8",
    );
    detectorMock.runAgent.mockImplementation(async ({ agent }) => [
      { ...mockFinding(agent.slug, "zzz.js"), id: "cross-file-finding" },
    ]);

    await runScan(
      projectRoot,
      { ...base(), maxAnchorsPerBatch: false, maxFilesPerBatch: 1, maxBatches: 1 },
      env,
    );

    const rec = readFileRecord(outputDir, SLUG, "zzz.js");
    expect(rec).not.toBeNull();
    // The record exists only because another batch reported into it. It must
    // not read as "analyzed whole" on the next run.
    expect(rec?.shards).toEqual([]);

    detectorMock.runAgent.mockClear();
    detectorMock.runAgent.mockImplementation(async ({ agent, candidates }) =>
      candidates.map((c) => mockFinding(agent.slug, c.filePath)),
    );
    // Uncapped this time, so the only thing that can keep zzz.js out of the
    // queue is resume deciding its record already covers it.
    await runScan(
      projectRoot,
      { ...base(), maxAnchorsPerBatch: false, maxFilesPerBatch: 1, maxBatches: false },
      env,
    );

    const reviewed = (detectorMock.runAgent.mock.calls as unknown as [RunAgentCall][]).flatMap(
      ([a]) => a.candidates.map((c) => c.filePath),
    );
    expect(reviewed).toContain("zzz.js");
  });
});

describe("cap values that are not a positive number", () => {
  // 0 must read as "no cap", the same sentinel --max-batches and
  // --max-files-per-agent use. Read literally it would disable the split but
  // still close a batch after every file.
  for (const [label, value] of [
    ["zero", 0],
    ["negative", -5],
    ["not a number", Number.NaN],
  ] as const) {
    it(`treats ${label} as no cap`, async () => {
      suppressLogs();
      await runScan(projectRoot, { ...base(), maxAnchorsPerBatch: value }, env);
      const lines = promptedLines();
      expect(lines.length).toBe(1);
      expect(lines[0].length).toBe(ANCHORS);
    });
  }
});
