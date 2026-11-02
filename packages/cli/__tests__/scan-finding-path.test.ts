/**
 * The scan keeps a finding only when it names a file inside the repository,
 * whatever the detector returns, so no later phase reads a file outside it.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import type { Finding, UserConfig } from "@agentgg/core";
import { saveUserConfig } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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
  runAgent: vi.fn(async (_args: { agent: { slug: string } }) => [] as Finding[]),
  validateFinding: vi.fn(async (_args: { fileContent: string }) => ({
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

const SLUG = "test-path-agent";
const OUTSIDE_TEXT = "OUTSIDE_FILE_TEXT=1";

let agentggHome: string;
let projectRoot: string;
let outside: string;
let outputDir: string;
let agentsDir: string;
let agentPath: string;
let env: NodeJS.ProcessEnv;

function finding(filePath: string): Finding {
  return {
    id: `${SLUG}-${filePath}`,
    agentSlug: SLUG,
    title: "mock finding",
    vulnSlug: SLUG,
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

beforeEach(() => {
  agentggHome = mkdtempSync(join(tmpdir(), "agentgg-home-"));
  projectRoot = mkdtempSync(join(tmpdir(), "agentgg-target-"));
  outside = mkdtempSync(join(tmpdir(), "agentgg-outside-"));
  outputDir = mkdtempSync(join(tmpdir(), "agentgg-out-"));
  agentsDir = mkdtempSync(join(tmpdir(), "agentgg-agents-"));
  env = { AGENTGG_HOME: agentggHome };
  agentPath = join(agentsDir, `${SLUG}.md`);
  writeFileSync(
    agentPath,
    `---
slug: ${SLUG}
name: ${SLUG}
description: Synthetic agent for finding path tests.
where:
  extensions:
    - js
  preFilter:
    - regex: TARGET
      label: target
---
Stub agent body. Detector is mocked.
`,
    "utf8",
  );
  writeFileSync(join(projectRoot, "app.js"), "TARGET route\n", "utf8");
  writeFileSync(join(outside, "data.txt"), OUTSIDE_TEXT, "utf8");
  const cfg: UserConfig = {
    provider: "anthropic",
    anthropic: { apiKey: "sk-ant-test", model: "claude-sonnet-4-6" },
    schemaVersion: 1,
  };
  saveUserConfig(cfg, env);
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  for (const d of [agentggHome, projectRoot, outside, outputDir, agentsDir]) {
    rmSync(d, { recursive: true, force: true });
  }
  vi.restoreAllMocks();
  detectorMock.runAgent.mockReset();
  detectorMock.validateFinding.mockClear();
  for (const h of process.listeners("SIGINT")) process.removeListener("SIGINT", h);
});

const scan = () =>
  runScan(projectRoot, { template: [agentPath], output: outputDir, validate: true }, env);

describe("a detector finding outside the repository", () => {
  it("is not validated when it names an absolute path", async () => {
    detectorMock.runAgent.mockImplementation(async () => [finding(join(outside, "data.txt"))]);
    await scan();
    expect(detectorMock.validateFinding).not.toHaveBeenCalled();
  });

  it("is not validated when it climbs out of the root", async () => {
    const rel = relative(projectRoot, join(outside, "data.txt"));
    detectorMock.runAgent.mockImplementation(async () => [finding(rel)]);
    await scan();
    expect(detectorMock.validateFinding).not.toHaveBeenCalled();
  });

  it("does not stop a finding inside the root", async () => {
    detectorMock.runAgent.mockImplementation(async () => [finding("app.js")]);
    await scan();
    expect(detectorMock.validateFinding).toHaveBeenCalledTimes(1);
  });
});
