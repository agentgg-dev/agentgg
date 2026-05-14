import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Finding, UserConfig } from "@agentgg/core";
import {
  loadAllFileRecords,
  readFileRecord,
  saveUserConfig,
} from "@agentgg/core";

const detectorMock = vi.hoisted(() => ({
  detectFile: vi.fn(async () => [] as Finding[]),
  hunt: vi.fn(async () => [] as Finding[]),
  validateFinding: vi.fn(async () => ({
    verdict: "confirmed" as const,
    reasoning: "default",
  })),
}));

vi.mock("../src/llm.js", () => ({
  resolveDetector: () => ({
    name: "test-mock",
    detectFile: detectorMock.detectFile,
    hunt: detectorMock.hunt,
    validateFinding: detectorMock.validateFinding,
  }),
}));

import { runScan } from "../src/commands/scan.js";

let agentggHome: string;
let projectRoot: string;
let outputDir: string;
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  agentggHome = mkdtempSync(join(tmpdir(), "agentgg-home-"));
  projectRoot = mkdtempSync(join(tmpdir(), "agentgg-target-"));
  outputDir = mkdtempSync(join(tmpdir(), "agentgg-out-"));
  env = { AGENTGG_HOME: agentggHome };

  writeFileSync(
    join(projectRoot, "server.js"),
    "const x = 'sk-test'; require('cp').exec(process.argv[2]);",
    "utf8",
  );

  const cfg: UserConfig = {
    provider: "anthropic",
    anthropic: { apiKey: "sk-ant-test", model: "claude-sonnet-4-6" },
    schemaVersion: 1,
  };
  saveUserConfig(cfg, env);

  detectorMock.detectFile.mockImplementation(async ({ agent, filePath }) => [
    {
      id: `${agent.slug}-${filePath}-finding`,
      agentSlug: agent.slug,
      title: "mock finding",
      vulnSlug: agent.slug,
      filePath,
      summary: "s",
      details: "d",
      poc: "p",
      impact: "i",
      references: [],
      confidence: 0.9,
      notifications: [],
    },
  ]);
  detectorMock.hunt.mockImplementation(async () => []);
  detectorMock.validateFinding.mockImplementation(async () => ({
    verdict: "confirmed",
    reasoning: "default",
  }));
});

afterEach(() => {
  rmSync(agentggHome, { recursive: true, force: true });
  rmSync(projectRoot, { recursive: true, force: true });
  rmSync(outputDir, { recursive: true, force: true });
  vi.restoreAllMocks();
  detectorMock.detectFile.mockReset();
  detectorMock.hunt.mockReset();
  detectorMock.validateFinding.mockReset();
  for (const h of process.listeners("SIGINT")) {
    process.removeListener("SIGINT", h);
  }
});

function suppressLogs() {
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
}

describe("scan resume — file mode", () => {
  it("first scan calls the detector; second scan with unchanged file skips it", async () => {
    suppressLogs();
    await runScan(
      projectRoot,
      { template: ["sql-injection"], output: outputDir },
      env,
    );
    expect(detectorMock.detectFile).toHaveBeenCalledTimes(1);

    detectorMock.detectFile.mockClear();
    await runScan(
      projectRoot,
      { template: ["sql-injection"], output: outputDir },
      env,
    );
    expect(detectorMock.detectFile).not.toHaveBeenCalled();

    const records = loadAllFileRecords(outputDir);
    expect(records.length).toBe(1);
    expect(records[0].findings.length).toBe(1);
  });

  it("re-runs detection when the file content changes (contentHash mismatch)", async () => {
    suppressLogs();
    await runScan(
      projectRoot,
      { template: ["sql-injection"], output: outputDir },
      env,
    );
    expect(detectorMock.detectFile).toHaveBeenCalledTimes(1);

    writeFileSync(
      join(projectRoot, "server.js"),
      "const y = 'DIFFERENT'; require('cp').exec(process.argv[3]);",
      "utf8",
    );

    detectorMock.detectFile.mockClear();
    await runScan(
      projectRoot,
      { template: ["sql-injection"], output: outputDir },
      env,
    );
    expect(detectorMock.detectFile).toHaveBeenCalledTimes(1);
  });

  it("--rescan forces re-detection even when the cache hit would apply", async () => {
    suppressLogs();
    await runScan(
      projectRoot,
      { template: ["sql-injection"], output: outputDir },
      env,
    );
    detectorMock.detectFile.mockClear();

    await runScan(
      projectRoot,
      {
        template: ["sql-injection"],
        output: outputDir,
        rescan: true,
      },
      env,
    );
    expect(detectorMock.detectFile).toHaveBeenCalledTimes(1);
  });

  it("only skips when *this* agent ran before — different agents do not share the cache", async () => {
    suppressLogs();
    await runScan(
      projectRoot,
      { template: ["sql-injection"], output: outputDir },
      env,
    );
    detectorMock.detectFile.mockClear();

    await runScan(
      projectRoot,
      { template: ["command-injection"], output: outputDir },
      env,
    );
    expect(detectorMock.detectFile).toHaveBeenCalledTimes(1);
  });

  it("different --output dirs do not share cache (each output dir is its own scan)", async () => {
    suppressLogs();
    const secondOut = mkdtempSync(join(tmpdir(), "agentgg-out2-"));
    try {
      await runScan(
        projectRoot,
        { template: ["sql-injection"], output: outputDir },
        env,
      );
      detectorMock.detectFile.mockClear();
      // Same code, different --output → fresh scan, detector called.
      await runScan(
        projectRoot,
        { template: ["sql-injection"], output: secondOut },
        env,
      );
      expect(detectorMock.detectFile).toHaveBeenCalledTimes(1);
    } finally {
      rmSync(secondOut, { recursive: true, force: true });
    }
  });
});

describe("scan resume — validation phase", () => {
  it("skips findings that already have a validation verdict on disk", async () => {
    suppressLogs();
    await runScan(
      projectRoot,
      {
        template: ["sql-injection"],
        output: outputDir,
        validate: true,
      },
      env,
    );
    expect(detectorMock.validateFinding).toHaveBeenCalledTimes(1);

    detectorMock.detectFile.mockClear();
    detectorMock.validateFinding.mockClear();
    await runScan(
      projectRoot,
      {
        template: ["sql-injection"],
        output: outputDir,
        validate: true,
      },
      env,
    );
    expect(detectorMock.detectFile).not.toHaveBeenCalled();
    expect(detectorMock.validateFinding).not.toHaveBeenCalled();
  });

  it("--revalidate-all re-runs validation even for findings that already have a verdict", async () => {
    suppressLogs();
    await runScan(
      projectRoot,
      {
        template: ["sql-injection"],
        output: outputDir,
        validate: true,
      },
      env,
    );
    detectorMock.validateFinding.mockClear();

    await runScan(
      projectRoot,
      {
        template: ["sql-injection"],
        output: outputDir,
        validate: true,
        revalidateAll: true,
      },
      env,
    );
    expect(detectorMock.validateFinding).toHaveBeenCalledTimes(1);
  });

  it("on resume, persisted validation verdict carries over to the new RunMeta's summary", async () => {
    suppressLogs();
    detectorMock.validateFinding.mockImplementation(async () => ({
      verdict: "false-positive",
      reasoning: "stub",
    }));
    await runScan(
      projectRoot,
      {
        template: ["sql-injection"],
        output: outputDir,
        validate: true,
      },
      env,
    );

    detectorMock.validateFinding.mockClear();
    await runScan(
      projectRoot,
      {
        template: ["sql-injection"],
        output: outputDir,
        validate: true,
      },
      env,
    );

    const record = readFileRecord(outputDir, "server.js");
    expect(record?.findings[0].validation?.verdict).toBe("false-positive");
  });
});

describe("scan resume — RunMeta + persistence", () => {
  it("first scan writes a FileRecord; second skipped scan does not destroy it", async () => {
    suppressLogs();
    await runScan(
      projectRoot,
      { template: ["sql-injection"], output: outputDir },
      env,
    );
    const before = readFileRecord(outputDir, "server.js");
    expect(before).not.toBeNull();
    expect(before?.findings.length).toBe(1);
    const contentHashBefore = before?.contentHash;

    await runScan(
      projectRoot,
      { template: ["sql-injection"], output: outputDir },
      env,
    );

    const after = readFileRecord(outputDir, "server.js");
    expect(after?.findings.length).toBe(1);
    expect(after?.contentHash).toBe(contentHashBefore);
  });

  it("registers a SIGINT handler during the scan and removes it afterwards", async () => {
    suppressLogs();
    const before = process.listenerCount("SIGINT");
    await runScan(
      projectRoot,
      { template: ["sql-injection"], output: outputDir },
      env,
    );
    expect(process.listenerCount("SIGINT")).toBe(before);
  });
});
