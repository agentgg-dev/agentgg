import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FileRecord, UserConfig } from "@agentgg/core";
import { saveUserConfig, upsertScanMeta, writeFileRecord } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const detectorMock = vi.hoisted(() => ({
  /** The options each `resolveDetector` call received. */
  resolved: [] as Record<string, unknown>[],
}));

const liveMocks = vi.hoisted(() => ({
  setUpDocker: vi.fn(
    async (): Promise<{ ok: true } | { ok: false; reason: string }> => ({
      ok: true,
    }),
  ),
  runReproducePhase: vi.fn(async () => {}),
}));
vi.mock("../src/validation/docker-setup.js", () => ({ setUpDocker: liveMocks.setUpDocker }));
vi.mock("../src/validation/reproduce.js", () => ({
  runReproducePhase: liveMocks.runReproducePhase,
}));

vi.mock("../src/llm.js", async () => {
  const actual = await vi.importActual<typeof import("../src/llm.js")>("../src/llm.js");
  return {
    ...actual,
    resolveDetector: (_config: unknown, options: Record<string, unknown>) => {
      detectorMock.resolved.push(options);
      return { name: "test-mock" };
    },
  };
});

import { runLiveValidate } from "../src/commands/live-validate.js";

const TARGET_URL = "http://localhost:3000";

let agentggHome: string;
let projectRoot: string;
let outputDir: string;
let env: NodeJS.ProcessEnv;

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
  // A scan with no records: the command builds its detector, finds nothing
  // to reproduce and returns before it needs a sandbox.
  upsertScanMeta(outputDir, projectRoot);
  detectorMock.resolved.length = 0;
  vi.spyOn(console, "log").mockImplementation(() => {});
});

afterEach(() => {
  rmSync(agentggHome, { recursive: true, force: true });
  rmSync(projectRoot, { recursive: true, force: true });
  rmSync(outputDir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

describe("runLiveValidate provider options", () => {
  it("gives the detector the routing", async () => {
    await runLiveValidate(
      outputDir,
      { targetUrl: TARGET_URL, provider: "openrouter", openrouterRouting: '{"sort":"price"}' },
      env,
    );

    expect(detectorMock.resolved[0]).toMatchObject({ openrouterRouting: '{"sort":"price"}' });
  });

  it("passes the project to the Vertex credentials", async () => {
    await runLiveValidate(
      outputDir,
      { targetUrl: TARGET_URL, provider: "vertex", project: "my-project" },
      env,
    );

    expect(detectorMock.resolved[0]).toMatchObject({
      credentials: { vertexProject: "my-project" },
    });
  });
});

describe("runLiveValidate Docker setup", () => {
  beforeEach(() => {
    writeFileRecord(outputDir, {
      agentSlug: "xss",
      filePath: "src/app.ts",
      contentHash: "h",
      findings: [],
      analysisHistory: [],
      candidates: [],
      status: "validated",
    } as unknown as FileRecord);
    liveMocks.setUpDocker.mockClear();
    liveMocks.runReproducePhase.mockClear();
  });

  it("stops with the reason when Docker is not ready", async () => {
    liveMocks.setUpDocker.mockResolvedValueOnce({ ok: false, reason: "Docker is not installed." });
    await expect(runLiveValidate(outputDir, { targetUrl: TARGET_URL }, env)).rejects.toThrow(
      "Docker is not installed.",
    );
    expect(liveMocks.runReproducePhase).not.toHaveBeenCalled();
  });

  it("goes on to reproduce once Docker is ready", async () => {
    await runLiveValidate(outputDir, { targetUrl: TARGET_URL }, env);
    expect(liveMocks.setUpDocker).toHaveBeenCalledTimes(1);
    expect(liveMocks.runReproducePhase).toHaveBeenCalledTimes(1);
  });

  it("does not touch local Docker when attaching to a running sandbox", async () => {
    await runLiveValidate(
      outputDir,
      { targetUrl: TARGET_URL, sandboxEndpoint: "http://127.0.0.1:8931" },
      { ...env, AGENTGG_SANDBOX_TOKEN: "tk" },
    );
    expect(liveMocks.setUpDocker).not.toHaveBeenCalled();
  });
});
