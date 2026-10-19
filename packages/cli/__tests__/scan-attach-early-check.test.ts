// `--sandbox-endpoint` without $AGENTGG_SANDBOX_TOKEN (or a bad endpoint URL)
// must fail before detect/validate/dedup spend anything — mirrors the
// existing "--live-validate requires --target-url" fail-fast check. The
// check now runs as the first thing in `runScan`, before config/catalog
// loading, so a mock-free assertion (no real rootArg or config needed) is
// itself proof the failure is early; `resolveDetector` is spied only to make
// "before detect runs" explicit rather than relying on nothing else throwing
// first. This is intentionally lighter than __tests__/scan-phase-order.test.ts's
// full detector-mock rig (agents dir, fixture files, findings): nothing past
// the fail-fast checks ever executes, so there is nothing for that rig to
// exercise.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";

const resolveDetectorMock = vi.fn();
vi.mock("../src/llm.js", async () => {
  const actual = await vi.importActual<typeof import("../src/llm.js")>("../src/llm.js");
  return { ...actual, resolveDetector: resolveDetectorMock };
});

const setUpDockerMock = vi.fn(async () => ({ ok: true }) as const);
vi.mock("../src/validation/docker-setup.js", () => ({ setUpDocker: setUpDockerMock }));

const { runScan } = await import("../src/commands/scan.js");

describe("scan --live-validate --sandbox-endpoint early checks", () => {
  beforeEach(() => {
    resolveDetectorMock.mockClear();
    setUpDockerMock.mockClear();
  });

  it("throws before any detect work when $AGENTGG_SANDBOX_TOKEN is missing", async () => {
    await expect(
      runScan(
        "/does/not/matter",
        {
          liveValidate: true,
          targetUrl: "http://localhost:3000",
          sandboxEndpoint: "http://127.0.0.1:8931",
        },
        {},
      ),
    ).rejects.toThrow(/AGENTGG_SANDBOX_TOKEN/);
    expect(resolveDetectorMock).not.toHaveBeenCalled();
  });

  it("reads the token from the passed-in env, not process.env", async () => {
    await expect(
      runScan(
        "/does/not/matter",
        {
          liveValidate: true,
          targetUrl: "http://localhost:3000",
          sandboxEndpoint: "http://127.0.0.1:8931",
        },
        { AGENTGG_SANDBOX_TOKEN: "tk" },
      ),
      // Fails on something further downstream (no real config/catalog here),
      // but never on the missing-token message.
    ).rejects.not.toThrow(/AGENTGG_SANDBOX_TOKEN/);
  });

  it("still runs the existing --live-validate/--target-url check first", async () => {
    await expect(runScan("/does/not/matter", { liveValidate: true }, {})).rejects.toThrow(
      /--target-url/,
    );
    expect(resolveDetectorMock).not.toHaveBeenCalled();
  });
});

describe("scan --live-validate Docker setup", () => {
  beforeEach(() => {
    resolveDetectorMock.mockClear();
    setUpDockerMock.mockClear();
  });

  it("sets up Docker before any scan work when the sandbox runs locally", async () => {
    setUpDockerMock.mockRejectedValueOnce(new Error("stop after the Docker setup"));
    await expect(
      runScan("/does/not/matter", { liveValidate: true, targetUrl: "http://localhost:3000" }, {}),
    ).rejects.toThrow("stop after the Docker setup");
    expect(setUpDockerMock).toHaveBeenCalledTimes(1);
    expect(resolveDetectorMock).not.toHaveBeenCalled();
  });

  it("does not touch local Docker when attaching to a running sandbox", async () => {
    await runScan(
      "/does/not/matter",
      {
        liveValidate: true,
        targetUrl: "http://localhost:3000",
        sandboxEndpoint: "http://127.0.0.1:8931",
      },
      { AGENTGG_SANDBOX_TOKEN: "tk" },
    ).catch(() => {});
    expect(setUpDockerMock).not.toHaveBeenCalled();
  });

  it("prints why Docker is not ready and goes on with the scan", async () => {
    setUpDockerMock.mockResolvedValueOnce({
      ok: false,
      reason: "Docker is not installed.",
    } as never);
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const output = mkdtempSync(join(tmpdir(), "agentgg-out-"));
    try {
      await runScan(
        "/does/not/matter",
        { liveValidate: true, targetUrl: "http://localhost:3000", output },
        {},
      ).catch(() => {});
      expect(log.mock.calls.flat().join("\n")).toContain("Docker is not installed.");
    } finally {
      log.mockRestore();
      rmSync(output, { recursive: true, force: true });
    }
  });
});
