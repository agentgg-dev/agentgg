import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Detector, PreconditionCheckArgs } from "../src/detect.js";
import { FatalScanError } from "../src/diagnostics.js";
import { selectAgents } from "../src/precondition.js";

function gatedAgent(slug: string): Agent {
  return Agent.parse({
    slug,
    name: slug,
    description: "Synthetic gated agent.",
    precondition: { prompt: "Only run if relevant to this repo." },
    prompt: "Stub.",
  });
}

function detectorWith(check: (args: PreconditionCheckArgs) => Promise<unknown>): Detector {
  return { name: "test-mock", checkPrecondition: check } as unknown as Detector;
}

let rootDir: string;

beforeEach(() => {
  rootDir = mkdtempSync(join(tmpdir(), "agentgg-precondition-"));
  writeFileSync(join(rootDir, "server.js"), "const x = 1;", "utf8");
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  rmSync(rootDir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

function select(detector: Detector, slugs: string[], abortController = new AbortController()) {
  return selectAgents(slugs.map(gatedAgent), {
    rootDir,
    walkCfg: { excludePatterns: [], includePatterns: [], maxFileSizeBytes: 500 * 1024 },
    detector,
    abortController,
  });
}

describe("selectAgents with a failing prompt gate", () => {
  it("warns and queues the agent, and still evaluates the others", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const detector = detectorWith(async (args) => {
      if (args.agentName === "flaky") throw new Error("No object generated");
      return { relevant: false, reason: "not relevant" };
    });

    const { queued, decisions } = await select(detector, ["flaky", "calm"]);

    expect(queued.map((a) => a.slug)).toEqual(["flaky"]);
    expect(decisions.find((d) => d.slug === "calm")?.queued).toBe(false);
    expect(warn.mock.calls.some(([line]) => String(line).includes("precondition:flaky"))).toBe(
      true,
    );
  });

  it("stops on an error that would fail every later call", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const detector = detectorWith(async () => {
      throw new Error("No allowed providers are available for the selected model.");
    });

    await expect(select(detector, ["one", "two"])).rejects.toBeInstanceOf(FatalScanError);
  });

  it("does not queue agents once the scan is aborted", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const abortController = new AbortController();
    abortController.abort();
    const detector = detectorWith(async () => {
      throw Object.assign(new Error("The operation was aborted"), { name: "AbortError" });
    });

    await expect(select(detector, ["one"], abortController)).rejects.toThrow(/aborted/);
    expect(warn).not.toHaveBeenCalled();
  });
});
