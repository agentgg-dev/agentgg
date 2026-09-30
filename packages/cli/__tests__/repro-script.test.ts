import { describe, expect, it, vi } from "vitest";
import { runReproScript } from "../src/validation/repro-script";

const fakeSandbox = (code: number, stdout = "", stderr = "") =>
  ({
    writeFile: vi.fn(async () => {}),
    exec: vi.fn(async () => ({ code, stdout, stderr })),
    readFile: vi.fn(),
    browserEndpoint: () => "",
    dispose: vi.fn(),
  }) as any;

const RAN_OK = "Running 1 test using 1 worker\n  1 passed (1.3s)";
const RAN_FAILED =
  "Running 1 test using 1 worker\n  1 failed\n    repro.spec.ts:3:5 > open redirect";
const NEVER_RAN =
  "Error: Cannot find module '@playwright/test'\n   at repro.spec.ts:1\nError: No tests found.";

describe("runReproScript", () => {
  it("marks passed when playwright ran the test and exited 0", async () => {
    const r = await runReproScript(fakeSandbox(0, RAN_OK), "test('x', async () => {});");
    expect(r).toMatchObject({ executed: true, passed: true });
  });

  it("marks failed when the test ran and did not pass", async () => {
    const r = await runReproScript(fakeSandbox(1, RAN_FAILED), "test('x', async () => {});");
    expect(r).toMatchObject({ executed: true, passed: false });
  });

  it("does not claim a run when no test ever started", async () => {
    const r = await runReproScript(fakeSandbox(1, "", NEVER_RAN), "test('x', async () => {});");
    expect(r).toMatchObject({ executed: false, passed: false });
  });

  it("keeps the runner output so a failure can be explained", async () => {
    const r = await runReproScript(fakeSandbox(1, "", NEVER_RAN), "test('x', async () => {});");
    expect(r.output).toContain("Cannot find module '@playwright/test'");
  });
});
