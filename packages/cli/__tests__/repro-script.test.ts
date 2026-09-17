import { describe, expect, it, vi } from "vitest";
import { runReproScript } from "../src/validation/repro-script";

const fakeSandbox = (code: number) => ({
  writeFile: vi.fn(async () => {}),
  exec: vi.fn(async () => ({ code, stdout: "", stderr: "" })),
  readFile: vi.fn(),
  browserEndpoint: () => "",
  dispose: vi.fn(),
}) as any;

describe("runReproScript", () => {
  it("marks passed when playwright exits 0", async () => {
    const r = await runReproScript(fakeSandbox(0), "test('x', async () => {});");
    expect(r).toMatchObject({ executed: true, passed: true });
  });

  it("marks failed when playwright exits nonzero", async () => {
    const r = await runReproScript(fakeSandbox(1), "test('x', async () => {});");
    expect(r).toMatchObject({ executed: true, passed: false });
  });
});
