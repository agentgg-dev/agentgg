import { describe, expect, it, vi } from "vitest";
import { parseProofReport, runProofScript } from "../src/validation/proof-script";
import { REQUEST_PANEL_SOURCE } from "../src/validation/request-panel";

const report = (specs: Array<{ title: string; ok: boolean }>) =>
  JSON.stringify({
    suites: [
      {
        title: "repro.spec.ts",
        specs: specs.map((s) => ({ title: s.title, ok: s.ok })),
      },
    ],
  });

describe("parseProofReport", () => {
  it("reads both outcomes when the script ran both tests", () => {
    const out = parseProofReport(
      report([
        { title: "exploit", ok: true },
        { title: "control", ok: true },
      ]),
    );
    expect(out).toEqual({ exploit: "passed", control: "passed" });
  });

  it("reports a failed exploit apart from a failed control", () => {
    const out = parseProofReport(
      report([
        { title: "exploit", ok: false },
        { title: "control", ok: true },
      ]),
    );
    expect(out).toEqual({ exploit: "failed", control: "passed" });
  });

  it("calls a test the script never declared missing, not failed", () => {
    expect(parseProofReport(report([{ title: "exploit", ok: true }]))).toEqual({
      exploit: "passed",
      control: "missing",
    });
  });

  it("finds tests nested in a describe block", () => {
    const nested = JSON.stringify({
      suites: [{ suites: [{ specs: [{ title: "exploit", ok: true }] }] }],
    });
    expect(parseProofReport(nested).exploit).toBe("passed");
  });

  it("treats output that is not a report as both tests missing", () => {
    expect(parseProofReport("Error: no tests found")).toEqual({
      exploit: "missing",
      control: "missing",
    });
  });
});

describe("runProofScript", () => {
  it("runs the spec through the request panel, so its page.request calls show on the recording", async () => {
    const sandbox = {
      writeFile: vi.fn(async () => {}),
      exec: vi.fn(async () => ({ code: 0, stdout: "", stderr: "" })),
    } as never as Parameters<typeof runProofScript>[0];
    await runProofScript(sandbox, 'import { test } from "@playwright/test";\n');
    expect(sandbox.writeFile).toHaveBeenCalledWith(
      "/srv/agentgg-request-panel.ts",
      REQUEST_PANEL_SOURCE,
    );
    expect(sandbox.writeFile).toHaveBeenCalledWith(
      "/srv/proof.spec.ts",
      'import { test } from "./agentgg-request-panel";\n',
    );
  });
});
