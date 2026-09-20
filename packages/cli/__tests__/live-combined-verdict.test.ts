// The combined verdict when the live agent claims more than its evidence
// shows. No Docker and no toy app: a fake sandbox and a stub detector drive
// runReproducePhase end to end, so this runs in the default suite.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { effectiveVerdict, type Finding, writeFileRecord } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Sandbox } from "../src/validation/sandbox.js";

describe("combined verdict when live evidence has no captured request", () => {
  let outDir: string;
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    outDir = mkdtempSync(join(tmpdir(), "agentgg-live-fake-"));
    fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));
  });

  afterEach(() => {
    fetchSpy.mockRestore();
    rmSync(outDir, { recursive: true, force: true });
    vi.doUnmock("../src/validation/sandbox.js");
    vi.doUnmock("../src/validation/image.js");
    vi.resetModules();
  });

  it("keeps a static-uncertain CSRF finding at uncertain", async () => {
    const out = new Map<string, Buffer>();
    const fakeSandbox: Sandbox = {
      browserEndpoint: () => "http://localhost:8931/sse",
      async exec(cmd) {
        const line = cmd.join(" ");
        if (line.startsWith("ls -1t /out")) {
          const names = [...out.keys()].map((p) => p.slice("/out/".length));
          return { code: 0, stdout: `${names.reverse().join("\n")}\n`, stderr: "" };
        }
        // No traces dir at all: the trace carries no captured request.
        if (line.includes("find /out/traces")) return { code: 1, stdout: "", stderr: "" };
        if (line.includes("rm -rf")) {
          out.clear();
          return { code: 0, stdout: "", stderr: "" };
        }
        return { code: 0, stdout: "", stderr: "" };
      },
      async readFile(path) {
        const buf = out.get(path);
        if (!buf) throw new Error(`no such file: ${path}`);
        return buf;
      },
      async writeFile() {},
      async logs() {
        return "";
      },
      async dispose() {},
    };

    vi.doMock("../src/validation/sandbox.js", async (orig) => ({
      ...(await orig<typeof import("../src/validation/sandbox.js")>()),
      startLocalDockerSandbox: async () => fakeSandbox,
    }));
    vi.doMock("../src/validation/image.js", () => ({
      ensureSandboxImage: async () => ({ ok: true, built: false }),
    }));
    // Import the phase fresh so it resolves ./sandbox.js and ./image.js to
    // the mocks registered just above.
    vi.resetModules();

    const { runReproducePhase: runReproducePhaseFakeSandbox } = await import(
      "../src/validation/reproduce.js"
    );

    const finding: Finding = {
      id: "csrf-1",
      agentSlug: "a",
      title: "CSRF on POST /account/email",
      vulnSlug: "csrf",
      filePath: "src/routes/account.ts",
      summary: "POST /account/email changes the account email with no CSRF token or origin check.",
      details:
        "`/account/email` accepts a state-changing POST with no CSRF token and no Origin/Referer check.",
      poc: "A same-origin form POST to /account/email changes the address while authenticated.",
      impact:
        "An attacker who lures a logged-in user to a hostile page can change that user's account email.",
      references: [],
      confidence: 0.6,
      notifications: [],
      validation: {
        verdict: "uncertain",
        reasoning:
          "the endpoint never checks the CSRF cookie, so a same-origin request alone does not prove cross-site forgery",
      },
    };

    writeFileRecord(outDir, {
      agentSlug: finding.agentSlug,
      filePath: finding.filePath,
      contentHash: "h",
      findings: [finding],
      analysisHistory: [],
      candidates: [],
      status: "analyzed",
    } as never);

    const detector = {
      name: "fake",
      async reproduceFinding() {
        // Playwright writes the session video, but never a network trace.
        out.set("/out/page-1.webm", Buffer.from("video"));
        return {
          result: "reproduced" as const,
          reasoning: "a same-origin POST changed the account email",
          counterevidence: "",
          script: "// repro",
        };
      },
    };

    await runReproducePhaseFakeSandbox({
      findings: [finding],
      // biome-ignore lint/suspicious/noExplicitAny: only reproduceFinding is exercised
      detector: detector as any,
      outDir,
      runId: "test-run",
      targetUrl: "http://localhost:3000",
      auth: {},
      image: "img",
      timeoutMs: 30_000,
      budgetMs: 60_000,
      max: 10,
      signal: new AbortController().signal,
    });

    expect(finding.live?.result).toBe("inconclusive");
    expect(effectiveVerdict(finding)).toBe("uncertain");
  });
});
