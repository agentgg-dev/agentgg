// End-to-end live-validation test, external mode, against the real
// toy-vulnerable-app. Docker- and network-gated: `describe.runIf` no-ops
// unless TOY_APP_URL is set, and the test itself skips again if Docker is
// unavailable. Excluded from the default `pnpm test` run (see
// vitest.config.ts); collected only by `pnpm test:integration`
// (vitest.integration.config.ts) — this is a manual/CI-only check.
//
// Manual run (from the repo root):
//   docker build -f packages/cli/src/validation/sandbox.Dockerfile -t agentgg/live-sandbox:pw1.56.0-mcp0.0.41-2 packages/cli/src/validation
//   cd ../toy-vulnerable-app && npm install && npm start
//   ANTHROPIC_API_KEY=sk-... TOY_APP_URL=http://localhost:3000 pnpm test:integration
import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { effectiveVerdict, type Finding, getEvidenceDir, writeFileRecord } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ClaudeAgentDetector } from "../src/detectors/claude-agent.js";
import { runReproducePhase } from "../src/validation/reproduce.js";
import { DEFAULT_SANDBOX_IMAGE, dockerAvailable, type Sandbox } from "../src/validation/sandbox.js";

const url = process.env.TOY_APP_URL;

describe.runIf(url)("live validation e2e (external mode)", () => {
  let outDir: string;

  beforeEach(() => {
    outDir = mkdtempSync(join(tmpdir(), "agentgg-live-e2e-"));
  });

  afterEach(() => {
    rmSync(outDir, { recursive: true, force: true });
  });

  it("confirms a reflected XSS finding against the toy app", async () => {
    if (!(await dockerAvailable())) return; // skip when Docker absent

    const finding: Finding = {
      id: "e2e-xss-1",
      agentSlug: "e2e",
      title: "Reflected XSS in /search",
      vulnSlug: "xss",
      filePath: "src/server.ts",
      summary: "The q parameter of GET /search is echoed into the response unescaped.",
      details:
        "`/search` renders the raw query string into the response body without encoding, so a script tag passed as `q` executes in the victim's browser.",
      poc: 'GET /search?q=<script>document.title="xss"</script> reflects the payload unescaped into the page body.',
      impact:
        "An attacker who gets a victim to open a crafted /search link can run arbitrary script in that victim's session.",
      references: [],
      confidence: 0.9,
      notifications: [],
    };

    const detector = new ClaudeAgentDetector({
      apiKey: process.env.ANTHROPIC_API_KEY ?? "test",
      model: "claude-haiku-4-5-20251001",
    });

    await runReproducePhase({
      findings: [finding],
      detector,
      outDir,
      runId: "test-run",
      targetUrl: url as string,
      auth: {},
      image: DEFAULT_SANDBOX_IMAGE,
      timeoutMs: 120_000,
      budgetMs: 180_000,
      max: 1,
      signal: new AbortController().signal,
    });

    expect(finding.live?.result).toBe("reproduced");

    const evidenceDir = getEvidenceDir(outDir, finding.agentSlug, finding.id);
    expect(existsSync(evidenceDir)).toBe(true);
    expect(readdirSync(evidenceDir).length).toBeGreaterThan(0);

    expect(finding.live?.evidence?.script?.passed).toBe(true);
  }, 300_000);
});

// No Docker or toy app needed: a fake sandbox and a stub detector drive
// runReproducePhase end to end. The detector claims "reproduced" but the
// sandbox's trace never captures an HTTP request, so gradeLiveResult must
// downgrade it to inconclusive and the finding's static verdict must survive.
// Module-mocked per test (vi.doMock + resetModules, not a file-level vi.mock)
// so the real-sandbox describe block above keeps using the real module.
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
    // The phase file is already loaded (top-level import above), so force a
    // fresh copy that resolves ./sandbox.js and ./image.js to the mocks just
    // registered above; the file-scoped `runReproducePhase` stays untouched.
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
