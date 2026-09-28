// End-to-end live-validation test, external mode, against the real
// toy-vulnerable-app. Docker- and network-gated: `describe.runIf` no-ops
// unless TOY_APP_URL is set, and the test itself skips again if Docker is
// unavailable. Excluded from the default `pnpm test` run (see
// vitest.config.ts); collected only by `pnpm test:integration`
// (vitest.integration.config.ts) — this is a manual/CI-only check.
//
// Manual run (from the repo root):
//   docker build -f packages/cli/src/validation/sandbox.Dockerfile -t agentgg/live-sandbox:pw1.56.0-mcp0.0.41-4 packages/cli/src/validation
//   cd ../toy-vulnerable-app && npm install && npm start
//   ANTHROPIC_API_KEY=sk-... TOY_APP_URL=http://localhost:3000 pnpm test:integration
import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Finding, getEvidenceDir } from "@agentgg/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ClaudeAgentDetector } from "../src/detectors/claude-agent.js";
import { runReproducePhase } from "../src/validation/reproduce.js";
import { DEFAULT_SANDBOX_IMAGE, dockerAvailable } from "../src/validation/sandbox.js";

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
      signal: new AbortController().signal,
    });

    expect(finding.live?.result).toBe("reproduced");

    const evidenceDir = getEvidenceDir(outDir, finding.agentSlug, finding.id);
    expect(existsSync(evidenceDir)).toBe(true);
    expect(readdirSync(evidenceDir).length).toBeGreaterThan(0);

    expect(finding.live?.evidence?.script?.passed).toBe(true);
  }, 300_000);
});
