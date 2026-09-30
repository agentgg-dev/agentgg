// Docker-gated: checks the real /out against the model that copy-evidence.test.ts
// fakes. If the layout drifts, those unit tests are worthless.
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import AdmZip from "adm-zip";
import { experimental_createMCPClient } from "ai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { clearSandboxOut, copyEvidence } from "../src/validation/reproduce.js";
import {
  DEFAULT_SANDBOX_IMAGE,
  dockerAvailable,
  type Sandbox,
  startLocalDockerSandbox,
} from "../src/validation/sandbox.js";

type McpClient = { tools: () => Promise<unknown>; close: () => Promise<void> };
type McpTools = Record<string, { execute: (a: unknown, o: unknown) => Promise<unknown> }>;
const OPTS = { toolCallId: "t1", messages: [] };

/** Drive one browser session, then close the client so Playwright flushes. */
async function session(sandbox: Sandbox, url: string, shot: string): Promise<void> {
  const client = (await experimental_createMCPClient({
    transport: { type: "sse", url: sandbox.browserEndpoint() },
  })) as unknown as McpClient;
  try {
    const tools = (await client.tools()) as McpTools;
    await tools.browser_navigate.execute({ url }, OPTS);
    await tools.browser_take_screenshot.execute({ filename: shot }, OPTS);
  } finally {
    await client.close();
  }
}

describe("copyEvidence against a real sandbox", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "agentgg-evidence-e2e-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("captures the video and a loadable trace zip, and isolates the next finding", async () => {
    if (!(await dockerAvailable())) return;

    let sandbox: Sandbox | undefined;
    try {
      sandbox = await startLocalDockerSandbox({ image: DEFAULT_SANDBOX_IMAGE });

      await session(sandbox, "data:text/html,<h1>first</h1>", "first.png");
      const first = await copyEvidence(sandbox, join(dir, "a"));

      expect(first.video).toMatch(/\.webm$/);
      expect(first.screenshots).toContain("first.png");
      // --save-trace writes a traces/ directory, never a zip; the copy builds one.
      expect(first.trace).toBe("trace.zip");
      const entries = new AdmZip(join(dir, "a", "trace.zip")).getEntries().map((e) => e.entryName);
      expect(entries.some((n) => n.endsWith(".trace"))).toBe(true);
      expect(existsSync(join(dir, "a", "traces"))).toBe(false);

      // Second finding in the SAME sandbox must not inherit the first's files.
      await clearSandboxOut(sandbox);
      await session(sandbox, "data:text/html,<h1>second</h1>", "second.png");
      const second = await copyEvidence(sandbox, join(dir, "b"));

      expect(second.screenshots).toEqual(["second.png"]);
      expect(second.video).not.toBe(first.video);
      expect(existsSync(join(dir, "b", "first.png"))).toBe(false);
      expect(existsSync(join(dir, "b", first.video as string))).toBe(false);
    } finally {
      await sandbox?.dispose();
    }
  }, 240_000);
});
