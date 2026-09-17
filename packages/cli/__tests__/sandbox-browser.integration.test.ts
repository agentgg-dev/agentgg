// Docker-gated: proves a fresh sandbox container launches a browser on the
// FIRST navigation (no browser_install detour) and injects the URL banner.
// Excluded from `pnpm test`; run with `pnpm test:integration`.
import { experimental_createMCPClient } from "ai";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_SANDBOX_IMAGE,
  dockerAvailable,
  type Sandbox,
  startLocalDockerSandbox,
} from "../src/validation/sandbox.js";

type McpClient = { tools: () => Promise<unknown>; close: () => Promise<void> };
type McpTools = Record<
  string,
  { execute: (a: unknown, o: unknown) => Promise<{ content: { text?: string }[] }> }
>;

/** Start a sandbox, run `fn` against its MCP tools, then always tear down. */
async function withTools(fn: (tools: McpTools) => Promise<void>): Promise<void> {
  let sandbox: Sandbox | undefined;
  let client: McpClient | undefined;
  try {
    sandbox = await startLocalDockerSandbox({ image: DEFAULT_SANDBOX_IMAGE });
    client = (await experimental_createMCPClient({
      transport: { type: "sse", url: sandbox.browserEndpoint() },
    })) as unknown as McpClient;
    await fn((await client.tools()) as McpTools);
  } finally {
    await client?.close();
    await sandbox?.dispose();
  }
}

const OPTS = { toolCallId: "t1", messages: [] };
const asText = (r: { content: { text?: string }[] }) => r.content.map((c) => c.text ?? "").join("");

describe("sandbox browser", () => {
  it("launches a browser on the first navigation", async () => {
    if (!(await dockerAvailable())) return;
    await withTools(async (tools) => {
      const nav = await tools.browser_navigate.execute({ url: "data:text/html,<h1>ok</h1>" }, OPTS);
      // Without --browser chromium this is "Chromium distribution 'chrome' is
      // not found at /opt/google/chrome/chrome", and the agent has to repair it
      // with a 435MB browser_install.
      expect(asText(nav)).not.toContain("is not found at");
      expect(asText(nav)).toContain("ok");
    });
  }, 180_000);

  it("injects a URL banner that tracks the current address", async () => {
    if (!(await dockerAvailable())) return;
    await withTools(async (tools) => {
      const url = "data:text/html,<h1>page</h1>";
      await tools.browser_navigate.execute({ url }, OPTS);
      const res = await tools.browser_evaluate.execute(
        {
          function:
            "() => { const e = document.getElementById('__agentgg_url_banner__'); return e ? e.textContent : 'MISSING'; }",
        },
        OPTS,
      );
      // (No `.not.toContain("MISSING")` check: mcp-server-playwright echoes the
      // called function's own source in every response, so that literal is
      // always present regardless of outcome. `toContain(url)` below is the
      // real assertion: it only holds if the banner element exists and its
      // text is the live page URL, not the fallback.
      expect(asText(res)).toContain(url);
    });
  }, 180_000);
});
