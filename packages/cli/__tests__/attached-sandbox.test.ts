import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startAttachedSandbox } from "../src/validation/sandbox";
// @ts-expect-error plain ESM module
import { createControlServer } from "../src/validation/sandbox-control.mjs";

let control: Server;
let mcp: Server;
let controlUrl = "";
let endpoint = "";

beforeAll(async () => {
  control = createControlServer({ token: "tk", logs: () => "logs!" });
  mcp = createServer((_req, res) => res.writeHead(200).end());
  await Promise.all([
    new Promise<void>((r) => control.listen(0, "127.0.0.1", () => r())),
    new Promise<void>((r) => mcp.listen(0, "127.0.0.1", () => r())),
  ]);
  controlUrl = `http://127.0.0.1:${(control.address() as AddressInfo).port}`;
  endpoint = `http://127.0.0.1:${(mcp.address() as AddressInfo).port}`;
});
afterAll(() => {
  control.close();
  mcp.close();
});

describe("startAttachedSandbox", () => {
  it("exposes the MCP endpoint with /sse and proxies exec/logs", async () => {
    const sb = await startAttachedSandbox({ endpoint, controlUrl, token: "tk" });
    expect(sb.browserEndpoint()).toBe(`${endpoint}/sse`);
    expect(await sb.exec(["node", "-e", "process.stdout.write('ok')"])).toEqual({
      code: 0,
      stdout: "ok",
      stderr: "",
    });
    expect(await sb.logs()).toBe("logs!");
    await sb.dispose();
  });
  it("throws 'timed out' on a control 504", async () => {
    const sb = await startAttachedSandbox({ endpoint, controlUrl, token: "tk" });
    await expect(
      sb.exec(["node", "-e", "setTimeout(()=>{},5000)"], { timeoutMs: 50 }),
    ).rejects.toThrow(/timed out/);
  });
  it("fails fast with a wrong token", async () => {
    await expect(startAttachedSandbox({ endpoint, controlUrl, token: "bad" })).rejects.toThrow(
      /401/,
    );
  });
  it("fails when the MCP endpoint never answers", async () => {
    await expect(
      startAttachedSandbox({
        endpoint: "http://127.0.0.1:1",
        controlUrl,
        token: "tk",
        readyTimeoutMs: 300,
      }),
    ).rejects.toThrow(/not ready/);
  });
});
