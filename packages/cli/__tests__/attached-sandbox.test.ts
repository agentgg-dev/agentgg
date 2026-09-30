import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startAttachedSandbox } from "../src/validation/sandbox";
// @ts-expect-error plain ESM module
import { createControlServer } from "../src/validation/sandbox-control.mjs";

let control: Server;
let mcp: Server;
// Answers every route with 404, never checks auth — stands in for a control
// server pointed at the wrong port (e.g. --sandbox-control given the MCP
// port) or a route that plain doesn't exist there.
let notFound: Server;
let controlUrl = "";
let endpoint = "";
let notFoundUrl = "";

beforeAll(async () => {
  control = createControlServer({ token: "tk", logs: () => "logs!" });
  mcp = createServer((_req, res) => res.writeHead(200).end());
  notFound = createServer((_req, res) => res.writeHead(404).end());
  await Promise.all([
    new Promise<void>((r) => control.listen(0, "127.0.0.1", () => r())),
    new Promise<void>((r) => mcp.listen(0, "127.0.0.1", () => r())),
    new Promise<void>((r) => notFound.listen(0, "127.0.0.1", () => r())),
  ]);
  controlUrl = `http://127.0.0.1:${(control.address() as AddressInfo).port}`;
  endpoint = `http://127.0.0.1:${(mcp.address() as AddressInfo).port}`;
  notFoundUrl = `http://127.0.0.1:${(notFound.address() as AddressInfo).port}`;
});
afterAll(() => {
  control.close();
  mcp.close();
  notFound.close();
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
  it("rejects the handshake against a server that 404s every route", async () => {
    // Not the missing-file case: this is the wrong server entirely (e.g.
    // --sandbox-control pointed at the MCP port). 404 must not be silently
    // treated as a successful handshake.
    await expect(
      startAttachedSandbox({ endpoint, controlUrl: notFoundUrl, token: "tk" }),
    ).rejects.toThrow(/404/);
  });
  it("still throws 'not found' for readFile of a missing file", async () => {
    const sb = await startAttachedSandbox({ endpoint, controlUrl, token: "tk" });
    await expect(sb.readFile("/no/such/file")).rejects.toThrow(/not found/);
  });
});
