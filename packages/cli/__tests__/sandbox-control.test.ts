import { mkdtempSync, readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
// @ts-expect-error plain ESM module shipped into the image
import { createControlServer } from "../src/validation/sandbox-control.mjs";

const token = "t0ken";
let base = "";
let server: import("node:http").Server;

beforeAll(async () => {
  server = createControlServer({ token, logs: () => "mcp log line" });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => server.close());

const auth = { Authorization: `Bearer ${token}` };

describe("sandbox control server", () => {
  it("rejects a request without the token", async () => {
    const res = await fetch(`${base}/logs`);
    expect(res.status).toBe(401);
  });
  it("runs a command", async () => {
    const res = await fetch(`${base}/exec`, {
      method: "POST",
      headers: { ...auth, "Content-Type": "application/json" },
      body: JSON.stringify({ cmd: ["node", "-e", "process.stdout.write('hi'); process.exit(3)"] }),
    });
    expect(await res.json()).toEqual({ code: 3, stdout: "hi", stderr: "" });
  });
  it("writes and reads a file", async () => {
    const p = join(mkdtempSync(join(tmpdir(), "ctl-")), "a.bin");
    const put = await fetch(`${base}/file?path=${encodeURIComponent(p)}`, {
      method: "PUT",
      headers: auth,
      body: Buffer.from([0, 1, 2]),
    });
    expect(put.status).toBe(204);
    expect([...readFileSync(p)]).toEqual([0, 1, 2]);
    const get = await fetch(`${base}/file?path=${encodeURIComponent(p)}`, { headers: auth });
    expect([...new Uint8Array(await get.arrayBuffer())]).toEqual([0, 1, 2]);
  });
  it("returns 404 for a missing file", async () => {
    const res = await fetch(`${base}/file?path=%2Fno%2Fsuch`, { headers: auth });
    expect(res.status).toBe(404);
  });
  it("returns 504 on a command timeout", async () => {
    const res = await fetch(`${base}/exec`, {
      method: "POST",
      headers: { ...auth, "Content-Type": "application/json" },
      body: JSON.stringify({ cmd: ["node", "-e", "setTimeout(()=>{},5000)"], timeoutMs: 100 }),
    });
    expect(res.status).toBe(504);
  });
});
