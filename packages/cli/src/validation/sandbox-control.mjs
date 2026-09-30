// Control server for an attached sandbox: exec, file read/write and logs over
// localhost HTTP, standing in for `docker exec` when the sandbox is a sidecar.
// A custom Authorization header forces a CORS preflight, so pages in the
// sandboxed browser cannot call it.
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname } from "node:path";
import { pathToFileURL } from "node:url";

const MAX_OUTPUT = 64 * 1024 * 1024;

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function send(res, status, body, type = "application/json") {
  res.writeHead(status, { "Content-Type": type });
  res.end(typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}

export function createControlServer({ token, logs = () => "" }) {
  if (!token) throw new Error("SANDBOX_CONTROL_TOKEN is required");
  return createServer(async (req, res) => {
    if (req.headers.authorization !== `Bearer ${token}`)
      return send(res, 401, { error: "unauthorized" });
    const url = new URL(req.url ?? "/", "http://localhost");
    try {
      if (req.method === "POST" && url.pathname === "/exec") {
        const { cmd, timeoutMs = 120_000 } = JSON.parse((await readBody(req)).toString("utf8"));
        if (!Array.isArray(cmd) || cmd.length === 0)
          return send(res, 400, { error: "cmd required" });
        execFile(
          cmd[0],
          cmd.slice(1),
          { timeout: timeoutMs, maxBuffer: MAX_OUTPUT },
          (err, stdout, stderr) => {
            if (err?.killed) return send(res, 504, { error: "timed out" });
            if (err && typeof err.code !== "number")
              return send(res, 500, { error: String(err.message) });
            send(res, 200, {
              code: err ? err.code : 0,
              stdout: String(stdout),
              stderr: String(stderr),
            });
          },
        );
        return;
      }
      const path = url.searchParams.get("path");
      if (url.pathname === "/file" && path) {
        if (req.method === "GET") {
          try {
            return send(res, 200, await readFile(path), "application/octet-stream");
          } catch (e) {
            if (e?.code === "ENOENT") return send(res, 404, { error: "not found" });
            throw e;
          }
        }
        if (req.method === "PUT") {
          await mkdir(dirname(path), { recursive: true });
          await writeFile(path, await readBody(req));
          res.writeHead(204).end();
          return;
        }
      }
      if (req.method === "GET" && url.pathname === "/logs")
        return send(res, 200, logs(), "text/plain");
      send(res, 404, { error: "no route" });
    } catch (e) {
      send(res, 500, { error: e instanceof Error ? e.message : String(e) });
    }
  });
}

// Entry: node sandbox-control.mjs <mcp-log-file>
if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const logFile = process.argv[2];
  const tail = () => {
    try {
      return readFileSync(logFile, "utf8").split("\n").slice(-40).join("\n");
    } catch {
      return "";
    }
  };
  createControlServer({ token: process.env.SANDBOX_CONTROL_TOKEN, logs: tail }).listen(
    8932,
    "127.0.0.1",
  );
}
