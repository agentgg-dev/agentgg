// Local Docker sandbox that hosts a Playwright MCP server for live validation.
// The image is built from sandbox.Dockerfile, with that file's own directory as
// the build context:
//   docker build -f packages/cli/src/validation/sandbox.Dockerfile -t <DEFAULT_SANDBOX_IMAGE> packages/cli/src/validation
import { execFile, spawn } from "node:child_process";
import { createServer } from "node:net";
import { hostname } from "node:os";
import { promisify } from "node:util";

const pexec = promisify(execFile);

// Pinned image tag; the scan command's default sandbox image for --target-image.
// Keep in sync with the tag in sandbox.Dockerfile's build comment.
export const DEFAULT_SANDBOX_IMAGE = "agentgg/live-sandbox:pw1.56.0-mcp0.0.41-8";

// Label on every sandbox container, valued `<host>:<pid>` of the CLI process
// that started it. A run removes only sandboxes whose owner process is gone (an
// aborted run where dispose never ran), so concurrent live runs on one machine
// leave each other's sandboxes alone.
const OWNER_LABEL = "agentgg.live-sandbox.owner";
// Each sandbox takes the first free port from FIRST_PORT up.
const FIRST_PORT = 8931;
const PORT_RANGE = 100;
const PORT_TAKEN = /port is already allocated|address already in use|bind for .* failed/i;
const READY_TIMEOUT_MS = 30_000;
const DEFAULT_EXEC_TIMEOUT_MS = 120_000;
const EXEC_MAX_BUFFER = 64 * 1024 * 1024;
const READ_MAX_BUFFER = 256 * 1024 * 1024;

export interface Sandbox {
  exec(
    cmd: string[],
    opts?: { timeoutMs?: number },
  ): Promise<{ code: number; stdout: string; stderr: string }>;
  browserEndpoint(): string;
  writeFile(path: string, bytes: Buffer | string): Promise<void>;
  readFile(path: string): Promise<Buffer>;
  logs(): Promise<string>;
  dispose(): Promise<void>;
}

export async function dockerAvailable(): Promise<boolean> {
  try {
    await pexec("docker", ["version", "--format", "{{.Server.Version}}"]);
    return true;
  } catch {
    return false;
  }
}

export async function startLocalDockerSandbox(opts: { image: string }): Promise<Sandbox> {
  const image = opts.image;

  // A run aborted with Ctrl+C leaves its --rm container up (dispose never ran).
  await removeStaleSandboxes();

  let id = "";
  let port = FIRST_PORT - 1;
  while (!id) {
    port = await nextFreePort(port + 1);
    try {
      // --add-host: lets the containerized browser reach a target the host
      // publishes on localhost via http://host.docker.internal.
      const { stdout } = await pexec("docker", [
        "run",
        "-d",
        "--rm",
        "--label",
        `${OWNER_LABEL}=${hostname()}:${process.pid}`,
        "--add-host=host.docker.internal:host-gateway",
        // Same port inside and out: the MCP server checks the Host header
        // against its own port, so a remapped port is rejected.
        "-e",
        `MCP_PORT=${port}`,
        "-p",
        `${port}:${port}`,
        image,
      ]);
      id = stdout.trim();
    } catch (err) {
      const msg = errText(err);
      // Another run can publish the port between the check and this run.
      if (PORT_TAKEN.test(msg)) continue;
      // Do not auto-build: point the caller at the exact build command instead.
      if (
        /no such image|manifest unknown|unable to find image|pull access denied|not found/i.test(
          msg,
        )
      ) {
        throw new Error(
          `Sandbox image "${image}" is not available locally. Build it first:\n` +
            `  docker build -f packages/cli/src/validation/sandbox.Dockerfile -t ${image} packages/cli/src/validation`,
        );
      }
      throw new Error(`Failed to start sandbox container from "${image}": ${msg}`);
    }
  }

  // Readiness probe hits /sse. Any HTTP response (even a 403/400 to a bare probe
  // GET) proves the server is listening; the agent connects over the same port.
  const endpoint = `http://localhost:${port}/sse`;
  try {
    await waitForSse(endpoint, READY_TIMEOUT_MS);
  } catch (err) {
    await forceRemove(id);
    throw new Error(
      `Sandbox MCP server was not ready at ${endpoint} within ${READY_TIMEOUT_MS}ms: ${errText(err)}`,
    );
  }

  return {
    browserEndpoint: () => endpoint,

    async exec(cmd, execOpts) {
      const timeout = execOpts?.timeoutMs ?? DEFAULT_EXEC_TIMEOUT_MS;
      try {
        const { stdout, stderr } = await pexec("docker", ["exec", id, ...cmd], {
          timeout,
          maxBuffer: EXEC_MAX_BUFFER,
        });
        return { code: 0, stdout: String(stdout), stderr: String(stderr) };
      } catch (err) {
        const e = err as NodeJS.ErrnoException & {
          code?: number | string;
          killed?: boolean;
          stdout?: string;
          stderr?: string;
        };
        if (e.killed)
          throw new Error(`sandbox exec timed out after ${timeout}ms: ${cmd.join(" ")}`);
        // execFile rejects on non-zero exit; that is a normal result here.
        if (typeof e.code === "number") {
          return { code: e.code, stdout: String(e.stdout ?? ""), stderr: String(e.stderr ?? "") };
        }
        throw new Error(`sandbox exec failed: ${errText(err)}`);
      }
    },

    // Read/write use `docker exec` with cat rather than `docker cp`, which would
    // require packing/unpacking a tar and a tar binary on the host. Without a TTY
    // the byte stream is untranslated, so binary artifacts (trace.zip, video) round-trip.
    async writeFile(path, bytes) {
      const buf = typeof bytes === "string" ? Buffer.from(bytes, "utf8") : bytes;
      await dockerCatIn(id, path, buf);
    },

    async readFile(path) {
      const { stdout } = await pexec("docker", ["exec", id, "cat", path], {
        encoding: "buffer",
        maxBuffer: READ_MAX_BUFFER,
      });
      return stdout as Buffer;
    },

    async logs() {
      try {
        const { stdout, stderr } = await pexec("docker", ["logs", "--tail", "40", id], {
          maxBuffer: EXEC_MAX_BUFFER,
        });
        return `${String(stdout)}${String(stderr)}`.trim();
      } catch (err) {
        return `(could not read sandbox logs: ${errText(err)})`;
      }
    },

    async dispose() {
      await forceRemove(id);
    },
  };
}

// Stream bytes to a container path via `docker exec -i sh -c 'cat > "$1"'`.
// The path is passed as an argv arg ($1), never interpolated into the shell.
function dockerCatIn(id: string, path: string, buf: Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn("docker", ["exec", "-i", id, "sh", "-c", 'cat > "$1"', "sh", path]);
    let stderr = "";
    child.stderr.on("data", (d) => {
      stderr += d.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`writeFile to ${path} failed (exit ${code}): ${stderr.trim()}`));
    });
    child.stdin.on("error", reject);
    child.stdin.end(buf);
  });
}

async function waitForSse(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown;
  while (Date.now() < deadline) {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), 2_000);
    try {
      await fetch(url, { signal: ac.signal, headers: { accept: "text/event-stream" } });
      ac.abort(); // stop reading the open event stream
      return; // any HTTP response means the server is listening
    } catch (e) {
      lastErr = e;
    } finally {
      clearTimeout(t);
    }
    await delay(300);
  }
  throw lastErr ?? new Error("readiness timeout");
}

async function removeStaleSandboxes(): Promise<void> {
  try {
    const { stdout } = await pexec("docker", [
      "ps",
      "-a",
      "--filter",
      `label=${OWNER_LABEL}`,
      "--format",
      "{{.ID}}|{{.Labels}}",
    ]);
    await Promise.all(staleSandboxIds(String(stdout), hostname(), processAlive).map(forceRemove));
  } catch {
    // Best effort: if docker is unusable we fail later with a clear error.
  }
}

/**
 * Sandboxes in a `docker ps --format "{{.ID}}|{{.Labels}}"` listing whose
 * owner ran on `host` and is no longer alive. A sandbox from another machine
 * sharing the daemon, or with an owner that cannot be read, is left alone.
 */
export function staleSandboxIds(
  listing: string,
  host: string,
  alive: (pid: number) => boolean,
): string[] {
  const stale: string[] = [];
  for (const line of listing.split(/\r?\n/)) {
    const sep = line.indexOf("|");
    if (sep <= 0) continue;
    const id = line.slice(0, sep).trim();
    const owner = new RegExp(`(?:^|,)${OWNER_LABEL.replace(/\./g, "\\.")}=([^,]+)`).exec(
      line.slice(sep + 1),
    )?.[1];
    if (!owner) continue;
    const colon = owner.lastIndexOf(":");
    const pid = Number(owner.slice(colon + 1));
    if (owner.slice(0, colon) !== host || !Number.isInteger(pid) || pid <= 0) continue;
    if (!alive(pid)) stale.push(id);
  }
  return stale;
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM: the process exists but belongs to another user.
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

async function nextFreePort(from: number): Promise<number> {
  const last = FIRST_PORT + PORT_RANGE - 1;
  for (let port = from; port <= last; port++) {
    if (await portFree(port)) return port;
  }
  throw new Error(
    `No free sandbox port between ${FIRST_PORT} and ${last}. Stop a leftover sandbox ` +
      `(docker ps, then docker rm -f <id>) and retry.`,
  );
}

function portFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const server = createServer();
    server.unref();
    server.once("error", () => resolve(false));
    server.listen(port, () => server.close(() => resolve(true)));
  });
}

async function forceRemove(id: string): Promise<void> {
  try {
    await pexec("docker", ["rm", "-f", id]);
  } catch {
    // best effort: the container may already be gone (--rm)
  }
}

// A sandbox something else already started (a Cloud Run sidecar, a CI
// service container). Commands and files go through its control server.
export async function startAttachedSandbox(opts: {
  endpoint: string;
  controlUrl: string;
  token: string;
  readyTimeoutMs?: number;
}): Promise<Sandbox> {
  const endpoint = `${opts.endpoint.replace(/\/+$/, "")}/sse`;
  const control = opts.controlUrl.replace(/\/+$/, "");
  const headers = { Authorization: `Bearer ${opts.token}` };

  // 404 is only ever a legitimate outcome for `GET /file` (a missing file);
  // everywhere else (the readiness handshake, /exec, a write) it means the
  // control server doesn't recognize the route at all — e.g. --sandbox-control
  // pointed at the wrong port — and must fail loudly, not look like success.
  const call = async (
    path: string,
    init: RequestInit & { allow404?: boolean } = {},
  ): Promise<Response> => {
    const { allow404, ...reqInit } = init;
    const res = await fetch(`${control}${path}`, {
      ...reqInit,
      headers: { ...headers, ...reqInit.headers },
    });
    if (res.status === 504) throw new Error("sandbox command timed out");
    if (!res.ok && !(allow404 && res.status === 404))
      throw new Error(`sandbox control ${path} failed: HTTP ${res.status}`);
    return res;
  };

  await call("/logs");
  const deadline = Date.now() + (opts.readyTimeoutMs ?? READY_TIMEOUT_MS);
  for (;;) {
    try {
      await fetch(endpoint, { signal: AbortSignal.timeout(2_000) }).then((r) => r.body?.cancel());
      break;
    } catch {
      if (Date.now() > deadline)
        throw new Error(`attached sandbox MCP endpoint ${endpoint} not ready`);
      await delay(500);
    }
  }

  const file = (path: string) => `/file?path=${encodeURIComponent(path)}`;
  return {
    browserEndpoint: () => endpoint,
    async exec(cmd, execOpts) {
      const res = await call("/exec", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cmd, timeoutMs: execOpts?.timeoutMs ?? DEFAULT_EXEC_TIMEOUT_MS }),
      });
      return (await res.json()) as { code: number; stdout: string; stderr: string };
    },
    async writeFile(path, bytes) {
      const buf = typeof bytes === "string" ? Buffer.from(bytes) : bytes;
      // Buffer satisfies BodyInit at runtime (it's a Uint8Array); the DOM lib's
      // ArrayBufferView type just doesn't line up with @types/node's generic Buffer.
      await call(file(path), { method: "PUT", body: buf as BodyInit });
    },
    async readFile(path) {
      const res = await call(file(path), { allow404: true });
      if (res.status === 404) throw new Error(`sandbox file not found: ${path}`);
      return Buffer.from(await res.arrayBuffer());
    },
    logs: async () => (await call("/logs")).text().catch(() => ""),
    // The owner of the sidecar stops it; only clear this run's output.
    dispose: async () => {},
  };
}

// Build the reproduce-phase `attach` arg from CLI opts, or undefined for the
// default (start-our-own-Docker) mode. Call this next to a command's other
// early flag checks (before any detect/LLM work), not inline in the
// reproduce-phase call, so a missing token or bad URL fails before the run
// spends anything.
export function attachFromOpts(
  opts: { sandboxEndpoint?: string; sandboxControl?: string },
  env: NodeJS.ProcessEnv = process.env,
): { endpoint: string; controlUrl: string; token: string } | undefined {
  if (!opts.sandboxEndpoint) return undefined;
  const token = env.AGENTGG_SANDBOX_TOKEN;
  if (!token) throw new Error("--sandbox-endpoint requires $AGENTGG_SANDBOX_TOKEN");
  const u = new URL(opts.sandboxEndpoint);
  const controlUrl = opts.sandboxControl ?? `${u.protocol}//${u.hostname}:8932`;
  return { endpoint: opts.sandboxEndpoint, controlUrl, token };
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function errText(err: unknown): string {
  const e = err as { stderr?: unknown; message?: unknown };
  const stderr = e?.stderr != null ? String(e.stderr).trim() : "";
  if (stderr) return stderr;
  return e?.message != null ? String(e.message) : String(err);
}
