// Local Docker sandbox that hosts a Playwright MCP server for live validation.
// The image is built from sandbox.Dockerfile:
//   docker build -f packages/cli/src/validation/sandbox.Dockerfile -t <DEFAULT_SANDBOX_IMAGE> .
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";

const pexec = promisify(execFile);

// Pinned image tag; the scan command's default sandbox image for --target-image.
// Keep in sync with the tag in sandbox.Dockerfile's build comment.
export const DEFAULT_SANDBOX_IMAGE = "agentgg/live-sandbox:pw1.56.0-mcp0.0.41";

// Container port the Playwright MCP server binds; published to a random host port.
const MCP_PORT = "8931";
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

  let id: string;
  try {
    // --add-host: lets the containerized browser reach a target the host
    // publishes on localhost via http://host.docker.internal.
    const { stdout } = await pexec("docker", [
      "run",
      "-d",
      "--rm",
      "--add-host=host.docker.internal:host-gateway",
      "-p",
      `0:${MCP_PORT}`,
      image,
    ]);
    id = stdout.trim();
  } catch (err) {
    const msg = errText(err);
    // Do not auto-build: point the caller at the exact build command instead.
    if (
      /no such image|manifest unknown|unable to find image|pull access denied|not found/i.test(msg)
    ) {
      throw new Error(
        `Sandbox image "${image}" is not available locally. Build it first:\n` +
          `  docker build -f packages/cli/src/validation/sandbox.Dockerfile -t ${image} .`,
      );
    }
    throw new Error(`Failed to start sandbox container from "${image}": ${msg}`);
  }

  let hostPort: string;
  try {
    const { stdout } = await pexec("docker", ["port", id, MCP_PORT]);
    hostPort = parseHostPort(stdout);
  } catch (err) {
    await forceRemove(id);
    throw new Error(
      `Could not read the published MCP port for sandbox ${short(id)}: ${errText(err)}`,
    );
  }

  // /sse (legacy SSE) answers a plain GET with 200; /mcp (streamable HTTP) is
  // also served on this port but rejects a bare GET, so /sse is the readiness probe.
  const endpoint = `http://localhost:${hostPort}/sse`;
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
      const res = await fetch(url, { signal: ac.signal, headers: { accept: "text/event-stream" } });
      ac.abort(); // stop reading the open event stream
      if (res.status >= 200 && res.status < 300) return;
      lastErr = new Error(`status ${res.status}`);
    } catch (e) {
      lastErr = e;
    } finally {
      clearTimeout(t);
    }
    await delay(300);
  }
  throw lastErr ?? new Error("readiness timeout");
}

function parseHostPort(portOutput: string): string {
  // `docker port <id> 8931` prints one line per binding, e.g. "0.0.0.0:49153" and "[::]:49153".
  const line = portOutput
    .split(/\r?\n/)
    .map((s) => s.trim())
    .find(Boolean);
  const port = line?.split(":").pop() ?? "";
  if (!/^\d+$/.test(port))
    throw new Error(`could not parse host port from: ${JSON.stringify(portOutput)}`);
  return port;
}

async function forceRemove(id: string): Promise<void> {
  try {
    await pexec("docker", ["rm", "-f", id]);
  } catch {
    // best effort: the container may already be gone (--rm)
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function short(id: string): string {
  return id.slice(0, 12);
}

function errText(err: unknown): string {
  const e = err as { stderr?: unknown; message?: unknown };
  const stderr = e?.stderr != null ? String(e.stderr).trim() : "";
  if (stderr) return stderr;
  return e?.message != null ? String(e.message) : String(err);
}
