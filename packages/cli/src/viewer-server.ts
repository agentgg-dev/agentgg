import { type ChildProcess, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { createServer, Socket } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const requireFrom = createRequire(import.meta.url);

/**
 * Default port for the viewer. 3737 is unassigned by IANA and easy to
 * type; if it's taken we walk forward until we find a free one (caller
 * can also pass an explicit port).
 */
export const DEFAULT_VIEWER_PORT = 3737;

export type ViewerLocation =
  /**
   * Self-contained Next.js standalone bundle that the publish script
   * dropped next to this file. `entry` is the spawnable `server.js` —
   * no npm, no resolution, no Next CLI involvement at runtime.
   */
  | { mode: "bundled"; root: string; entry: string }
  /**
   * Monorepo source tree. We resolve and spawn the `next` binary
   * ourselves to support both `next start` (build present) and
   * `next dev` (fresh checkout) without an npm wrapper.
   */
  | { mode: "source"; root: string };

/**
 * Find the viewer Next.js app. Two layouts:
 *
 *   1. **Bundled** — `packages/cli/dist/viewer/packages/viewer/server.js`.
 *      Produced by `scripts/bundle-viewer.mjs` and shipped in the npm
 *      tarball, so `npm install -g agentgg` users get the viewer with
 *      zero extra steps.
 *
 *   2. **Source** — `packages/viewer/` somewhere up the directory tree.
 *      Used when running from a monorepo checkout (`tsx`, `node dist/...`,
 *      `npm link`). Falls through to `next dev` if there's no build.
 *
 * Returns null when neither is present. The CLI turns that into a
 * helpful error instead of half-starting Next.
 */
export function locateViewerPackage(): ViewerLocation | null {
  // 1. Bundled layout sits at `<cli-dist>/viewer/packages/viewer/`.
  //    This file lives at `<cli-dist>/viewer-server.js`.
  const bundledRoot = resolve(__dirname, "viewer", "packages", "viewer");
  const bundledEntry = resolve(bundledRoot, "server.js");
  if (existsSync(bundledEntry)) {
    return { mode: "bundled", root: bundledRoot, entry: bundledEntry };
  }
  // 2. Source layout — walk up looking for `packages/viewer/package.json`.
  let cur = __dirname;
  for (let i = 0; i < 8; i++) {
    const candidate = resolve(cur, "packages", "viewer");
    if (existsSync(resolve(candidate, "package.json"))) {
      return { mode: "source", root: candidate };
    }
    const parent = dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return null;
}

/**
 * Return the first port >= `start` that nothing is listening on. Walks
 * forward up to `attempts` ports before giving up. Used so the viewer
 * survives a previously-orphaned run still holding 3737.
 */
export async function findFreePort(start: number, attempts = 20): Promise<number> {
  for (let p = start; p < start + attempts; p++) {
    if (await isPortFree(p)) return p;
  }
  throw new Error(`Could not find a free port in [${start}, ${start + attempts - 1}]`);
}

function isPortFree(port: number): Promise<boolean> {
  return new Promise((resolveP) => {
    const srv = createServer();
    srv.unref();
    srv.on("error", () => resolveP(false));
    srv.listen(port, "127.0.0.1", () => {
      srv.close(() => resolveP(true));
    });
  });
}

export type ViewerHandle = {
  url: string;
  port: number;
  child: ChildProcess;
  stop: () => Promise<void>;
};

type StartOpts = {
  outputDir: string;
  port?: number;
  /** When true, run `next dev` instead of `next start`. Default false. */
  dev?: boolean;
  /** Forward viewer output to stdout. Default false (quiet). */
  verbose?: boolean;
};

/**
 * Spawn the Next.js viewer as a child process and resolve once it's
 * ready to serve requests. The scan-results directory is passed via
 * `AGENTGG_RESULTS_DIR` — the viewer reads it at request time, so a
 * single server instance can be repointed (in theory) without a
 * restart. We currently spawn one per `view`/`--serve` invocation.
 */
export async function startViewer(opts: StartOpts): Promise<ViewerHandle> {
  const location = locateViewerPackage();
  if (!location) {
    throw new Error(
      "The viewer is unavailable in this install. " +
        "Try reinstalling: `npm install -g agentgg`. " +
        "If you're running from a source checkout, run `npm install` in the agentgg directory.",
    );
  }

  const desired = opts.port ?? DEFAULT_VIEWER_PORT;
  const port = await findFreePort(desired);
  if (opts.port && port !== opts.port) {
    process.stdout.write(`Port ${opts.port} is busy; using ${port} instead.\n`);
  }

  // Common env for both spawn paths. AGENTGG_RESULTS_DIR is what the
  // viewer's API routes and pages read at request time; PORT/HOSTNAME
  // are what Next.js itself looks for.
  const childEnv: NodeJS.ProcessEnv = {
    ...process.env,
    AGENTGG_RESULTS_DIR: resolve(opts.outputDir),
    PORT: String(port),
    HOSTNAME: "127.0.0.1",
    NODE_ENV: opts.dev ? "development" : "production",
    NEXT_TELEMETRY_DISABLED: "1",
  };

  // Bundled standalone path is preferred. It's a single self-contained
  // server.js produced by `next build --output=standalone`, with all
  // production deps already in a sibling `node_modules/`. No npm, no
  // Next CLI, no on-disk source — exactly what an npm-install user
  // gets out of the tarball.
  let child: ChildProcess;
  if (location.mode === "bundled") {
    if (opts.dev) {
      throw new Error(
        "--dev mode requires a source checkout of the viewer. " +
          "The bundled (production) viewer doesn't include the Next.js CLI.",
      );
    }
    child = spawn(process.execPath, [location.entry], {
      // standalone's server.js does process.chdir(__dirname) internally,
      // but setting cwd up front avoids surprises with relative paths
      // that it might log.
      cwd: location.root,
      env: childEnv,
      stdio: opts.verbose ? "inherit" : ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
  } else {
    // Source mode: spawn the `next` binary from the viewer's node_modules.
    // Falls back to `next dev` when there's no `.next/BUILD_ID` so a fresh
    // monorepo checkout works without an extra build step.
    const hasBuild = existsSync(resolve(location.root, ".next", "BUILD_ID"));
    const script = opts.dev ? "dev" : hasBuild ? "start" : "dev";
    if (!opts.dev && !hasBuild) {
      process.stdout.write(
        "No production build found; running viewer in dev mode (first request may take a few seconds).\n",
      );
    }
    let nextBin: string;
    try {
      nextBin = requireFrom.resolve("next/dist/bin/next", {
        paths: [location.root],
      });
    } catch {
      throw new Error(
        "Could not locate the `next` package for the viewer. " +
          "Run `npm install` in the agentgg monorepo to install viewer dependencies.",
      );
    }
    child = spawn(
      process.execPath,
      [nextBin, script, "--port", String(port), "--hostname", "127.0.0.1"],
      {
        cwd: location.root,
        env: childEnv,
        stdio: opts.verbose ? "inherit" : ["ignore", "pipe", "pipe"],
        windowsHide: true,
      },
    );
  }

  const url = `http://127.0.0.1:${port}`;

  // Wait for either the "Ready" line or the port to start accepting
  // connections — whichever happens first. Bail out on early exit.
  await new Promise<void>((resolveP, rejectP) => {
    let done = false;
    const finish = (err?: Error) => {
      if (done) return;
      done = true;
      if (err) rejectP(err);
      else resolveP();
    };

    const exitHandler = (code: number | null) => {
      finish(new Error(`Viewer process exited with code ${code ?? "null"} before it was ready.`));
    };
    child.once("exit", exitHandler);

    if (!opts.verbose && child.stdout && child.stderr) {
      const onChunk = (buf: Buffer) => {
        const s = buf.toString("utf8");
        // Next 13+ logs "Ready in NNNms" (dev) or "Ready" / "Local:" (prod).
        if (/Ready in|started server on|Local:\s+http/i.test(s)) finish();
      };
      child.stdout.on("data", onChunk);
      child.stderr.on("data", onChunk);
    }

    // Belt-and-suspenders poll the port. Useful when stdout was missed
    // (e.g. very fast startup) or with --verbose passed through.
    const started = Date.now();
    const TIMEOUT_MS = 60_000;
    const pollInterval = setInterval(async () => {
      if (await isReachable(port)) {
        clearInterval(pollInterval);
        finish();
        return;
      }
      if (Date.now() - started > TIMEOUT_MS) {
        clearInterval(pollInterval);
        finish(new Error("Viewer did not become ready within 60s."));
      }
    }, 350);

    child.once("error", (err) => finish(err as Error));
  });

  const stop = async () => {
    if (child.killed || child.exitCode !== null) return;
    return new Promise<void>((res) => {
      child.once("exit", () => res());
      // On Unix, SIGINT lets Next print its shutdown line and exit
      // cleanly. On Windows, POSIX signals aren't a thing; `kill()`
      // (default SIGTERM) maps to TerminateProcess, which is the
      // equivalent of pulling the cord — fine for a stateless web
      // server with all state already flushed to disk.
      if (process.platform === "win32") {
        child.kill();
      } else {
        child.kill("SIGINT");
      }
      // Hard stop after 5s if it's still hanging.
      setTimeout(() => {
        if (!child.killed && child.exitCode === null) {
          child.kill(process.platform === "win32" ? undefined : "SIGKILL");
        }
      }, 5_000).unref();
    });
  };

  return { url, port, child, stop };
}

/**
 * Pop the user's default browser to `url`. Best-effort and silent on
 * failure — the URL is printed to stdout regardless, so headless
 * environments (or systems missing `xdg-open`) still get a clickable
 * link. Spawns detached + unref'd so the browser launcher doesn't keep
 * the CLI process alive after the viewer shuts down.
 */
export function openBrowser(url: string): void {
  let cmd: string;
  let args: string[];
  if (process.platform === "darwin") {
    cmd = "open";
    args = [url];
  } else if (process.platform === "win32") {
    // `start` is a cmd builtin. The empty first arg is the window
    // title slot — without it, `start` would treat the URL as the
    // title and prompt for a file to open.
    cmd = "cmd";
    args = ["/c", "start", "", url];
  } else {
    cmd = "xdg-open";
    args = [url];
  }
  try {
    const child = spawn(cmd, args, {
      stdio: "ignore",
      detached: true,
      windowsHide: true,
    });
    child.on("error", () => {
      // swallow — the printed URL is the user's fallback
    });
    child.unref();
  } catch {
    // ditto — never let a browser-launch failure crash the CLI
  }
}

function isReachable(port: number): Promise<boolean> {
  return new Promise((res) => {
    const s = new Socket();
    s.setTimeout(500);
    s.once("connect", () => {
      s.destroy();
      res(true);
    });
    s.once("error", () => res(false));
    s.once("timeout", () => {
      s.destroy();
      res(false);
    });
    s.connect(port, "127.0.0.1");
  });
}
