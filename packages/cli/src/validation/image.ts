// Preflight for the live-validation sandbox image: check Docker, then build the
// image locally when it is absent. Never pulls: the image is not published, so a
// pull would fail with a confusing registry error.
import { execFile, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const pexec = promisify(execFile);

export interface ImageProbes {
  installed(): Promise<boolean>;
  daemonUp(): Promise<boolean>;
  present(image: string): Promise<boolean>;
  build(image: string): Promise<void>;
}

export type PreflightResult = { ok: true; built: boolean } | { ok: false; reason: string };

/**
 * Check, in order: Docker installed, daemon up, image present, and build it if
 * not. Every failure returns a reason rather than throwing, so the caller keeps
 * the static verdicts and lets the scan finish.
 */
export async function preflightSandboxImage(
  image: string,
  probes: ImageProbes,
): Promise<PreflightResult> {
  if (!(await probes.installed())) {
    return {
      ok: false,
      reason:
        "Docker is not installed, so the live-validation sandbox cannot start. Install Docker Desktop or the Docker engine, then retry.",
    };
  }
  if (!(await probes.daemonUp())) {
    return { ok: false, reason: "The Docker daemon is not responding. Start Docker and retry." };
  }
  if (await probes.present(image)) return { ok: true, built: false };
  try {
    await probes.build(image);
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : String(err) };
  }
  return { ok: true, built: true };
}

export async function ensureSandboxImage(image: string): Promise<PreflightResult> {
  return preflightSandboxImage(image, {
    installed: () => ok(pexec("docker", ["--version"])),
    daemonUp: () => ok(pexec("docker", ["version", "--format", "{{.Server.Version}}"])),
    present: (img) => ok(pexec("docker", ["image", "inspect", img])),
    build: buildSandboxImage,
  });
}

async function ok(p: Promise<unknown>): Promise<boolean> {
  try {
    await p;
    return true;
  } catch {
    return false;
  }
}

// esbuild flattens every module's import.meta.url to the bundled entry's URL,
// so a path relative to *this* file's own location is only correct unbundled
// (tsx). Try the bundled layout (dist/validation, next to dist/cli.js) first,
// then fall back to this file's own directory for dev/tsx.
function validationDir(): string {
  const bundled = fileURLToPath(new URL("./validation/", import.meta.url));
  return existsSync(bundled) ? bundled : fileURLToPath(new URL("./", import.meta.url));
}

/**
 * Run `docker build` with the Dockerfile's own directory as the context (it
 * COPYs url-banner.js from there), streaming every line so a multi-minute build
 * is never a silent wait.
 */
function buildSandboxImage(image: string): Promise<void> {
  const context = validationDir();
  const dockerfile = join(context, "sandbox.Dockerfile");
  console.log(`  live validation: building the sandbox image ${image}`);
  console.log("  first run only. This may take a few minutes.");
  return new Promise((resolve, reject) => {
    const child = spawn("docker", ["build", "-f", dockerfile, "-t", image, context]);
    const tail: string[] = [];
    const onLine = (chunk: Buffer) => {
      for (const line of chunk.toString().split(/\r?\n/)) {
        if (!line.trim()) continue;
        console.log(`    ${line}`);
        tail.push(line);
        if (tail.length > 20) tail.shift();
      }
    };
    child.stdout.on("data", onLine);
    child.stderr.on("data", onLine);
    child.on("error", (err) => reject(new Error(`could not run \`docker build\`: ${err.message}`)));
    child.on("close", (code) => {
      if (code === 0) {
        console.log(`  live validation: built ${image}`);
        resolve();
        return;
      }
      reject(new Error(`\`docker build\` failed (exit ${code}):\n${tail.join("\n")}`));
    });
  });
}
