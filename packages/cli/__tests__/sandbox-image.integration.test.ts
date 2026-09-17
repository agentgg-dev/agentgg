// Docker-gated: proves the preflight talks to real Docker, not the fake
// ImageProbes in sandbox-image.test.ts. Run with `pnpm test:integration`.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { buildSandboxImage, ensureSandboxImage } from "../src/validation/image.js";
import { DEFAULT_SANDBOX_IMAGE, dockerAvailable } from "../src/validation/sandbox.js";

const pexec = promisify(execFile);

// A tag distinct from DEFAULT_SANDBOX_IMAGE and every other pinned tag, so
// this test never builds or removes anything real docker has to clean up.
const CUSTOM_IMAGE = "agentgg/live-sandbox:sdd-custom-probe";
// Distinct from CUSTOM_IMAGE too: this one really is built and removed below.
const BUILD_PROBE_IMAGE = "agentgg/live-sandbox:sdd-build-probe";

async function imagePresent(image: string): Promise<boolean> {
  try {
    await pexec("docker", ["image", "inspect", image]);
    return true;
  } catch {
    return false;
  }
}

async function removeTag(image: string): Promise<void> {
  try {
    await pexec("docker", ["rmi", image]);
  } catch {
    // Already absent, or the tag shares layers with another tag; either way
    // there is nothing to clean up.
  }
}

describe("sandbox image preflight (real docker)", () => {
  it("recognizes the already-built default image", async () => {
    if (!(await dockerAvailable())) return;
    const result = await ensureSandboxImage(DEFAULT_SANDBOX_IMAGE);
    expect(result).toEqual({ ok: true, built: false });
  }, 60_000);

  it("refuses to build a missing custom --target-image", async () => {
    if (!(await dockerAvailable())) return;
    expect(await imagePresent(CUSTOM_IMAGE)).toBe(false);
    const result = await ensureSandboxImage(CUSTOM_IMAGE);
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toContain(CUSTOM_IMAGE);
    expect(await imagePresent(CUSTOM_IMAGE)).toBe(false);
  }, 60_000);
});

describe("buildSandboxImage (real docker)", () => {
  it("builds an image from scratch", async () => {
    if (!(await dockerAvailable())) return;
    await removeTag(BUILD_PROBE_IMAGE);
    try {
      expect(await imagePresent(BUILD_PROBE_IMAGE)).toBe(false);
      await buildSandboxImage(BUILD_PROBE_IMAGE);
      expect(await imagePresent(BUILD_PROBE_IMAGE)).toBe(true);
    } finally {
      await removeTag(BUILD_PROBE_IMAGE);
    }
    // Layers are cached from the pinned image's own build, so this should be
    // fast; the generous timeout only guards against a real cold build.
  }, 180_000);
});
