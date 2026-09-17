// Docker-gated: proves the preflight talks to real Docker, not the fake
// ImageProbes in sandbox-image.test.ts. Run with `pnpm test:integration`.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { ensureSandboxImage } from "../src/validation/image.js";
import { DEFAULT_SANDBOX_IMAGE, dockerAvailable } from "../src/validation/sandbox.js";

const pexec = promisify(execFile);

// A tag distinct from DEFAULT_SANDBOX_IMAGE and every other pinned tag, so
// removing it never touches an image another test depends on.
const PROBE_IMAGE = "agentgg/live-sandbox:sdd-build-probe";

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

  it("builds a missing image from scratch", async () => {
    if (!(await dockerAvailable())) return;
    await removeTag(PROBE_IMAGE);
    try {
      const result = await ensureSandboxImage(PROBE_IMAGE);
      expect(result).toEqual({ ok: true, built: true });
      expect(await imagePresent(PROBE_IMAGE)).toBe(true);
    } finally {
      await removeTag(PROBE_IMAGE);
    }
    // Layers are cached from the pinned image's build, so this should be
    // fast; the generous timeout only guards against a real cold build.
  }, 180_000);
});
