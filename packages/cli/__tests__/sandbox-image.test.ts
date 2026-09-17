import { existsSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { type ImageProbes, preflightSandboxImage } from "../src/validation/image.js";

const probes = (over: Partial<ImageProbes> = {}): ImageProbes => ({
  installed: async () => true,
  daemonUp: async () => true,
  present: async () => true,
  build: async () => {},
  ...over,
});

describe("preflightSandboxImage", () => {
  it("passes through when the image is already there", async () => {
    const build = vi.fn(async () => {});
    const r = await preflightSandboxImage("img", probes({ build }));
    expect(r).toEqual({ ok: true, built: false });
    expect(build).not.toHaveBeenCalled();
  });

  it("builds the image when it is absent", async () => {
    const build = vi.fn(async () => {});
    const r = await preflightSandboxImage("img", probes({ present: async () => false, build }));
    expect(r).toEqual({ ok: true, built: true });
    expect(build).toHaveBeenCalledWith("img");
  });

  it("reports that Docker is not installed", async () => {
    const r = await preflightSandboxImage("img", probes({ installed: async () => false }));
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toContain("Docker is not installed");
  });

  it("reports that the daemon is down", async () => {
    const r = await preflightSandboxImage("img", probes({ daemonUp: async () => false }));
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toContain("Docker daemon");
  });

  it("reports a build failure instead of throwing", async () => {
    const r = await preflightSandboxImage(
      "img",
      probes({
        present: async () => false,
        build: async () => {
          throw new Error("`docker build` failed (exit 1): no space left on device");
        },
      }),
    );
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toContain("no space left on device");
  });

  it("never checks for the image when the daemon is down", async () => {
    const present = vi.fn(async () => true);
    await preflightSandboxImage("img", probes({ daemonUp: async () => false, present }));
    expect(present).not.toHaveBeenCalled();
  });
});

describe("bundled sandbox image path resolution", () => {
  it("finds the Dockerfile and banner the way the bundled CLI resolves them", () => {
    const distCli = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
    if (!existsSync(distCli)) return; // fresh checkout, never built: nothing to check

    // Mirrors validationDir() in image.ts: once bundled, every module's
    // import.meta.url collapses to dist/cli.js's own URL, so resolve from there.
    const base = pathToFileURL(distCli);
    const dockerfile = fileURLToPath(new URL("./validation/sandbox.Dockerfile", base));
    const banner = fileURLToPath(new URL("./validation/url-banner.js", base));

    expect(existsSync(dockerfile)).toBe(true);
    expect(existsSync(banner)).toBe(true);
  });
});
