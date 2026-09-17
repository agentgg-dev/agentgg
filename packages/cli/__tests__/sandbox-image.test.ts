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
