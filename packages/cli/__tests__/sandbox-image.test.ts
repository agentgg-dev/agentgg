import { existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { type ImageProbes, preflightSandboxImage, validationDir } from "../src/validation/image.js";

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

describe("validationDir", () => {
  function withTempDir(fn: (dir: string) => void): void {
    const dir = mkdtempSync(join(tmpdir(), "agentgg-validation-dir-"));
    try {
      fn(dir);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  it("returns the validation/ subdirectory when one exists (bundled layout)", () => {
    withTempDir((dir) => {
      mkdirSync(join(dir, "validation"));
      const base = pathToFileURL(join(dir, "cli.js")).toString();
      expect(validationDir(base)).toBe(join(dir, "validation") + sep);
    });
  });

  it("falls back to its own directory when there is no validation/ (source layout)", () => {
    withTempDir((dir) => {
      const base = pathToFileURL(join(dir, "image.ts")).toString();
      expect(validationDir(base)).toBe(dir + sep);
    });
  });
});

describe("bundled sandbox image path resolution", () => {
  it("finds the Dockerfile and banner the way the bundled CLI resolves them", () => {
    const distDir = fileURLToPath(new URL("../dist/", import.meta.url));
    // dist/agents/ is copied only by bundle-cli.mjs; tsc (the plain `pnpm build`)
    // never creates it, so its presence proves the bundle step actually ran.
    if (!existsSync(join(distDir, "agents"))) return;

    const base = pathToFileURL(join(distDir, "cli.js")).toString();
    const dir = validationDir(base);

    expect(existsSync(join(dir, "sandbox.Dockerfile"))).toBe(true);
    expect(existsSync(join(dir, "url-banner.js"))).toBe(true);
  });
});
