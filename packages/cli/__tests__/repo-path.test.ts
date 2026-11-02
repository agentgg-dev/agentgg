import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { namesOutsideRoot, readRepoFileSync, resolveInsideRoot } from "../src/repo-path.js";
import { linkDir, tryLinkFile } from "./fs-links.js";

let base: string;
let root: string;
let secret: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), "agentgg-repo-path-"));
  root = join(base, "app");
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src", "a.ts"), "inside", "utf8");
  mkdirSync(join(base, "app2"));
  secret = join(base, "app2", "secret.txt");
  writeFileSync(secret, "outside", "utf8");
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

describe("resolveInsideRoot", () => {
  it("returns the real path of a file inside the root", () => {
    expect(resolveInsideRoot(root, "src/a.ts")).toBe(
      realpathSync.native(join(root, "src", "a.ts")),
    );
  });

  it("rejects an absolute path outside the root", () => {
    expect(resolveInsideRoot(root, secret)).toBeUndefined();
  });

  it("rejects a relative path that climbs out of the root", () => {
    expect(resolveInsideRoot(root, relative(root, secret))).toBeUndefined();
  });

  it("rejects a folder next to the root whose name starts with the root's name", () => {
    expect(resolveInsideRoot(root, join(base, "app2", "secret.txt"))).toBeUndefined();
  });

  it("rejects a path through a folder link that points outside the root", () => {
    linkDir(join(base, "app2"), join(root, "shared"));
    expect(resolveInsideRoot(root, "shared/secret.txt")).toBeUndefined();
  });

  it("rejects a file link that points outside the root", (ctx) => {
    if (!tryLinkFile(secret, join(root, "notes.txt"))) ctx.skip();
    expect(resolveInsideRoot(root, "notes.txt")).toBeUndefined();
  });

  it("accepts a file inside a root that is itself a link", () => {
    linkDir(root, join(base, "root-link"));
    expect(resolveInsideRoot(join(base, "root-link"), "src/a.ts")).toBe(
      realpathSync.native(join(root, "src", "a.ts")),
    );
  });

  it("is undefined for a file that does not exist", () => {
    expect(resolveInsideRoot(root, "src/missing.ts")).toBeUndefined();
  });
});

describe("namesOutsideRoot", () => {
  it("is false for no path", () => {
    expect(namesOutsideRoot(root, undefined)).toBe(false);
    expect(namesOutsideRoot(root, "  ")).toBe(false);
  });

  it("is false for a file inside the root", () => {
    expect(namesOutsideRoot(root, "src/a.ts")).toBe(false);
  });

  it("is false for a missing path inside the root", () => {
    expect(namesOutsideRoot(root, "src/missing.ts")).toBe(false);
  });

  it("is true for an existing file outside the root", () => {
    expect(namesOutsideRoot(root, secret)).toBe(true);
  });

  it("is true for a missing path that climbs out of the root", () => {
    expect(namesOutsideRoot(root, "../elsewhere/missing.ts")).toBe(true);
  });

  it("is true for a path through a link that points outside the root", () => {
    linkDir(join(base, "app2"), join(root, "shared"));
    expect(namesOutsideRoot(root, "shared/secret.txt")).toBe(true);
  });
});

describe("readRepoFileSync", () => {
  it("reads a file inside the root", () => {
    expect(readRepoFileSync(root, "src/a.ts")).toBe("inside");
  });

  it("throws for a file outside the root", () => {
    expect(() => readRepoFileSync(root, secret)).toThrow();
  });
});
