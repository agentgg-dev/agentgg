import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { repoReader } from "../src/fix-phase.js";
import { linkDir } from "./fs-links.js";

let base: string;
let root: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), "agentgg-repo-reader-"));
  root = join(base, "app");
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src", "a.ts"), "inside", "utf8");
  mkdirSync(join(base, "other"));
  writeFileSync(join(base, "other", "secret.ts"), "outside", "utf8");
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

describe("repoReader", () => {
  it("reads a file inside the root", () => {
    expect(repoReader(root)("src/a.ts")).toBe("inside");
  });

  it("reads no file through a folder link that points outside the root", () => {
    linkDir(join(base, "other"), join(root, "shared"));
    expect(repoReader(root)("shared/secret.ts")).toBeUndefined();
  });

  it("reads no file for a path that climbs out of the root", () => {
    expect(repoReader(root)("../other/secret.ts")).toBeUndefined();
  });

  it("reads no file for an absolute path", () => {
    expect(repoReader(root)(join(root, "src", "a.ts"))).toBeUndefined();
  });
});
