import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { readTargetContext } from "../src/validation/target-context";

describe("readTargetContext", () => {
  it("returns plain text unchanged", () => {
    expect(readTargetContext("login at /signin")).toBe("login at /signin");
  });
  it("reads @file contents", () => {
    const dir = mkdtempSync(join(tmpdir(), "ctx-"));
    const p = join(dir, "ctx.md");
    writeFileSync(p, "use account alice\n");
    expect(readTargetContext(`@${p}`)).toBe("use account alice\n");
  });
  it("throws a clear error for a missing file", () => {
    expect(() => readTargetContext("@/no/such/file")).toThrow(/--target-context file/);
  });
  it("passes undefined through", () => {
    expect(readTargetContext(undefined)).toBeUndefined();
  });
});
