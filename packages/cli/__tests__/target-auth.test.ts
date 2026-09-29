import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseTargetAuth, readTargetContext, redact } from "../src/validation/target-auth";

describe("target auth", () => {
  it("parses user:pass", () => {
    const a = parseTargetAuth({ targetCredentials: "alice:password123" });
    expect(a.username).toBe("alice");
    expect(a.password).toBe("password123");
  });
  it("redacts secrets from text", () => {
    const a = parseTargetAuth({ targetCredentials: "alice:password123" });
    expect(redact("logged in with password123", a)).toBe("logged in with ***");
  });
  it("handles undefined password without throwing", () => {
    const a = parseTargetAuth({});
    expect(a.password).toBeUndefined();
    expect(redact("text with nothing to redact", a)).toBe("text with nothing to redact");
  });
});

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
