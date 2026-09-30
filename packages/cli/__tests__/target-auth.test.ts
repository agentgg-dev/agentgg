import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  credentialVariants,
  parseTargetAuth,
  readTargetContext,
  redact,
  redactBytes,
} from "../src/validation/target-auth";

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

describe("credential redaction", () => {
  const auth = { username: "alice", password: "p@ss word&1" };
  it("covers raw, percent-encoded, form-encoded and basic-auth forms", () => {
    const v = credentialVariants(auth);
    expect(v).toContain("p@ss word&1");
    expect(v).toContain(encodeURIComponent("p@ss word&1"));
    expect(v).toContain("p%40ss+word%261");
    expect(v).toContain(Buffer.from("alice:p@ss word&1").toString("base64"));
  });
  it("redacts a JSON-escaped password", () => {
    const body = JSON.stringify({ password: 'a"b\\c' });
    expect(redact(body, { password: 'a"b\\c' })).not.toContain('a\\"b\\\\c');
  });
  it("redacts every variant in bytes", () => {
    const text = `password=p%40ss+word%261&x=1\nAuthorization: Basic ${Buffer.from("alice:p@ss word&1").toString("base64")}`;
    const out = redactBytes(Buffer.from(text), auth).toString("utf8");
    expect(out).not.toContain("p%40ss");
    expect(out).not.toContain(Buffer.from("alice:p@ss word&1").toString("base64"));
    expect(out).toContain("***");
  });
  it("leaves bytes alone when there is no password", () => {
    const b = Buffer.from("nothing");
    expect(redactBytes(b, {})).toBe(b);
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
