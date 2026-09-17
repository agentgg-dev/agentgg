import { describe, expect, it } from "vitest";
import { parseTargetAuth, redact } from "../src/validation/target-auth";

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
