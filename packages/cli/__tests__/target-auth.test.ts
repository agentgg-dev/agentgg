import { describe, expect, it } from "vitest";
import { parseTargetAuth, redact } from "../src/validation/target-auth";
describe("target auth", () => {
  it("parses user:pass and headers", () => {
    const a = parseTargetAuth({ targetCredentials: "alice:password123", targetHeader: ["X-Token: abc"] });
    expect(a.username).toBe("alice"); expect(a.password).toBe("password123");
    expect(a.headers["X-Token"]).toBe("abc");
  });
  it("redacts secrets from text", () => {
    const a = parseTargetAuth({ targetCredentials: "alice:password123", targetHeader: ["X-Token: abc"] });
    expect(redact("logged in with password123 and abc", a)).toBe("logged in with *** and ***");
  });
  it("handles undefined password without throwing", () => {
    const a = parseTargetAuth({ targetHeader: ["X-Token: abc"] });
    expect(a.password).toBeUndefined();
    expect(redact("text with abc in it", a)).toBe("text with *** in it");
  });
  it("redacts multiple header values", () => {
    const a = parseTargetAuth({ targetHeader: ["X-Token: secret1", "Authorization: secret2"] });
    expect(redact("secret1 and secret2", a)).toBe("*** and ***");
  });
  it("redacts longer secrets before shorter substrings", () => {
    const a = parseTargetAuth({ targetCredentials: "user:pass", targetHeader: ["X-Token: passcode123"] });
    expect(redact("secret: pass and token: passcode123", a)).toBe("secret: *** and token: ***");
  });
});
