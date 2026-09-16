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
});
