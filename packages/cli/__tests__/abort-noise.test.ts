import { describe, expect, it } from "vitest";
import { isAbortNoise } from "../src/validation/reproduce";

describe("isAbortNoise", () => {
  it("matches an undici body timeout from an aborted stream", () => {
    const err = new TypeError("terminated");
    (err as { cause?: unknown }).cause = { code: "UND_ERR_BODY_TIMEOUT" };
    expect(isAbortNoise(err)).toBe(true);
  });

  it("matches a bare AbortError", () => {
    const err = new Error("The operation was aborted");
    err.name = "AbortError";
    expect(isAbortNoise(err)).toBe(true);
  });

  it("matches a terminated fetch by message", () => {
    expect(isAbortNoise(new TypeError("terminated"))).toBe(true);
  });

  it("does not match an ordinary error, so real bugs still crash", () => {
    expect(isAbortNoise(new Error("Cannot read property 'x' of undefined"))).toBe(false);
  });

  it("does not match a non-error value", () => {
    expect(isAbortNoise("some string")).toBe(false);
    expect(isAbortNoise(undefined)).toBe(false);
  });
});
