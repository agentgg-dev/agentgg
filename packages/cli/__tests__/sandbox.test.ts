import { describe, expect, it } from "vitest";
import { dockerAvailable } from "../src/validation/sandbox";

describe("sandbox", () => {
  it("exposes a docker availability probe", async () => {
    expect(typeof (await dockerAvailable())).toBe("boolean");
  });
});
