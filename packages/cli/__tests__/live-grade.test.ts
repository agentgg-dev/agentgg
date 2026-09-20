import { describe, expect, it } from "vitest";
import { gradeLiveResult } from "../src/validation/reproduce";

describe("gradeLiveResult", () => {
  it("keeps reproduced when the trace carries a request", () => {
    expect(
      gradeLiveResult("reproduced", {
        screenshots: [],
        requests: [{ method: "GET", url: "u", status: 200 }],
      }),
    ).toBe("reproduced");
  });

  it("downgrades reproduced with no captured request", () => {
    expect(gradeLiveResult("reproduced", { screenshots: [] })).toBe("inconclusive");
  });

  it("downgrades reproduced with no evidence at all", () => {
    expect(gradeLiveResult("reproduced", undefined)).toBe("inconclusive");
  });

  it("leaves refuted alone", () => {
    expect(gradeLiveResult("refuted", undefined)).toBe("refuted");
  });
});
