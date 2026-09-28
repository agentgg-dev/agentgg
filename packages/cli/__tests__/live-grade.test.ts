import { describe, expect, it } from "vitest";
import { gradeLiveResult } from "../src/validation/reproduce";

const withRequest = {
  screenshots: [],
  requests: [{ method: "GET", url: "u", status: 200 }],
};
const control = "Same request without the session returned 401.";

describe("gradeLiveResult", () => {
  it("keeps reproduced when a request was captured and a control was run", () => {
    expect(gradeLiveResult("reproduced", withRequest, control)).toBe("reproduced");
  });

  it("downgrades reproduced with no captured request", () => {
    expect(gradeLiveResult("reproduced", { screenshots: [] }, control)).toBe("inconclusive");
  });

  it("downgrades reproduced with no evidence at all", () => {
    expect(gradeLiveResult("reproduced", undefined, control)).toBe("inconclusive");
  });

  it("downgrades reproduced when no negative control was reported", () => {
    expect(gradeLiveResult("reproduced", withRequest, undefined)).toBe("inconclusive");
  });

  it("downgrades reproduced when the negative control is only whitespace", () => {
    expect(gradeLiveResult("reproduced", withRequest, "  \n ")).toBe("inconclusive");
  });

  it("leaves refuted alone, control or not", () => {
    expect(gradeLiveResult("refuted", undefined, undefined)).toBe("refuted");
  });
});
