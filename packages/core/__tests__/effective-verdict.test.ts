import { describe, expect, it } from "vitest";
import { effectiveVerdict } from "../src/persistence";

const base = {
  id: "x",
  agentSlug: "a",
  title: "t",
  vulnSlug: "xss",
  filePath: "p",
  summary: "s",
  details: "d",
  poc: "p",
  impact: "i",
  references: [],
  confidence: 0.5,
  notifications: [],
} as any;

describe("effectiveVerdict", () => {
  it("dynamic confirm upgrades", () => {
    expect(
      effectiveVerdict({
        ...base,
        validation: {
          verdict: "uncertain",
          reasoning: "r",
          dynamic: { verdict: "confirmed", reasoning: "y" },
        },
      }),
    ).toBe("confirmed");
  });

  it("dynamic not-reproduced does not downgrade a static confirmed", () => {
    expect(
      effectiveVerdict({
        ...base,
        validation: {
          verdict: "confirmed",
          reasoning: "r",
          dynamic: { verdict: "not-reproduced", reasoning: "n" },
        },
      }),
    ).toBe("confirmed");
  });
});
