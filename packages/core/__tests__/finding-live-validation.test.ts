import { describe, expect, it } from "vitest";
import { Finding } from "../src/types";

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
};

describe("Finding.live", () => {
  it("parses a reproduced result with evidence", () => {
    const f = Finding.parse({
      ...base,
      validation: { verdict: "uncertain", reasoning: "r" },
      live: {
        result: "reproduced",
        reasoning: "reproduced",
        counterevidence: "none found",
        evidence: {
          trace: "trace.zip",
          script: { path: "repro.spec.ts", executed: true, passed: true },
        },
      },
    });
    expect(f.live?.result).toBe("reproduced");
    expect(f.live?.evidence?.script?.passed).toBe(true);
  });

  it("rejects an unknown live result", () => {
    expect(() =>
      Finding.parse({
        ...base,
        live: { result: "confirmed", reasoning: "r", counterevidence: "c" },
      }),
    ).toThrow();
  });
});
