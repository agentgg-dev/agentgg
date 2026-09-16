import { describe, expect, it } from "vitest";
import { Finding } from "../src/types";
describe("Finding.validation.dynamic", () => {
  it("parses a dynamic confirmed result with evidence", () => {
    const f = Finding.parse({
      id: "x", agentSlug: "a", title: "t", vulnSlug: "xss", filePath: "p",
      summary: "s", details: "d", poc: "p", impact: "i",
      validation: { verdict: "uncertain", reasoning: "r",
        dynamic: { verdict: "confirmed", reasoning: "reproduced",
          evidence: { trace: "trace.zip", script: { path: "repro.spec.ts", executed: true, passed: true } } } },
    });
    expect(f.validation?.dynamic?.verdict).toBe("confirmed");
    expect(f.validation?.dynamic?.evidence?.script?.passed).toBe(true);
  });
});
