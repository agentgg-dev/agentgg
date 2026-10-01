import type { Finding } from "@agentgg/core";
import { describe, expect, it } from "vitest";
import { renderFindingMd } from "../src/reporters/md.js";

const FIX = "Bind `id` as a query parameter instead of concatenating it.";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "abc123",
    agentSlug: "sql-injection",
    title: "SQLi in login handler",
    vulnSlug: "sql-injection",
    filePath: "src/login.ts",
    lineRange: [12, 14],
    summary: "Login handler concatenates request body into SQL.",
    details: "Line 12 builds the query via string concatenation.",
    poc: "curl -X GET '/users/1%20OR%201%3D1'",
    impact: "Any unauthenticated request can read the users table.",
    references: ["CWE-89"],
    confidence: 0.9,
    notifications: [],
    suggestedFix: FIX,
    ...overrides,
  };
}

describe("renderFindingMd suggested fix", () => {
  it("shows the fix of a confirmed finding between the impact and the references", () => {
    const md = renderFindingMd(
      makeFinding({ validation: { verdict: "confirmed", reasoning: "r" } }),
    );
    expect(md).toContain(`### Suggested fix\n${FIX}`);
    expect(md.indexOf("### Impact")).toBeLessThan(md.indexOf("### Suggested fix"));
    expect(md.indexOf("### Suggested fix")).toBeLessThan(md.indexOf("### References"));
  });

  it.each([
    "uncertain",
    "false-positive",
    "out-of-scope",
  ] as const)("has no fix section for a %s finding", (verdict) => {
    const md = renderFindingMd(makeFinding({ validation: { verdict, reasoning: "r" } }));
    expect(md).not.toContain("Suggested fix");
    expect(md).not.toContain(FIX);
  });

  it("has no fix section for a finding that was never validated", () => {
    expect(renderFindingMd(makeFinding())).not.toContain("Suggested fix");
  });

  it("has no fix section when a live run refuted a confirmed finding", () => {
    const md = renderFindingMd(
      makeFinding({
        validation: { verdict: "confirmed", reasoning: "r" },
        live: { result: "refuted", reasoning: "r", counterevidence: "" },
      }),
    );
    expect(md).not.toContain("Suggested fix");
  });

  it("has no fix section for a confirmed finding with no fix", () => {
    const md = renderFindingMd(
      makeFinding({
        suggestedFix: undefined,
        validation: { verdict: "confirmed", reasoning: "r" },
      }),
    );
    expect(md).not.toContain("Suggested fix");
  });

  it("gives a rendered duplicate its primary's fix", () => {
    const p = makeFinding({ id: "p1", validation: { verdict: "confirmed", reasoning: "r" } });
    const d = makeFinding({
      id: "d1",
      suggestedFix: undefined,
      dedup: { duplicateOf: "p1", reasoning: "same" },
    });
    const byId = new Map([p, d].map((g) => [g.id, g] as const));
    expect(renderFindingMd(d, undefined, undefined, byId)).toContain(`### Suggested fix\n${FIX}`);
  });
});
