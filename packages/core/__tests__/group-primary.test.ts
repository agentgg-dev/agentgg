import { describe, expect, it } from "vitest";
import { Finding, groupPrimary } from "../src/index.js";

const f = (id: string, extra: object = {}) =>
  Finding.parse({
    id,
    agentSlug: "a",
    title: "t",
    vulnSlug: "sql-injection",
    filePath: "p.ts",
    summary: "s",
    details: "d",
    poc: "p",
    impact: "i",
    ...extra,
  });

describe("groupPrimary", () => {
  it("returns the primary of a duplicate", () => {
    const p = f("p1");
    const d = f("d1", { dedup: { duplicateOf: "p1", reasoning: "same" } });
    const byId = new Map([p, d].map((x) => [x.id, x]));
    expect(groupPrimary(d, byId)).toBe(p);
  });

  it("returns the finding itself when it is a primary", () => {
    const p = f("p1");
    expect(groupPrimary(p, new Map([[p.id, p]]))).toBe(p);
  });

  it("returns the finding itself when its primary is missing", () => {
    const d = f("d1", { dedup: { duplicateOf: "gone", reasoning: "same" } });
    expect(groupPrimary(d, new Map([[d.id, d]]))).toBe(d);
  });

  it("parses the impact fields on validation", () => {
    const p = f("p1", {
      validation: {
        verdict: "confirmed",
        reasoning: "r",
        confirmedImpact: "Reads any user's notes.",
        unconfirmedImpact: "Full database dump.",
      },
    });
    expect(p.validation?.confirmedImpact).toBe("Reads any user's notes.");
    expect(p.validation?.unconfirmedImpact).toBe("Full database dump.");
  });
});
