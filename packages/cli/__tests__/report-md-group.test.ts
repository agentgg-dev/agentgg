import type { Finding } from "@agentgg/core";
import { describe, expect, it } from "vitest";
import { renderFindingMd } from "../src/reporters/md.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "abc123",
    agentSlug: "sql-injection",
    title: "SQLi in login handler",
    vulnSlug: "sql-injection",
    filePath: "src/login.ts",
    lineRange: [12, 14],
    summary: "Login handler concatenates request body into SQL, allowing arbitrary DB access.",
    details:
      "Line 12 builds the query via string concatenation:\n```\ndb.query('SELECT * FROM users WHERE id=' + id)\n```",
    poc: "curl -X GET '/users/1%20OR%201%3D1'",
    impact: "Any unauthenticated request can read or modify the users table.",
    references: ["CWE-89"],
    confidence: 0.9,
    notifications: [],
    ...overrides,
  };
}

/** Renders a single finding with no group context, same as an ungrouped call. */
function renderOne(f: Finding): string {
  return renderFindingMd(f);
}

/**
 * Renders every finding in the group, including duplicates (normally
 * collapsed out of `writeMarkdownReport`'s output), with a `byId` map built
 * from the whole group so a duplicate resolves its primary.
 */
function renderWithDuplicatesShown(findings: Finding[]): string {
  const byId = new Map(findings.map((f) => [f.id, f] as const));
  return findings.map((f) => renderFindingMd(f, undefined, undefined, byId)).join("\n\n---\n\n");
}

describe("renderFindingMd confirmed impact and group verdict", () => {
  it("shows the confirmed impact above the agent's impact, and the unconfirmed claim", () => {
    const md = renderOne(
      makeFinding({
        impact: "Full database dump.",
        validation: {
          verdict: "confirmed",
          reasoning: "r",
          confirmedImpact: "Reads any user's notes.",
          unconfirmedImpact: "Full database dump.",
        },
      }),
    );
    expect(md).toContain("**Confirmed impact:** Reads any user's notes.");
    expect(md).toContain("**Claimed, not confirmed:** Full database dump.");
    expect(md.indexOf("**Confirmed impact:**")).toBeLessThan(md.indexOf("### Summary"));
  });

  it("gives a rendered duplicate its primary's verdict", () => {
    const p = makeFinding({ id: "p1", validation: { verdict: "confirmed", reasoning: "r" } });
    const d = makeFinding({ id: "d1", dedup: { duplicateOf: "p1", reasoning: "same" } });
    const md = renderWithDuplicatesShown([p, d]);
    const dupSection = md.slice(md.indexOf("**Duplicate of:** `p1`"));
    expect(dupSection).toContain("**Validation:** `confirmed` (from `p1`)");
  });
});
