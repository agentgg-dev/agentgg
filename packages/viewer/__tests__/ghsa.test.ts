import type { CvssScore, Finding } from "@agentgg/core";
import { describe, expect, it } from "vitest";
import { findingToGhsaMarkdown } from "../app/lib/ghsa";

const CVSS: CvssScore = {
  vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  baseScore: 9.8,
  severity: "CRITICAL",
  metrics: {
    attackVector: "N",
    attackComplexity: "L",
    privilegesRequired: "N",
    userInteraction: "N",
    scope: "U",
    confidentiality: "H",
    integrity: "H",
    availability: "H",
  },
  justification: "stub",
};

const finding = (id: string, extra: Partial<Finding> = {}): Finding => ({
  id,
  agentSlug: "a",
  title: `title ${id}`,
  vulnSlug: "xss",
  filePath: "p",
  summary: "s",
  details: "d",
  poc: "p",
  impact: "i",
  references: [],
  confidence: 0.5,
  notifications: [],
  ...extra,
});

describe("findingToGhsaMarkdown", () => {
  it("gives a duplicate its primary's CVSS and keeps its own text", () => {
    const primary = finding("p1", { cvss: CVSS });
    const dupe = finding("d1", { dedup: { duplicateOf: "p1", reasoning: "same" } });
    const out = findingToGhsaMarkdown(dupe, primary);
    expect(out).toContain("# title d1");
    expect(out).toContain("Base score: 9.8");
    expect(out).toContain(CVSS.vector);
  });

  it("omits CVSS when the holder has none", () => {
    const stale = finding("d1", { cvss: CVSS });
    expect(findingToGhsaMarkdown(stale, finding("p1"))).not.toContain("## CVSS");
  });
});
