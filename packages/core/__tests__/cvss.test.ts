import { describe, expect, it } from "vitest";
import {
  buildCvssScore,
  buildVector,
  type CvssMetrics,
  computeBaseScore,
  parseVector,
  roundUp1,
  severityFromScore,
} from "../src/cvss.js";

/**
 * Canonical vectors cross-checked against the FIRST.org calculator
 * (https://www.first.org/cvss/calculator/3.1). Covers the dimensions
 * the formula branches on: scope changed vs unchanged, full impact
 * vs partial, requires-privileges, requires-UI, network vs local.
 */
const FIXTURES: { vector: string; score: number; label: string }[] = [
  {
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    score: 9.8,
    label: "remote pre-auth full impact, scope unchanged",
  },
  {
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    score: 10.0,
    label: "remote pre-auth full impact, scope changed",
  },
  {
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    score: 7.5,
    label: "remote info disclosure (CVE-2017-5638 shape)",
  },
  {
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    score: 5.3,
    label: "remote low-impact info disclosure",
  },
  {
    vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
    score: 6.5,
    label: "authenticated integrity impact",
  },
  {
    vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N",
    score: 4.4,
    label: "complex scope-changed XSS-style finding",
  },
  {
    vector: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L",
    score: 1.8,
    label: "minimal local availability impact",
  },
  {
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    score: 0.0,
    label: "no impact => zero score",
  },
];

describe("roundUp1", () => {
  it("matches the CVSS 3.1 reference rounding", () => {
    expect(roundUp1(0)).toBe(0);
    expect(roundUp1(4.0)).toBe(4.0);
    expect(roundUp1(4.01)).toBe(4.1);
    expect(roundUp1(4.001)).toBe(4.1);
    expect(roundUp1(9.76)).toBe(9.8);
    expect(roundUp1(10)).toBe(10);
  });
});

describe("computeBaseScore + buildVector", () => {
  for (const fx of FIXTURES) {
    it(`scores "${fx.label}" as ${fx.score}`, () => {
      const metrics = parseVector(fx.vector);
      expect(computeBaseScore(metrics)).toBe(fx.score);
      expect(buildVector(metrics)).toBe(fx.vector);
    });
  }
});

describe("parseVector round-trip", () => {
  it("rejects vectors without the CVSS:3.1 prefix", () => {
    expect(() => parseVector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toThrow();
  });

  it("rejects vectors missing a required metric", () => {
    expect(() => parseVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")).toThrow();
  });

  it("rejects unknown enum values", () => {
    expect(() => parseVector("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toThrow();
  });

  it("round-trips a canonical vector through parse + build", () => {
    const original = "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:H/A:N";
    const metrics = parseVector(original);
    expect(buildVector(metrics)).toBe(original);
  });
});

describe("severityFromScore", () => {
  it("uses the CVSS 3.1 severity buckets", () => {
    expect(severityFromScore(0.0)).toBe("INFO");
    expect(severityFromScore(0.1)).toBe("LOW");
    expect(severityFromScore(3.9)).toBe("LOW");
    expect(severityFromScore(4.0)).toBe("MEDIUM");
    expect(severityFromScore(6.9)).toBe("MEDIUM");
    expect(severityFromScore(7.0)).toBe("HIGH");
    expect(severityFromScore(8.9)).toBe("HIGH");
    expect(severityFromScore(9.0)).toBe("CRITICAL");
    expect(severityFromScore(10.0)).toBe("CRITICAL");
  });
});

describe("buildCvssScore", () => {
  it("assembles a CvssScore for the canonical 9.8 vector", () => {
    const metrics: CvssMetrics = {
      attackVector: "N",
      attackComplexity: "L",
      privilegesRequired: "N",
      userInteraction: "N",
      scope: "U",
      confidentiality: "H",
      integrity: "H",
      availability: "H",
    };
    const score = buildCvssScore({
      metrics,
      justification: "Pre-auth SQLi reachable from the public endpoint.",
    });
    expect(score.baseScore).toBe(9.8);
    expect(score.severity).toBe("CRITICAL");
    expect(score.vector).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(score.metrics).toEqual(metrics);
    expect(score.justification).toContain("Pre-auth");
  });
});
