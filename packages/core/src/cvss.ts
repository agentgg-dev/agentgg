import type { CvssScore, Severity } from "./types.js";

/**
 * CVSS 3.1 base-score math. Pure functions — no LLM, no I/O.
 *
 * The scoring agent picks the 8 base metric values; this module computes
 * the canonical vector string, the numeric base score, and the severity
 * bucket. Keeping the math in Node (rather than asking the model to do
 * it) avoids the well-known failure mode of small models miscalculating
 * the formula while still picking reasonable metrics.
 *
 * Reference: https://www.first.org/cvss/v3.1/specification-document
 */

export type AttackVector = "N" | "A" | "L" | "P";
export type AttackComplexity = "L" | "H";
export type PrivilegesRequired = "N" | "L" | "H";
export type UserInteraction = "N" | "R";
export type Scope = "U" | "C";
export type Impact = "H" | "L" | "N";

export interface CvssMetrics {
  attackVector: AttackVector;
  attackComplexity: AttackComplexity;
  privilegesRequired: PrivilegesRequired;
  userInteraction: UserInteraction;
  scope: Scope;
  confidentiality: Impact;
  integrity: Impact;
  availability: Impact;
}

const AV_WEIGHTS: Record<AttackVector, number> = {
  N: 0.85,
  A: 0.62,
  L: 0.55,
  P: 0.2,
};

const AC_WEIGHTS: Record<AttackComplexity, number> = {
  L: 0.77,
  H: 0.44,
};

// Privileges Required has different weights depending on Scope.
const PR_WEIGHTS_UNCHANGED: Record<PrivilegesRequired, number> = {
  N: 0.85,
  L: 0.62,
  H: 0.27,
};

const PR_WEIGHTS_CHANGED: Record<PrivilegesRequired, number> = {
  N: 0.85,
  L: 0.68,
  H: 0.5,
};

const UI_WEIGHTS: Record<UserInteraction, number> = {
  N: 0.85,
  R: 0.62,
};

const IMPACT_WEIGHTS: Record<Impact, number> = {
  H: 0.56,
  L: 0.22,
  N: 0.0,
};

/**
 * CVSS 3.1 spec's `roundUp1` — round to one decimal, biased upward.
 * Behaviour matches the JS reference at
 * https://www.first.org/cvss/v3.1/specification-document#Appendix-A---Floating-Point-Rounding
 */
export function roundUp1(value: number): number {
  const intInput = Math.round(value * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/**
 * Compute the CVSS 3.1 base score (0.0–10.0) from the 8 metrics.
 */
export function computeBaseScore(metrics: CvssMetrics): number {
  const av = AV_WEIGHTS[metrics.attackVector];
  const ac = AC_WEIGHTS[metrics.attackComplexity];
  const pr =
    metrics.scope === "U"
      ? PR_WEIGHTS_UNCHANGED[metrics.privilegesRequired]
      : PR_WEIGHTS_CHANGED[metrics.privilegesRequired];
  const ui = UI_WEIGHTS[metrics.userInteraction];

  const c = IMPACT_WEIGHTS[metrics.confidentiality];
  const i = IMPACT_WEIGHTS[metrics.integrity];
  const a = IMPACT_WEIGHTS[metrics.availability];

  const iscBase = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact =
    metrics.scope === "U"
      ? 6.42 * iscBase
      : 7.52 * (iscBase - 0.029) - 3.25 * (iscBase - 0.02) ** 15;

  const exploitability = 8.22 * av * ac * pr * ui;

  if (impact <= 0) return 0;

  const raw =
    metrics.scope === "U"
      ? Math.min(impact + exploitability, 10)
      : Math.min(1.08 * (impact + exploitability), 10);
  return roundUp1(raw);
}

/**
 * Build the canonical CVSS 3.1 vector string for a set of metrics.
 */
export function buildVector(metrics: CvssMetrics): string {
  return [
    "CVSS:3.1",
    `AV:${metrics.attackVector}`,
    `AC:${metrics.attackComplexity}`,
    `PR:${metrics.privilegesRequired}`,
    `UI:${metrics.userInteraction}`,
    `S:${metrics.scope}`,
    `C:${metrics.confidentiality}`,
    `I:${metrics.integrity}`,
    `A:${metrics.availability}`,
  ].join("/");
}

/**
 * Parse a CVSS 3.1 vector string back into structured metrics. Throws
 * on malformed input; the prefix `CVSS:3.1` is required, every base
 * metric must be present, and unknown enum values are rejected. Used
 * mainly in tests for round-trip assertions.
 */
export function parseVector(vector: string): CvssMetrics {
  const parts = vector.split("/");
  if (parts.length < 9 || parts[0] !== "CVSS:3.1") {
    throw new Error(`Not a CVSS:3.1 vector: ${vector}`);
  }
  const map = new Map<string, string>();
  for (const part of parts.slice(1)) {
    const idx = part.indexOf(":");
    if (idx === -1) throw new Error(`Malformed CVSS metric: ${part}`);
    map.set(part.slice(0, idx), part.slice(idx + 1));
  }
  const required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
  for (const key of required) {
    if (!map.has(key)) throw new Error(`Missing CVSS metric ${key} in ${vector}`);
  }
  return {
    attackVector: requireEnum(map.get("AV"), ["N", "A", "L", "P"]) as AttackVector,
    attackComplexity: requireEnum(map.get("AC"), ["L", "H"]) as AttackComplexity,
    privilegesRequired: requireEnum(map.get("PR"), ["N", "L", "H"]) as PrivilegesRequired,
    userInteraction: requireEnum(map.get("UI"), ["N", "R"]) as UserInteraction,
    scope: requireEnum(map.get("S"), ["U", "C"]) as Scope,
    confidentiality: requireEnum(map.get("C"), ["H", "L", "N"]) as Impact,
    integrity: requireEnum(map.get("I"), ["H", "L", "N"]) as Impact,
    availability: requireEnum(map.get("A"), ["H", "L", "N"]) as Impact,
  };
}

function requireEnum<T extends string>(value: string | undefined, allowed: T[]): T {
  if (value === undefined || !allowed.includes(value as T)) {
    throw new Error(`CVSS metric value "${value}" not in ${allowed.join("|")}`);
  }
  return value as T;
}

/**
 * Map a CVSS 3.1 base score onto agentgg's severity bucket. A score of
 * 0.0 maps to INFO (CVSS calls it "None"); above that the standard
 * Low/Medium/High/Critical thresholds apply.
 */
export function severityFromScore(score: number): Severity {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score >= 0.1) return "LOW";
  return "INFO";
}

/**
 * Assemble a full `CvssScore` (vector + score + bucket + metrics) from
 * the metrics the scoring agent picked. The justification is passed
 * through unchanged.
 */
export function buildCvssScore(args: { metrics: CvssMetrics; justification: string }): CvssScore {
  const baseScore = computeBaseScore(args.metrics);
  return {
    vector: buildVector(args.metrics),
    baseScore,
    severity: severityFromScore(baseScore),
    metrics: args.metrics,
    justification: args.justification,
  };
}
