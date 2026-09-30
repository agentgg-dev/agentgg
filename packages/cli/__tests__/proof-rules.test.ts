import { describe, expect, it } from "vitest";
import { PROOF_PRINCIPLE, proofRuleMap, proofRules } from "../src/validation/proof-rules";

describe("proofRules", () => {
  it("states the principle when the reporting agent declares no rule", () => {
    expect(proofRules()).toContain(PROOF_PRINCIPLE);
  });

  it("appends the agent's own rule after the principle", () => {
    const rule = "The request MUST come from a different origin than the target.";
    const out = proofRules(rule);
    expect(out).toContain(rule);
    expect(out.indexOf(PROOF_PRINCIPLE)).toBeLessThan(out.indexOf(rule));
  });

  it("keeps the principle when an agent declares a rule, so a rule can only add", () => {
    expect(proofRules("Anything goes.")).toContain(PROOF_PRINCIPLE);
  });

  it("ignores an agent rule that is only whitespace", () => {
    expect(proofRules("   \n  ")).toBe(proofRules());
  });

  it("tells the agent to return inconclusive when it cannot isolate the effect", () => {
    expect(proofRules()).toContain("inconclusive");
  });
});

describe("proofRuleMap", () => {
  const agent = (slug, liveProofRule) => ({ slug, liveProofRule }) as any;

  it("keys each declared rule by the agent slug that owns it", () => {
    const map = proofRuleMap([agent("csrf", "Cross origin only."), agent("xss", undefined)]);
    expect(map.get("csrf")).toBe("Cross origin only.");
  });

  it("leaves out an agent that declares no rule, so it falls to the principle", () => {
    const map = proofRuleMap([agent("xss", undefined)]);
    expect(map.has("xss")).toBe(false);
  });
});
