import { describe, expect, it } from "vitest";
import { renderFindingMd } from "../src/reporters/md";
const f = { id: "x", agentSlug: "a", title: "t", vulnSlug: "xss", filePath: "p",
  summary: "s", details: "d", poc: "p", impact: "i", references: [], confidence: 0.5, notifications: [],
  validation: { verdict: "uncertain", reasoning: "r",
    dynamic: { verdict: "confirmed", reasoning: "reproduced in browser",
      evidence: { trace: "trace.zip", script: { path: "repro.spec.ts", executed: true, passed: true } } } } } as any;
describe("renderFindingMd live validation", () => {
  it("renders the live validation section for a dynamic confirm", () => {
    const md = renderFindingMd(f);
    expect(md).toContain("### Live validation");
    expect(md).toContain("reproduced in browser");
    expect(md).toContain("repro.spec.ts");
  });
});
