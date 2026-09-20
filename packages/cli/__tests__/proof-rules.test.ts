import { describe, expect, it } from "vitest";
import { proofRulesFor } from "../src/validation/proof-rules";

const f = (vulnSlug: string, references: string[] = []) =>
  ({ vulnSlug, references, id: "i", agentSlug: "a", filePath: "p" }) as any;

describe("proofRulesFor", () => {
  it("requires a cross-origin request and a negative control for CSRF", () => {
    const rules = proofRulesFor(f("csrf"));
    expect(rules).toContain("different origin");
    expect(rules).toContain("without the victim's session");
  });

  it("matches on the CWE when the slug is free text", () => {
    expect(proofRulesFor(f("forged-request", ["CWE-352"]))).toContain("different origin");
  });

  it("falls back to the generic rules for an unlisted class", () => {
    const rules = proofRulesFor(f("open-redirect-ish"));
    expect(rules).toContain("observed");
    expect(rules).not.toContain("different origin");
  });
});
