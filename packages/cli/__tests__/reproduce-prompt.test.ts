import { describe, expect, it } from "vitest";
import { buildReproducePrompt } from "../src/detect";
import { PROOF_PRINCIPLE } from "../src/validation/proof-rules";

const finding = {
  id: "f1",
  agentSlug: "csrf",
  vulnSlug: "csrf",
  title: "No CSRF token on POST /notes",
  filePath: "app.js",
  lineRange: [10, 20],
  summary: "s",
  poc: "p",
  impact: "i",
  references: ["CWE-352"],
} as any;

describe("buildReproducePrompt", () => {
  it("carries the static review and demands an answer to it", () => {
    const prompt = buildReproducePrompt(finding, "http://t", undefined, {
      verdict: "uncertain",
      reasoning: "POST /notes never checks the cookie and hardcodes owner=alice.",
    });
    expect(prompt).toContain("never checks the cookie");
    expect(prompt).toContain("uncertain");
    expect(prompt).toContain("answers the source review");
  });

  it("omits the static section when no review ran", () => {
    const prompt = buildReproducePrompt(finding, "http://t");
    expect(prompt).not.toContain("Source review");
  });

  it("does not ask the 'reproduced' criterion to answer a review that isn't there", () => {
    const prompt = buildReproducePrompt(finding, "http://t");
    expect(prompt).not.toContain("answers the source review");
  });

  it("states the principle when the reporting agent declares no rule", () => {
    const prompt = buildReproducePrompt(finding, "http://t");
    expect(prompt).toContain(PROOF_PRINCIPLE);
    expect(prompt).not.toContain("different origin");
  });

  it("carries the reporting agent own proof rule when the catalog declares one", () => {
    const rule = "The request MUST come from a different origin than the target.";
    const prompt = buildReproducePrompt(finding, "http://t", undefined, undefined, rule);
    expect(prompt).toContain(rule);
    expect(prompt).toContain(PROOF_PRINCIPLE);
  });

  it("asks the agent to report the control it ran", () => {
    expect(buildReproducePrompt(finding, "http://t")).toContain("negativeControl");
  });

  it("asks the agent to reproduce the confirmed impact", () => {
    const out = buildReproducePrompt(finding, "http://localhost:3000", undefined, {
      verdict: "confirmed",
      reasoning: "r",
      confirmedImpact: "Reads any user's notes.",
    });
    expect(out).toContain("The impact to reproduce is the one the review confirmed");
    expect(out).toContain("Reads any user's notes.");
  });

  it("tells the reproduce agent to prove XSS with an alert the recording can show", () => {
    const out = buildReproducePrompt(finding, "http://t");
    expect(out).toContain("alert(document.domain)");
  });

  it("offers the sentinel as a dialog-free alternative the banner also captures", () => {
    expect(buildReproducePrompt(finding, "http://t")).toContain("window.__agentggXss");
  });
});
