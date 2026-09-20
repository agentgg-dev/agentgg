import { describe, expect, it } from "vitest";
import { buildReproducePrompt } from "../src/detect";

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
    const prompt = buildReproducePrompt(finding, "http://t", undefined, undefined, {
      verdict: "uncertain",
      reasoning: "POST /notes never checks the cookie and hardcodes owner=alice.",
    });
    expect(prompt).toContain("never checks the cookie");
    expect(prompt).toContain("uncertain");
    expect(prompt).toContain("different origin");
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
});
