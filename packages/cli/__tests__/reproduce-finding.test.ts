import { openai } from "@ai-sdk/openai";
import { describe, expect, it } from "vitest";
import { ClaudeAgentDetector } from "../src/detectors/claude-agent.js";
import { asReproduceField, VercelAgentDetector } from "../src/detectors/vercel-agent.js";

describe("reproduceFinding", () => {
  it("is present on the claude-agent detector", () => {
    const d = new ClaudeAgentDetector({ apiKey: "test", model: "claude-opus-4-8" });
    expect(typeof d.reproduceFinding).toBe("function");
  });

  it("is present on the vercel detector, so non-anthropic providers can live-validate", () => {
    const d = new VercelAgentDetector("openrouter", openai("gpt-4o-mini"));
    expect(typeof d.reproduceFinding).toBe("function");
  });
});

describe("asReproduceField", () => {
  it("keeps the script on a confirmation", () => {
    expect(asReproduceField({ verdict: "confirmed", reasoning: "r", script: "s" })).toEqual({
      verdict: "confirmed",
      reasoning: "r",
      script: "s",
    });
  });

  it("drops the script when the finding did not reproduce", () => {
    expect(asReproduceField({ verdict: "not-reproduced", reasoning: "r", script: "s" })).toEqual({
      verdict: "not-reproduced",
      reasoning: "r",
    });
  });

  it("omits the script key entirely when the model returned none", () => {
    expect(asReproduceField({ verdict: "confirmed", reasoning: "r" })).toEqual({
      verdict: "confirmed",
      reasoning: "r",
    });
  });
});
