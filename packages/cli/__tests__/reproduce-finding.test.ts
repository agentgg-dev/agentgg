import { describe, expect, it } from "vitest";
import { ClaudeAgentDetector } from "../src/detectors/claude-agent.js";

describe("reproduceFinding", () => {
  it("is present on the claude-agent detector", () => {
    const d = new ClaudeAgentDetector({ apiKey: "test", model: "claude-opus-4-8" });
    expect(typeof d.reproduceFinding).toBe("function");
  });
});
