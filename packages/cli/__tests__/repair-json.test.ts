import { MockLanguageModelV1 } from "ai/test";
import { describe, expect, it } from "vitest";
import { MultiProviderDetector } from "../src/detectors/multi-provider.js";
import { repairJsonText } from "../src/detectors/repair-json.js";

const OBJECT = '{"relevant": true, "reason": "Express app with raw SQL."}';

function repair(text: string): Promise<string | null> {
  return repairJsonText({ text, error: new Error("parse") as never });
}

describe("repairJsonText", () => {
  it("strips a json code fence", async () => {
    expect(await repair(`\`\`\`json\n${OBJECT}\n\`\`\``)).toBe(OBJECT);
  });

  it("strips a fence with no language tag", async () => {
    expect(await repair(`\`\`\`\n${OBJECT}\n\`\`\``)).toBe(OBJECT);
  });

  it("drops prose around the object", async () => {
    expect(await repair(`Here is the verdict:\n${OBJECT}\nHope that helps.`)).toBe(OBJECT);
  });

  it("keeps a top-level array", async () => {
    expect(await repair('```json\n[{"a": 1}]\n```')).toBe('[{"a": 1}]');
  });

  it("returns null when there is nothing to repair", async () => {
    expect(await repair(OBJECT)).toBeNull();
    expect(await repair("no json here")).toBeNull();
  });
});

describe("structured calls accept a fenced response", () => {
  it("parses a precondition verdict wrapped in a code fence", async () => {
    const model = new MockLanguageModelV1({
      defaultObjectGenerationMode: "json",
      doGenerate: async () => ({
        rawCall: { rawPrompt: null, rawSettings: {} },
        finishReason: "stop",
        usage: { promptTokens: 10, completionTokens: 10 },
        text: `\`\`\`json\n${OBJECT}\n\`\`\``,
      }),
    });
    const detector = new MultiProviderDetector("openrouter", model);
    const check = await detector.checkPrecondition({
      agentName: "Raw SQL Injection",
      agentDescription: "x",
      conditionPrompt: "Run only if this project uses SQL.",
    });
    expect(check.relevant).toBe(true);
  });
});
