import type { Agent, Finding } from "@agentgg/core";
import { type LanguageModelV1, generateObject } from "ai";
import {
  DetectionResult,
  type Detector,
  type HuntArgs,
  type InvestigateArgs,
  buildDetectPrompt,
  hydrateFinding,
} from "../detect.js";
import { LlmValidation, asValidationField, buildValidatePrompt } from "../validator.js";

/**
 * Multi-provider detector. Backed by the Vercel AI SDK's `generateObject`
 * — works against any provider for which we have a `LanguageModelV1`:
 *
 * - Anthropic (API key, file mode)
 * - OpenAI / Codex (file mode)
 * - Ollama (file mode)
 *
 * Strict structured output is enforced at the schema level — the model
 * is forced to produce a `DetectionResult` object that we then hydrate
 * into full `Finding`s.
 *
 * **Hunt mode is not supported through this detector.** Tool-call
 * orchestration with structured output is finicky across providers, so
 * the resolver routes hunt-mode invocations through `ClaudeAgentDetector`
 * (which uses the Claude Agent SDK regardless of credential type).
 */

export class MultiProviderDetector implements Detector {
  readonly name: string;
  private readonly model: LanguageModelV1;

  constructor(name: string, model: LanguageModelV1) {
    this.name = name;
    this.model = model;
  }

  async detectFile(args: {
    agent: Agent;
    filePath: string;
    content: string;
  }): Promise<Finding[]> {
    const { agent, filePath, content } = args;
    try {
      const { object } = await generateObject({
        model: this.model,
        schema: DetectionResult,
        mode: "json",
        prompt: buildDetectPrompt(agent, filePath, content),
      });
      return object.findings.map((f) => hydrateFinding(f, agent, filePath));
    } catch (err) {
      if (process.env.AGENTGG_DEBUG) {
        const util = await import("node:util");
        console.error("---- MultiProviderDetector raw error ----");
        console.error(util.inspect(err, { depth: 5, colors: false }));
        console.error("-----------------------------------------");
      }
      throw err;
    }
  }

  async hunt(_args: HuntArgs): Promise<Finding[]> {
    throw new Error(
      `Hunt mode is not supported by the MultiProviderDetector (provider: ${this.name}). ` +
        "Hunt-mode agents are routed through the Claude Agent SDK. " +
        "Use `--provider anthropic` (API key or OAuth) for hunt agents, " +
        "or change the agent's mode to 'file'.",
    );
  }

  async investigate(_args: InvestigateArgs): Promise<Finding[]> {
    throw new Error(
      `Walker mode is not supported by the MultiProviderDetector (provider: ${this.name}). ` +
        "Walker-mode per-file investigation needs tool access; route through " +
        "the Claude Agent SDK by using `--provider anthropic` (API key or OAuth), " +
        "or change the agent's mode to 'file'.",
    );
  }

  async validateFinding(args: { finding: Finding; fileContent: string; scope?: string }) {
    try {
      const { object } = await generateObject({
        model: this.model,
        schema: LlmValidation,
        mode: "json",
        prompt: buildValidatePrompt(args),
      });
      return asValidationField(object);
    } catch (err) {
      if (process.env.AGENTGG_DEBUG) {
        const util = await import("node:util");
        console.error("---- MultiProviderDetector validate error ----");
        console.error(util.inspect(err, { depth: 5, colors: false }));
        console.error("----------------------------------------------");
      }
      throw err;
    }
  }
}
