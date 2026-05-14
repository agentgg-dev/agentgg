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
 *
 * The constructor accepts `effort` and `thinking` knobs that map to
 * provider-native options where the provider supports them:
 *
 * - Anthropic (via Vercel SDK): `thinking` maps to
 *   `providerOptions.anthropic.thinking` (`enabled`/`disabled`).
 *   `adaptive` is treated as `enabled` — the Vercel SDK Anthropic
 *   provider doesn't expose an adaptive mode. `effort` has no
 *   equivalent here.
 * - OpenAI (via Vercel SDK): `effort` maps to
 *   `providerOptions.openai.reasoningEffort` (`low`/`medium`/`high`).
 *   `max` is treated as `high` — OpenAI's reasoning effort tops out
 *   at `high`. `thinking` has no equivalent.
 * - Ollama: neither maps to anything generally available. Both are
 *   honest no-ops.
 */

export type Effort = "low" | "medium" | "high" | "max";
export type Thinking = "off" | "adaptive" | "enabled";

export interface MultiProviderDetectorOpts {
  /** Provider key for `providerOptions`. Derived from constructor `name` if omitted. */
  providerKey?: "anthropic" | "openai" | "ollama";
  effort?: Effort;
  thinking?: Thinking;
}

/**
 * Shape of the `providerOptions` argument we pass to `generateObject`.
 * Each provider key's inner object matches what that provider's
 * package consumes — `anthropic` keys to `@ai-sdk/anthropic`'s
 * provider options schema, `openai` to `@ai-sdk/openai`'s.
 */
type ProviderOptionsArg = {
  anthropic?: {
    thinking?: { type: "enabled" | "disabled"; budgetTokens?: number };
  };
  openai?: {
    reasoningEffort?: "low" | "medium" | "high";
  };
};

export class MultiProviderDetector implements Detector {
  readonly name: string;
  private readonly model: LanguageModelV1;
  private readonly providerKey?: "anthropic" | "openai" | "ollama";
  private readonly effort?: Effort;
  private readonly thinking?: Thinking;

  constructor(name: string, model: LanguageModelV1, opts: MultiProviderDetectorOpts = {}) {
    this.name = name;
    this.model = model;
    // `name` is the human-readable label ("anthropic-api", "openai", "ollama").
    // The `providerOptions` key in the Vercel SDK is the provider package
    // identifier — usually equal to the name's prefix. Derive when not given.
    this.providerKey = opts.providerKey ?? derivedProviderKey(name);
    this.effort = opts.effort;
    this.thinking = opts.thinking;
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
        providerOptions: this.providerOptionsArg(),
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
        providerOptions: this.providerOptionsArg(),
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

  /**
   * Build the `providerOptions` argument for a `generateObject` call,
   * mapping agentgg's `effort` / `thinking` knobs to the Vercel SDK
   * shape the underlying provider expects. Returns `undefined` when
   * there's nothing to pass — `generateObject` accepts `undefined`
   * here as "no provider options."
   */
  private providerOptionsArg(): ProviderOptionsArg | undefined {
    if (!this.providerKey) return undefined;

    if (this.providerKey === "anthropic") {
      // Vercel SDK's @ai-sdk/anthropic exposes `thinking` only —
      // `{ type: 'enabled' | 'disabled', budgetTokens?: number }`.
      // agentgg's "adaptive" maps to "enabled" (closest available);
      // `effort` has no analog and is a no-op here.
      if (!this.thinking) return undefined;
      const type: "enabled" | "disabled" = this.thinking === "off" ? "disabled" : "enabled";
      return { anthropic: { thinking: { type } } };
    }

    if (this.providerKey === "openai") {
      // OpenAI reasoning models expose `reasoningEffort: low|medium|high`.
      // agentgg's "max" maps to "high"; `thinking` has no analog.
      if (!this.effort) return undefined;
      const reasoningEffort: "low" | "medium" | "high" =
        this.effort === "max" ? "high" : this.effort;
      return { openai: { reasoningEffort } };
    }

    // Ollama: no general provider options for thinking/effort. No-op.
    return undefined;
  }
}

function derivedProviderKey(name: string): "anthropic" | "openai" | "ollama" | undefined {
  if (name.startsWith("anthropic")) return "anthropic";
  if (name.startsWith("openai")) return "openai";
  if (name.startsWith("ollama")) return "ollama";
  return undefined;
}
