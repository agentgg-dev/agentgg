import type { CvssScore, Finding } from "@agentgg/core";
import { generateObject, type LanguageModelV1 } from "ai";
import { AgentSpec } from "../agent-spec.js";
import { buildDedupePrompt, LlmDedup } from "../deduper.js";
import {
  buildAgentPrompt,
  buildCreateAgentPrompt,
  buildPreconditionPrompt,
  buildReconPrompt,
  type CreateAgentArgs,
  DetectionResult,
  type Detector,
  hydrateFinding,
  PreconditionCheck,
  type PreconditionCheckArgs,
  type ReconArgs,
  ReconResult,
  type RunAgentArgs,
} from "../detect.js";
import { asCvssScore, buildScorePrompt, LlmScore } from "../scoring.js";
import type { UsageMeter } from "../usage-meter.js";
import {
  asValidationField,
  buildScopeValidatePrompt,
  buildValidatePrompt,
  LlmValidation,
} from "../validator.js";
import { extractCallUsage } from "./vercel-agent.js";

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
 * Each provider key's inner object matches what the Vercel AI SDK
 * adapter for that provider consumes.
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
  private meter?: UsageMeter;

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

  attachUsageMeter(meter: UsageMeter): void {
    this.meter = meter;
  }

  /**
   * Run one `generateObject` call, then record its token usage into the
   * attached meter (a no-op when no meter is attached). Every call funnels
   * through here so usage capture lives in one place.
   */
  private async metered<R>(run: () => Promise<R>): Promise<R> {
    const result = await run();
    this.meter?.record(extractCallUsage(result), this.model.modelId);
    return result;
  }

  async recon(args: ReconArgs & { signal?: AbortSignal }): Promise<ReconResult> {
    // Best-effort: this detector has no tools, so the model can't browse
    // the repo. It produces a brief from the fingerprint tags + its own
    // priors. The resolver routes tool-capable providers to a detector
    // that can actually read files; this is the degraded fallback.
    try {
      const { object } = await this.metered(() =>
        generateObject({
          model: this.model,
          schema: ReconResult,
          mode: "json",
          prompt: buildReconPrompt({
            instructions: args.instructions,
            fingerprintTags: args.fingerprintTags,
            excludePatterns: args.excludePatterns,
            includePatterns: args.includePatterns,
            maxFileSizeKb: args.maxFileSizeKb,
          }),
          providerOptions: this.providerOptionsArg(),
          abortSignal: args.signal,
        }),
      );
      return object;
    } catch (err) {
      if (process.env.AGENTGG_DEBUG) {
        const util = await import("node:util");
        console.error("---- MultiProviderDetector recon error ----");
        console.error(util.inspect(err, { depth: 5, colors: false }));
        console.error("-------------------------------------------");
      }
      throw err;
    }
  }

  async createAgent(args: CreateAgentArgs & { signal?: AbortSignal }): Promise<AgentSpec> {
    // Best-effort: no tools, so the model can't browse the repo. It derives
    // the spec from the report content alone. Tool-capable providers are
    // routed to a detector that can actually read files.
    try {
      const { object } = await this.metered(() =>
        generateObject({
          model: this.model,
          schema: AgentSpec,
          mode: "json",
          prompt: buildCreateAgentPrompt({
            instructions: args.instructions,
            reportName: args.reportName,
            reportContent: args.reportContent,
            excludePatterns: args.excludePatterns,
            includePatterns: args.includePatterns,
            maxFileSizeKb: args.maxFileSizeKb,
          }),
          providerOptions: this.providerOptionsArg(),
          abortSignal: args.signal,
        }),
      );
      return object;
    } catch (err) {
      if (process.env.AGENTGG_DEBUG) {
        const util = await import("node:util");
        console.error("---- MultiProviderDetector createAgent error ----");
        console.error(util.inspect(err, { depth: 5, colors: false }));
        console.error("-------------------------------------------------");
      }
      throw err;
    }
  }

  async runAgent(args: RunAgentArgs & { signal?: AbortSignal }): Promise<Finding[]> {
    // Best-effort, no tools: the model can't browse the repo, so it works
    // from the seeded candidate file contents embedded in the prompt.
    // Roam-mode agents (no candidates) will find little here — tool-capable
    // providers are routed to a detector that can actually read files.
    try {
      const { object } = await this.metered(() =>
        generateObject({
          model: this.model,
          schema: DetectionResult,
          mode: "json",
          prompt: buildAgentPrompt(args),
          providerOptions: this.providerOptionsArg(),
          abortSignal: args.signal,
        }),
      );
      const fallback = args.candidates[0]?.filePath ?? "(unknown)";
      return object.findings.map((f) => hydrateFinding(f, args.agent, f.filePath ?? fallback));
    } catch (err) {
      if (process.env.AGENTGG_DEBUG) {
        const util = await import("node:util");
        console.error("---- MultiProviderDetector runAgent error ----");
        console.error(util.inspect(err, { depth: 5, colors: false }));
        console.error("----------------------------------------------");
      }
      throw err;
    }
  }

  async checkPrecondition(
    args: PreconditionCheckArgs & { signal?: AbortSignal },
  ): Promise<PreconditionCheck> {
    try {
      const { object } = await this.metered(() =>
        generateObject({
          model: this.model,
          schema: PreconditionCheck,
          mode: "json",
          prompt: buildPreconditionPrompt(args),
          providerOptions: this.providerOptionsArg(),
          abortSignal: args.signal,
        }),
      );
      return object;
    } catch (err) {
      if (process.env.AGENTGG_DEBUG) {
        const util = await import("node:util");
        console.error("---- MultiProviderDetector checkPrecondition error ----");
        console.error(util.inspect(err, { depth: 5, colors: false }));
        console.error("-------------------------------------------------------");
      }
      throw err;
    }
  }

  async validateFinding(args: {
    finding: Finding;
    fileContent: string;
    scope?: string;
    signal?: AbortSignal;
  }) {
    try {
      const { object } = await this.metered(() =>
        generateObject({
          model: this.model,
          schema: LlmValidation,
          mode: "json",
          prompt: buildValidatePrompt(args),
          providerOptions: this.providerOptionsArg(),
          abortSignal: args.signal,
        }),
      );
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

  async validateFindingByScope(args: { finding: Finding; scope: string; signal?: AbortSignal }) {
    try {
      const { object } = await this.metered(() =>
        generateObject({
          model: this.model,
          schema: LlmValidation,
          mode: "json",
          prompt: buildScopeValidatePrompt(args),
          providerOptions: this.providerOptionsArg(),
          abortSignal: args.signal,
        }),
      );
      return asValidationField(object);
    } catch (err) {
      if (process.env.AGENTGG_DEBUG) {
        const util = await import("node:util");
        console.error("---- MultiProviderDetector scope-validate error ----");
        console.error(util.inspect(err, { depth: 5, colors: false }));
        console.error("-----------------------------------------------------");
      }
      throw err;
    }
  }

  async scoreFinding(args: {
    finding: Finding;
    fileContent: string;
    signal?: AbortSignal;
  }): Promise<CvssScore> {
    try {
      const { object } = await this.metered(() =>
        generateObject({
          model: this.model,
          schema: LlmScore,
          mode: "json",
          prompt: buildScorePrompt(args),
          providerOptions: this.providerOptionsArg(),
          abortSignal: args.signal,
        }),
      );
      return asCvssScore(object);
    } catch (err) {
      if (process.env.AGENTGG_DEBUG) {
        const util = await import("node:util");
        console.error("---- MultiProviderDetector score error ----");
        console.error(util.inspect(err, { depth: 5, colors: false }));
        console.error("-------------------------------------------");
      }
      throw err;
    }
  }

  async dedupeFindings(args: {
    filePath: string;
    findings: Finding[];
    fileContent?: string;
    signal?: AbortSignal;
  }): Promise<LlmDedup["clusters"]> {
    try {
      const { object } = await this.metered(() =>
        generateObject({
          model: this.model,
          schema: LlmDedup,
          mode: "json",
          prompt: buildDedupePrompt(args),
          providerOptions: this.providerOptionsArg(),
          abortSignal: args.signal,
        }),
      );
      return object.clusters;
    } catch (err) {
      if (process.env.AGENTGG_DEBUG) {
        const util = await import("node:util");
        console.error("---- MultiProviderDetector dedupe error ----");
        console.error(util.inspect(err, { depth: 5, colors: false }));
        console.error("--------------------------------------------");
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
      // Vercel SDK's Anthropic adapter exposes `thinking` only —
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
