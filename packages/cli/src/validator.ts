import type { Finding, ValidationVerdict } from "@agentgg/core";
import { z } from "zod";
import { languageFromPath } from "./detect.js";

/**
 * Shape the LLM is asked to produce for a single finding. Maps onto a
 * subset of `ValidationResult` from @agentgg/core — fields like
 * `scopeRef` (SECURITY.md driven) and `adjustedSeverity` (scoring
 * agent driven) are intentionally NOT delegated to the validator.
 *
 * The detector wraps this in its provider-specific schema enforcement
 * (Vercel SDK uses `generateObject`; Claude Agent SDK relies on a
 * JSON-only prompt and defensive parsing).
 */
export const LlmValidation = z.object({
  verdict: z
    .enum(["confirmed", "false-positive", "out-of-scope", "uncertain"])
    .describe(
      "Your classification of the finding. " +
        "'confirmed' = real bug, exploitation plausible. " +
        "'false-positive' = code is not vulnerable as described. " +
        "'out-of-scope' = applies only when scope hints disqualify it. " +
        "'uncertain' = you don't have enough information to decide.",
    ),
  reasoning: z
    .string()
    .describe(
      "Short prose (max 4 sentences) explaining your verdict. Cite the specific code element that made you decide.",
    ),
  confidence: z
    .preprocess((v) => (typeof v === "number" && v > 1 ? v / 100 : v), z.number().min(0).max(1))
    .describe(
      "Decimal 0.0–1.0. NOT a percentage. Write 0.3 not 30. 0.0 = guess, 1.0 = certain. Uncertain verdicts should have low confidence.",
    ),
});
export type LlmValidation = z.infer<typeof LlmValidation>;

/**
 * Build the prompt the validator sees for one finding. Includes the
 * finding's narrative fields and the full file content (so the
 * validator re-grounds its judgement in the actual code, not the
 * detector's prose).
 *
 * Returns the prompt as a string; the calling detector wraps it with
 * provider-specific output enforcement.
 */
export function buildValidatePrompt(args: {
  finding: Finding;
  fileContent: string;
  /**
   * Optional scope document (typically SECURITY.md contents). When
   * present, the validator is told to also classify the finding against
   * the documented scope and may return `out-of-scope`. When absent,
   * the model is told that the `out-of-scope` verdict is NOT available
   * — without scope context, that verdict would be guesswork.
   */
  scope?: string;
}): string {
  const { finding, fileContent, scope } = args;
  const lang = languageFromPath(finding.filePath);
  const lineHint = finding.lineRange
    ? `lines ${finding.lineRange[0]}–${finding.lineRange[1]}`
    : "unspecified lines";

  const scopeBlock = scope
    ? `
## Scope rules

The document below describes what's in-scope for this engagement
(usually a SECURITY.md). If the finding describes a real bug but its
file path, vulnerability class, or affected component is explicitly
excluded by this scope, return \`out-of-scope\`. Quote the matching
scope rule in your reasoning. If nothing in the scope disqualifies it,
ignore the scope and judge the finding on technical merit.

\`\`\`
${scope}
\`\`\`
`
    : "";

  const verdictOptions = scope
    ? '"confirmed" | "false-positive" | "out-of-scope" | "uncertain"'
    : '"confirmed" | "false-positive" | "uncertain"';

  const scopeVerdictNote = scope
    ? ""
    : '\nNo scope document was supplied for this run, so `out-of-scope` is not a valid verdict — use `uncertain` if you would otherwise have picked it.\n';

  return `You are reviewing a security finding produced by another agent.
Your job is to classify it by re-examining the source code yourself.

Be skeptical. Detection agents often over-report. A finding is only
"confirmed" if you can identify the specific unsafe code element AND
articulate how an attacker would exploit it given the surrounding
context (auth middleware, framework defaults, calling conventions,
etc.). When in doubt, say "uncertain" — false negatives in the
validator (calling a real bug FP) are worse than uncertain verdicts.

## The finding

**Title:** ${finding.title}
**Vuln class:** ${finding.vulnSlug}
**Reported by agent:** ${finding.agentSlug}
**File:** ${finding.filePath} (${lineHint})
**Detector confidence:** ${finding.confidence.toFixed(2)} (0.0–1.0 scale)

### Summary
${finding.summary}

### Details
${finding.details}

### PoC
${finding.poc}

### Impact
${finding.impact}

## The source code

\`\`\`${lang}
${fileContent}
\`\`\`
${scopeBlock}
## Your task

Return a verdict (${verdictOptions}), a short reasoning (max 4
sentences, cite a specific code element), and your confidence.
${scopeVerdictNote}
If you find that the detector's PoC wouldn't actually work (wrong
endpoint shape, missing auth bypass step, etc.), that's strong
evidence for false-positive. If the code legitimately matches what the
detector described and the exploit chain is reachable from an untrusted
input, that's confirmed.`;
}

/**
 * Convenience: map an LLM-produced classification onto the slot on the
 * Finding. Kept here so both detectors hydrate identically.
 */
export function asValidationField(v: LlmValidation): {
  verdict: ValidationVerdict;
  reasoning: string;
} {
  return { verdict: v.verdict, reasoning: v.reasoning };
}
