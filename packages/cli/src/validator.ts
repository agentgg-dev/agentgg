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
/**
 * Reasoning recorded when the validator returns nothing at all: it spent its
 * whole turn budget on tool calls, or the completion came back empty. The
 * verdict stays `uncertain` because that is the truth (we do not know), but the
 * prose has to say the run was cut short.
 *
 * Previously an empty response went through the structured reformat, whose
 * prompt carries only the model's own output and never the finding. Asked to
 * extract a verdict from a blank page, the model complied: it picked
 * `uncertain` and wrote "No validation content or finding was provided to
 * analyze", which landed on the finding looking like a real judgement.
 *
 * Exported so both detectors emit the same string, tests assert on it, and a
 * cleanup pass can find affected findings. User-facing: the dashboard renders
 * it verbatim.
 */
export const VALIDATION_CUT_SHORT =
  "Validation was cut short. The model stopped before it returned a verdict, so this finding was not assessed.";

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
  // Optional: `asValidationField` drops it, so a missing value costs nothing —
  // but a required field threw away whole verdicts when the model closed the
  // object early (unescaped quote inside `reasoning`).
  confidence: z
    .preprocess((v) => (typeof v === "number" && v > 1 ? v / 100 : v), z.number().min(0).max(1))
    .default(0.5)
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
  /**
   * When set, the validator is running tool-enabled (Read/Glob/Grep
   * rooted at the repo). The prompt then tells the model to trace the
   * exploit chain across files rather than judging the embedded file in
   * isolation. When omitted, the model only has the embedded file.
   */
  root?: string;
}): string {
  const { finding, fileContent, scope, root } = args;
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
    : "\nNo scope document was supplied for this run, so `out-of-scope` is not a valid verdict — use `uncertain` if you would otherwise have picked it.\n";

  // Tool-enabled runs (root set) get an explicit instruction to trace the
  // exploit chain across files. The embedded file below is only the
  // finding's OWN file — for a cross-file chain (endpoint → service →
  // sink) the mitigating guard often lives in a DIFFERENT file the model
  // must open itself.
  const tracingBlock = root
    ? `
## Trace the chain across files — do not judge this file in isolation

You have Read/Glob/Grep tools rooted at the repository. The source
below is only the finding's own file (\`${finding.filePath}\`). Many
findings are cross-file: an entry point in one file reaches the sink in
another through a service or repository layer, and a validation/filter
step in between can neutralize the reported bug (or, conversely, a
missing guard upstream can confirm it).

Before deciding, actually investigate:
- Grep for the sink method / endpoint named in the finding to locate its
  callers and the request handler that reaches it.
- Read those intermediate files. Confirm whether the untrusted input
  really flows to the sink UNCHANGED, or whether an intermediate step
  filters, allowlists, or otherwise constrains it (e.g. the input is used
  only to look up / select an already-trusted value, not as the sink
  argument itself).
- Check the actual auth/authorization gating on the real entry point.

Only after tracing the reachable path end to end should you classify. If
the reported mechanism is broken by an intermediate guard (for example
the input only selects an already-trusted value rather than being the
sink argument): return 'false-positive' when no real vulnerability
remains, or 'uncertain' when a weaker or different real issue remains (a
different entry point, or one reachable only by a privileged actor). Do
NOT confirm the original writeup in that case.
`
    : "";

  return `You are reviewing a security finding produced by another agent.
Your job is to classify it by re-examining the source code yourself.

Be skeptical. Detection agents over-report. Reserve 'confirmed' for
findings you are certain are a genuine, exploitable security
vulnerability: the kind you would stake a CVE, a security advisory, or a
published proof-of-concept on. That means you traced the exact unsafe
code element AND a concrete, working exploit path from an
attacker-reachable entry point, AND the finding as reported matches that
path. If you are not that certain, do not confirm.

Use 'uncertain' whenever a real issue is plausible but you cannot stand
behind the report as written: the reported entry point turns out to be a
filter or guard, the described PoC does not actually work as stated, the
true exploit path runs through a different endpoint than the title
claims, exploitation depends on a privileged or otherwise trusted actor,
or you could not fully verify reachability. 'uncertain' is the correct
home for "there is probably something here, but not the clean, certain,
report-it-upstream finding that was described." Confirming a shaky or
mischaracterized finding is worse than an honest 'uncertain'.

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
${tracingBlock}${scopeBlock}
## Your task

Return a verdict (${verdictOptions}), a short reasoning (max 4
sentences, cite a specific code element), and your confidence.
${scopeVerdictNote}
'confirmed' requires ALL of: you traced a working exploit path end to
end, it is reachable by the relevant attacker, and the finding as
reported is accurate. If the PoC as written would not work but a real
issue may still exist, return 'uncertain', not 'confirmed'. If there is
no real vulnerability at all, return 'false-positive'.`;
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

/**
 * Build the prompt for `--scope-validate`. Same schema (`LlmValidation`)
 * as the full validator so detectors can reuse their structured-output
 * path, but the prompt:
 *
 *   - withholds file content entirely
 *   - requires a scope document
 *   - constrains the model to `out-of-scope` or `uncertain`
 *     (`confirmed` / `false-positive` need the code, which scope-only
 *     mode deliberately skips)
 *
 * Used as a cheap pre-filter to knock out scope-disqualified findings
 * before paying the full validator cost.
 */
export function buildScopeValidatePrompt(args: { finding: Finding; scope: string }): string {
  const { finding, scope } = args;
  const lineHint = finding.lineRange
    ? `lines ${finding.lineRange[0]}–${finding.lineRange[1]}`
    : "unspecified lines";

  return `You are classifying a security finding against a scope document.
You will NOT see the source code — your only job is to decide whether
the documented scope explicitly excludes this finding.

## The finding

**Title:** ${finding.title}
**Vuln class:** ${finding.vulnSlug}
**Reported by agent:** ${finding.agentSlug}
**File:** ${finding.filePath} (${lineHint})

### Summary
${finding.summary}

### Details
${finding.details}

### Impact
${finding.impact}

## Scope rules

The document below describes what's in-scope for this engagement
(usually a SECURITY.md). If the finding's file path, vulnerability
class, or affected component is explicitly excluded by this scope,
return \`out-of-scope\` and quote the matching rule. Otherwise return
\`uncertain\` — that signals the scope did not disqualify the finding
(full validation against the source is still needed to confirm or
dismiss it).

\`\`\`
${scope}
\`\`\`

## Your task

Return one of:
- \`out-of-scope\` — scope explicitly excludes this finding's path,
  vulnerability class, or affected component. Quote the matching rule.
- \`uncertain\` — scope does not clearly exclude this finding.

You MUST NOT return \`confirmed\` or \`false-positive\` — those
verdicts require reading the source code, which has not been provided.

Reasoning: at most 4 sentences. Quote the specific scope rule that
drove your decision.`;
}
