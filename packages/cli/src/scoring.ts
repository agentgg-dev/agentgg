import type { CvssScore, Finding } from "@agentgg/core";
import { buildCvssScore } from "@agentgg/core";
import { z } from "zod";
import { languageFromPath } from "./detect.js";

/**
 * Shape the scoring agent is asked to produce. Only the 8 CVSS 3.1 base
 * metrics + a short justification — the score, the vector string, and
 * the severity bucket are computed deterministically in Node from these
 * values, not picked by the LLM. Small models routinely miscalculate the
 * formula; constraining the model to metric choice keeps the output
 * provider-agnostic and the math correct.
 */
export const LlmScore = z.object({
  attackVector: z
    .enum(["N", "A", "L", "P"])
    .describe(
      "Attack Vector. N=Network (remotely exploitable), A=Adjacent (same LAN/subnet), L=Local (attacker has shell/CLI access), P=Physical (attacker touches the device).",
    ),
  attackComplexity: z
    .enum(["L", "H"])
    .describe(
      "Attack Complexity. L=Low (no special conditions needed). H=High (race condition, specific configuration, or attacker preparation required).",
    ),
  privilegesRequired: z
    .enum(["N", "L", "H"])
    .describe(
      "Privileges Required to exploit. N=None (anonymous attacker), L=Low (basic authenticated user), H=High (admin / privileged account).",
    ),
  userInteraction: z
    .enum(["N", "R"])
    .describe(
      "User Interaction. N=None (works without a victim acting), R=Required (a victim must click a link, open a file, etc.).",
    ),
  scope: z
    .enum(["U", "C"])
    .describe(
      "Scope. U=Unchanged (impact stays in the vulnerable component's security authority), C=Changed (impact crosses into another component, e.g. sandbox escape, SSRF reaching internal services, stored XSS in another origin).",
    ),
  confidentiality: z
    .enum(["H", "L", "N"])
    .describe(
      "Confidentiality impact. H=High (total disclosure or all critical data leaks). L=Low (some restricted data leaks but attacker doesn't control which). N=None.",
    ),
  integrity: z
    .enum(["H", "L", "N"])
    .describe(
      "Integrity impact. H=High (attacker can modify any data / serious consequences). L=Low (attacker can modify limited data, can't fully control what). N=None.",
    ),
  availability: z
    .enum(["H", "L", "N"])
    .describe(
      "Availability impact. H=High (resource fully unavailable or sustained DoS). L=Low (reduced performance / intermittent unavailability). N=None.",
    ),
  justification: z
    .string()
    .describe(
      "2–4 sentences justifying the metric choices. Cite the specific code element or exploitation chain. Reviewers read this to sanity-check the score.",
    ),
});
export type LlmScore = z.infer<typeof LlmScore>;

/**
 * Convert the LLM's metric choices into a full `CvssScore` by running
 * the deterministic math. The vector string, the numeric base score,
 * and the severity bucket all come from `@agentgg/core/cvss`, not from
 * the model.
 */
export function asCvssScore(llm: LlmScore): CvssScore {
  return buildCvssScore({
    metrics: {
      attackVector: llm.attackVector,
      attackComplexity: llm.attackComplexity,
      privilegesRequired: llm.privilegesRequired,
      userInteraction: llm.userInteraction,
      scope: llm.scope,
      confidentiality: llm.confidentiality,
      integrity: llm.integrity,
      availability: llm.availability,
    },
    justification: llm.justification,
  });
}

/**
 * Prompt the scoring agent sees for one finding. It receives the
 * finding's narrative + the full file content (same shape as the
 * validator) and is asked to pick the 8 CVSS 3.1 base metrics. The
 * prompt teaches each metric by example so we don't depend on the
 * model having internalised the CVSS rubric.
 */
export function buildScorePrompt(args: {
  finding: Finding;
  fileContent: string;
}): string {
  const { finding, fileContent } = args;
  const lang = languageFromPath(finding.filePath);
  const lineHint = finding.lineRange
    ? `lines ${finding.lineRange[0]}–${finding.lineRange[1]}`
    : "unspecified lines";

  return `You are scoring a confirmed security finding on the CVSS 3.1 base
metrics. You will NOT pick the numeric score yourself — your job is to
choose the 8 metric values and write a short justification. The score
and severity bucket are computed deterministically afterward.

Pick each metric based on the worst plausible exploitation of the
vulnerability AS WRITTEN in the source below. Don't speculate about
hardening that isn't visible in the code. If the code shows a real
auth check that gates the sink, reflect that in Privileges Required;
if there's no such check, score it as None.

## The finding

**Title:** ${finding.title}
**Vuln class:** ${finding.vulnSlug}
**Reported by agent:** ${finding.agentSlug}
**File:** ${finding.filePath} (${lineHint})

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

## Metric reference (CVSS 3.1 base metrics)

- **Attack Vector (AV):** N (remote over network), A (adjacent network
  — same LAN/Bluetooth/etc.), L (local — attacker needs shell/CLI),
  P (physical access required). Pick the lowest privilege channel
  through which an attacker can reach the sink.
- **Attack Complexity (AC):** L (no specific conditions beyond the
  attacker's own action), H (race conditions, specific configuration,
  attacker preparation, or chained pre-requisites).
- **Privileges Required (PR):** N (no auth needed), L (any
  authenticated user), H (admin / privileged account).
- **User Interaction (UI):** N (works against the system directly),
  R (a victim must click a link / open a file / etc.).
- **Scope (S):** U (impact stays in the vulnerable component), C
  (impact crosses into a different security authority — sandbox
  escape, SSRF reaching internal services, stored XSS executing in
  another origin, container escape, etc.). Picking C is significant —
  only do it when the bug genuinely transcends the component boundary.
- **Confidentiality / Integrity / Availability (C, I, A):**
  - H = total or near-total impact on this dimension within the
    affected component
  - L = some impact but attacker has limited control over what
  - N = no impact

## Your task

Return the 8 metric values plus a 2–4 sentence justification that
references the specific code element or exploitation chain. If the
PoC is unauthenticated and pre-auth, PR must be N — do not paper over
missing auth. Conversely, if the only sink is gated by a verified
admin middleware, PR is H.

Be honest about uncertainty: if a code path could be reachable with or
without authentication depending on configuration not shown here, pick
the metric that reflects the worst plausible code-visible state, and
flag that in your justification.`;
}
