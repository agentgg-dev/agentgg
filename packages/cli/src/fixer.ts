import type { Finding } from "@agentgg/core";
import { z } from "zod";
import { languageFromPath } from "./detect.js";

/** Wrapper for a backend that can only return a schema-constrained object. */
export const LlmFix = z.object({
  fix: z.string().describe("The fix, in Markdown."),
});
export type LlmFix = z.infer<typeof LlmFix>;

/**
 * Prompt the fix phase sends for one confirmed finding. Same grounding as
 * the validator and the scorer (finding + full file content), and the
 * answer is plain Markdown: a fix is mostly code, and code inside a JSON
 * string is what breaks structured output.
 */
export function buildFixPrompt(args: { finding: Finding; fileContent: string }): string {
  const { finding, fileContent } = args;
  const lang = languageFromPath(finding.filePath);
  const lineHint = finding.lineRange
    ? `lines ${finding.lineRange[0]}–${finding.lineRange[1]}`
    : "unspecified lines";

  // Validation may have cut the claim down; fix only what it confirmed.
  const confirmed = finding.validation?.confirmedImpact;
  const impactBlock = confirmed
    ? `### Impact (confirmed by validation)\n${confirmed}`
    : `### Impact\n${finding.impact}`;

  const reviewBlock = finding.validation?.reasoning
    ? `\n### Validator's reasoning\n${finding.validation.reasoning}\n`
    : "";

  return `You are writing the remediation for a confirmed security finding.
A reviewer already confirmed the vulnerability against the source code,
so do not re-judge it. Tell the developer who owns this code how to fix
it.

## The finding

**Title:** ${finding.title}
**Vuln class:** ${finding.vulnSlug}
**File:** ${finding.filePath} (${lineHint})

### Summary
${finding.summary}

### Details
${finding.details}

### PoC
${finding.poc}

${impactBlock}
${reviewBlock}
## The source code

\`\`\`${lang}
${fileContent}
\`\`\`

## Your task

Write the fix in Markdown, in this order:

1. One or two sentences: the root cause, and the change that removes it.
2. The corrected code for the affected lines of \`${finding.filePath}\`,
   in a fenced code block. Change only what the fix needs, and keep the
   surrounding code, names and style as they are.
3. Only when that edit is not the whole fix: one short line per further
   step (another call site, a configuration value, a dependency upgrade).

Fix the root cause where the code goes wrong. Prefer the safe API the
codebase or its framework already provides over a hand-written filter or
a blocklist of bad input.

Write code only for the file shown above. When part of the fix belongs
in a file you cannot see, name that file and describe the change in
words; do not invent its code.

Do not restate the vulnerability, the PoC or the impact. No heading, no
closing remark.`;
}

/**
 * Normalize the model's answer. Blank means no fix. A model sometimes
 * wraps its whole Markdown answer in one \`\`\`markdown fence, which would
 * render the fix as a code block.
 */
export function cleanFix(text: string | undefined): string | undefined {
  const trimmed = (text ?? "").trim();
  const wrapped = /^```(?:markdown|md)[ \t]*\r?\n([\s\S]*?)\r?\n```$/i.exec(trimmed);
  const fix = (wrapped ? wrapped[1] : trimmed).trim();
  return fix.length > 0 ? fix : undefined;
}
