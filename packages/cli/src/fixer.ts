import type { Finding, ReconReport } from "@agentgg/core";
import { z } from "zod";
import { languageFromPath } from "./detect.js";
import { renderReconForPrompt } from "./recon.js";

/** Wrapper for a backend that can only return a schema-constrained object. */
export const LlmFix = z.object({
  fix: z
    .string()
    .describe("The whole answer: the explanation, the SEARCH/REPLACE blocks, any further steps."),
});
export type LlmFix = z.infer<typeof LlmFix>;

/** An answer `finishFix` rejected, sent back to the model once. */
export interface FixRetry {
  answer: string;
  problems: string[];
}

/** Requests of a live run shown in the prompt. A run can send dozens; the
 *  first ones carry the exploit, the rest are navigation. */
const LIVE_REQUEST_CAP = 10;

/** What a reproduced live run adds: the path that actually fired. */
function liveBlock(finding: Finding): string {
  const live = finding.live;
  if (live?.result !== "reproduced") return "";
  const requests = (live.evidence?.requests ?? []).slice(0, LIVE_REQUEST_CAP).map((r) => {
    const body = r.requestBody ? `, payload \`${r.requestBody}\`` : "";
    return `- ${r.method} ${r.url} → ${r.status}${body}`;
  });
  const sent = requests.length > 0 ? `\n\nRequests it sent:\n${requests.join("\n")}` : "";
  return `\n### Live reproduction\n${live.reasoning}${sent}\n`;
}

/**
 * Prompt the fix phase sends for one confirmed finding. Same grounding as
 * the validator and the scorer (finding + full file content). The answer is
 * plain text, not JSON: a fix is mostly code, and code inside a JSON string
 * is what breaks structured output. The code comes as SEARCH/REPLACE blocks
 * so `finishFix` can check every changed line against the file, and so each
 * fix is a small edit instead of a rewritten function.
 */
export function buildFixPrompt(args: {
  finding: Finding;
  fileContent: string;
  recon?: ReconReport;
  retry?: FixRetry;
}): string {
  const { finding, fileContent, recon, retry } = args;
  const lang = languageFromPath(finding.filePath);
  const lineHint = finding.lineRange
    ? `lines ${finding.lineRange[0]}–${finding.lineRange[1]}`
    : "unspecified lines";
  const reconBlock = recon ? `\n${renderReconForPrompt(recon)}\n` : "";

  // The combined verdict is `confirmed` through the source review, the live
  // run, or both. Name the one that holds: an `uncertain` review that a live
  // run overruled is not a confirmation and is not quoted as one.
  const reviewed = finding.validation?.verdict === "confirmed";
  const reproduced = finding.live?.result === "reproduced";
  const proof = [
    reviewed ? "A reviewer confirmed the vulnerability against the source code." : "",
    reproduced ? "A live run reproduced the vulnerability against the running application." : "",
  ]
    .filter(Boolean)
    .join(" ");

  // Validation may have cut the claim down; fix only what it confirmed.
  const confirmed = reviewed ? finding.validation?.confirmedImpact : undefined;
  const impactBlock = confirmed
    ? `### Impact (confirmed by validation)\n${confirmed}`
    : `### Impact\n${finding.impact}`;

  const reviewBlock = reviewed
    ? `\n### Validator's reasoning\n${finding.validation?.reasoning}\n`
    : "";

  const retryBlock = retry
    ? `

## Your previous answer was rejected

${retry.answer}

Problems:
${retry.problems.map((p) => `- ${p}`).join("\n")}

Answer again in the same format, with every problem fixed.`
    : "";

  return `You are writing the remediation for a confirmed security finding.
${proof || "The vulnerability is confirmed."} Do not re-judge it. Tell
the developer who owns this code how to fix it.
${reconBlock}
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
${reviewBlock}${liveBlock(finding)}
## The source code

\`\`\`${lang}
${fileContent}
\`\`\`

## Your task

Write the fix in this order:

1. One or two sentences: the root cause, and the change that removes it.
2. The edit to \`${finding.filePath}\`, as one or more SEARCH/REPLACE blocks:

<<<<<<< SEARCH
lines copied from the file above
=======
the lines that replace them
>>>>>>> REPLACE

3. Only when those edits are not the whole fix: a short list of the
   further steps, one line each.

Rules for the blocks:

- SEARCH holds whole lines copied character for character from the file
  above, indentation included. It is checked against the file, and a
  block that does not match is rejected.
- SEARCH must match exactly one place in the file. Add neighbouring
  lines until it does, and no more than that.
- One block for each place that changes, and only the lines that change
  there. Do not put a whole function in a block to change one line.
- To add code, put the existing line it goes next to in SEARCH and
  repeat that line in REPLACE.
- Never shorten code with "..." or a comment that stands for skipped
  lines.
- Every code change goes in a block. Use no code fence anywhere.
- Put the blocks one after another, with no text between them. The
  reader sees them as one diff.

Fix the root cause where the code goes wrong. The fix must stop the whole
class of input, not only the PoC payload: cover every path to the same
sink in this file. Keep the behavior for valid input unchanged. Prefer
the safe API the codebase or its framework already provides over a
hand-written filter or a blocklist of bad input.

Write code only for the file shown above, and only with names you can
see in it or that its framework provides. When part of the fix belongs
in another file, name the file and say in words what must change there.
You cannot see that file, so do not state what it contains. If you
cannot write a correct fix from this file alone, do not guess: write no
block, describe the change in words and say what you would need to see.

A further step is something the fix needs to work, or another place with
the same flaw. No optional hardening, no tests, no documentation changes.

Do not restate the vulnerability, the PoC or the impact. No heading, no
closing remark.${retryBlock}`;
}
