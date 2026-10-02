import type { Finding, ReconReport } from "@agentgg/core";
import { z } from "zod";
import { languageFromPath } from "./detect.js";
import { renderReconForPrompt } from "./recon.js";

/** Wrapper for a backend that can only return a schema-constrained object. */
export const LlmFix = z.object({
  fix: z.string().describe("The fix, in Markdown."),
});
export type LlmFix = z.infer<typeof LlmFix>;

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
 * the validator and the scorer (finding + full file content), and the
 * answer is plain Markdown: a fix is mostly code, and code inside a JSON
 * string is what breaks structured output.
 */
export function buildFixPrompt(args: {
  finding: Finding;
  fileContent: string;
  recon?: ReconReport;
}): string {
  const { finding, fileContent, recon } = args;
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

Write the fix in Markdown, in this order:

1. One or two sentences: the root cause, and the change that removes it.
2. The corrected code for the affected lines of \`${finding.filePath}\`,
   in a fenced code block. Change only what the fix needs, and keep the
   surrounding code, names and style as they are.
3. Only when that edit is not the whole fix: one short line per further
   step (another call site, a configuration value, a dependency upgrade).

Fix the root cause where the code goes wrong. The fix must stop the whole
class of input, not only the PoC payload: cover every path to the same
sink in this file. Keep the behavior for valid input unchanged. Prefer
the safe API the codebase or its framework already provides over a
hand-written filter or a blocklist of bad input.

Write code only for the file shown above, and only with names you can
see in it or that its framework provides. When part of the fix belongs
in a file you cannot see, name that file and describe the change in
words; do not invent its code. If you cannot write a correct fix from
this file alone, do not guess: describe the change in words and say what
you would need to see.

Do not restate the vulnerability, the PoC or the impact. No heading, no
closing remark.`;
}

const FENCE = /^ {0,3}(`{3,}|~{3,})(.*)$/;

/** True when `line` closes a fence opened with `open`. */
function closes(line: string, open: string): boolean {
  const m = FENCE.exec(line);
  return !!m && m[1][0] === open[0] && m[1].length >= open.length && m[2].trim() === "";
}

/** The marker of the fence still open at the end of `lines`, if any. */
function openFence(lines: string[]): string | undefined {
  let open: string | undefined;
  for (const line of lines) {
    if (open) {
      if (closes(line, open)) open = undefined;
    } else {
      open = FENCE.exec(line)?.[1];
    }
  }
  return open;
}

/**
 * Normalize the model's answer. Blank means no fix. A model sometimes wraps
 * its whole Markdown answer in one \`markdown\` fence, which would render the
 * fix as a code block; and an answer that leaves a code fence open would
 * swallow every report section after it.
 */
export function cleanFix(text: string | undefined): string | undefined {
  let lines = (text ?? "").trim().split(/\r?\n/);
  const wrapper = FENCE.exec(lines[0]);
  if (wrapper && /^(?:markdown|md)$/i.test(wrapper[2].trim())) {
    const inner = lines.slice(1, -1);
    // The last line is the wrapper's own closing fence only when the content
    // between them is balanced; otherwise it closes a code block inside.
    const wrapped =
      lines.length > 1 && closes(lines[lines.length - 1], wrapper[1]) && !openFence(inner);
    lines = wrapped ? inner : lines.slice(1);
  }
  const open = openFence(lines);
  if (open) lines.push(open);
  const fix = lines.join("\n").trim();
  return fix.length > 0 ? fix : undefined;
}
