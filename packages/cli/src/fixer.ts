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

/** The reproduction script of a live run, read from the finding's evidence. */
export interface LiveScript {
  source: string;
  /** Whether its replay passed. A script that did not is the agent's account
   *  of the attack, not proof of it. */
  passed: boolean;
}

const LIVE_REQUEST_CAP = 10;
const LIVE_SCRIPT_CAP = 6000;
/** A request counts as cited only through a value this long: `1` or `on`
 *  occurs in any prose. */
const MIN_CITED_LENGTH = 4;

type LiveRequest = NonNullable<
  NonNullable<NonNullable<Finding["live"]>["evidence"]>["requests"]
>[number];

function decode(text: string): string {
  try {
    return decodeURIComponent(text.replace(/\+/g, " "));
  } catch {
    return text;
  }
}

function jsonStrings(value: unknown, out: string[]): void {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const v of value) jsonStrings(v, out);
  else if (value && typeof value === "object") {
    for (const v of Object.values(value)) jsonStrings(v, out);
  }
}

/** The input a request carries: its path, its query values, its body values. */
function inputsOf(r: LiveRequest): string[] {
  const out: string[] = [];
  try {
    const url = new URL(r.url);
    for (const v of url.searchParams.values()) out.push(v);
    if (url.pathname !== "/") out.push(decode(url.pathname));
  } catch {
    // not a URL: nothing to take from it
  }
  // The stored body is a preview, cut with an ellipsis.
  const body = r.requestBody?.replace(/…$/, "");
  if (body) {
    try {
      jsonStrings(JSON.parse(body), out);
    } catch {
      for (const pair of body.split("&")) {
        const eq = pair.indexOf("=");
        out.push(decode(eq < 0 ? pair : pair.slice(eq + 1)));
      }
    }
  }
  return out.map((v) => v.trim());
}

/**
 * The requests the live agent itself points at. A session holds the hunt for
 * the page, the attack and the control in no fixed order, so position says
 * nothing; a request whose input the agent wrote down in its reasoning, its
 * control or the PoC is one it meant.
 */
function citedRequests(finding: Finding): string[] {
  const live = finding.live;
  const cited = `${live?.reasoning ?? ""}\n${live?.negativeControl ?? ""}\n${finding.poc}`;
  const lines: string[] = [];
  for (const r of live?.evidence?.requests ?? []) {
    if (!inputsOf(r).some((v) => v.length >= MIN_CITED_LENGTH && cited.includes(v))) continue;
    const body = r.requestBody ? `, payload \`${r.requestBody}\`` : "";
    const line = `- ${r.method} ${r.url} → ${r.status}${body}`;
    if (!lines.includes(line)) lines.push(line);
    if (lines.length === LIVE_REQUEST_CAP) break;
  }
  return lines;
}

/**
 * What a reproduced live run adds: the path that actually fired. The script
 * is the best account of it (only the steps that cause the effect, with the
 * exact payload), so it replaces the request list when there is one.
 */
function liveBlock(finding: Finding, script?: LiveScript): string {
  const live = finding.live;
  if (live?.result !== "reproduced") return "";
  const parts = [`### Live reproduction\n${live.reasoning}`];
  if (live.negativeControl?.trim()) parts.push(`Negative control: ${live.negativeControl.trim()}`);
  if (script) {
    const cut = script.source.length > LIVE_SCRIPT_CAP;
    const source = cut
      ? `${script.source.slice(0, LIVE_SCRIPT_CAP)}\n// [script cut]`
      : script.source;
    const status = script.passed
      ? "Its replay passed."
      : "Its replay did not pass, so read its steps as the agent's account of the attack, not as proof.";
    parts.push(
      `The script that reproduces it (Playwright). ${status} It can hold a login for the test target. Never repeat a credential in your answer.\n\n\`\`\`ts\n${source.trimEnd()}\n\`\`\``,
    );
  } else {
    const requests = citedRequests(finding);
    if (requests.length > 0) parts.push(`Requests it refers to:\n${requests.join("\n")}`);
  }
  return `\n${parts.join("\n\n")}\n`;
}

/** The scope rules of the fix, which differ when the model can read the repo. */
function scopeRules(filePath: string, tools: boolean): string {
  if (!tools) {
    return `Write code only for the file shown above, and only with names you can
see in it or that its framework provides. When part of the fix belongs
in another file, name the file and say in words what must change there.
You cannot see that file, so do not state what it contains. If you
cannot write a correct fix from this file alone, do not guess: write no
block, describe the change in words and say what you would need to see.`;
  }
  return `You have Read, Glob and Grep tools rooted at the repository. The source
above is only the finding's own file (\`${filePath}\`). Before you write,
read what the fix depends on:

- the definition of every function, helper, filter or template syntax
  the fix uses. Do not use an API or a syntax that you
  have not seen in this repository: a library bundled here can be older
  than the one you know.
- the other files the flow passes through, when the root cause or a
  safer place for the fix is there.

You have a limited number of tool calls. Read only what the fix needs,
and write the fix as soon as you know it: a session that ends with no
fix is a failure, and an unread file that the fix does not touch is not.

A block can edit any file you have read. Put the fix where the code goes
wrong, even when that is not the finding's file. Say nothing about a
file you have not read. If you cannot write a correct fix, do not guess:
write no block, describe the change in words and say what stopped you.`;
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
  liveScript?: LiveScript;
  /** Set when the call runs with Read/Glob/Grep rooted here. The prompt then
   *  tells the model to read before it writes, and lets it edit other files. */
  root?: string;
}): string {
  const { finding, fileContent, recon, retry, liveScript } = args;
  const tools = args.root !== undefined;
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

  const blockTarget = tools
    ? `The edit, as one or more SEARCH/REPLACE blocks. Above each block,
   on its own line, write the path of its file from the repository root:

${finding.filePath}
<<<<<<< SEARCH
lines copied from that file
=======
the lines that replace them
>>>>>>> REPLACE`
    : `The edit to \`${finding.filePath}\`, as one or more SEARCH/REPLACE blocks:

<<<<<<< SEARCH
lines copied from the file above
=======
the lines that replace them
>>>>>>> REPLACE`;

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
${reviewBlock}${liveBlock(finding, liveScript)}
## The source code

\`\`\`${lang}
${fileContent}
\`\`\`

## Your task

Write the fix in this order:

1. One or two sentences: the root cause, and the change that removes it.
2. ${blockTarget}

3. Only when those edits are not the whole fix: a short list of the
   further steps, one line each.

Rules for the blocks:

- SEARCH holds whole lines copied character for character from the
  file, indentation included. It is checked against the file, and a
  block that does not match is rejected.
- SEARCH must match exactly one place in the file. Add neighbouring
  lines until it does, and no more than that.
- One block for each place that changes, and only the lines that change
  there. Do not put a whole function in a block to change one line.
- REPLACE must be valid where it lands. Read each new line as the file
  will hold it: keep the syntax around the value you change (the
  delimiters, quotes, brackets and indentation of the original line)
  unless removing it is the fix.
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

${scopeRules(finding.filePath, tools)}

A further step is something the fix needs to work, or another place with
the same flaw. No optional hardening, no tests, no documentation changes.

Do not restate the vulnerability, the PoC or the impact. No heading, no
closing remark.${retryBlock}`;
}
