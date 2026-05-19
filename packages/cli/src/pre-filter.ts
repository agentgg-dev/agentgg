import type { AgentPreFilterPattern } from "@agentgg/core";

/**
 * One line where a walker-mode agent's preFilter regex matched. The
 * line number is 1-indexed (LLM-friendly) and the snippet is the
 * matched line itself, trimmed and truncated for prompt brevity.
 *
 * One hit per row so the prompt can render exactly which line the
 * model should anchor on.
 */
export interface PreFilterHit {
  line: number;
  label: string;
  snippet: string;
}

/**
 * Run an agent's `preFilter` regexes against one file's content.
 * Returns every (line, pattern) pair that matched. A file with zero
 * hits should not be sent to the LLM — `preFilter` is the cheap pass
 * that narrows `filePatterns`-matched files down to candidates.
 *
 * Empty `preFilter` is treated as "no filtering" — every line passes
 * with a synthetic single hit on line 1, so a walker agent without
 * preFilter still gets to investigate every file (the batch-investigate
 * fallback for direct-invocation flows).
 */
export function evaluatePreFilter(
  content: string,
  preFilter: ReadonlyArray<AgentPreFilterPattern>,
): PreFilterHit[] {
  if (preFilter.length === 0) {
    // No preFilter declared → fall through and let the model see the
    // whole file. One synthetic hit so callers can still treat
    // "candidate or not" as `hits.length > 0`.
    return [{ line: 1, label: "(no preFilter)", snippet: "" }];
  }

  const lines = content.split("\n");
  const hits: PreFilterHit[] = [];
  for (const { regex, label } of preFilter) {
    let re: RegExp;
    try {
      re = new RegExp(regex);
    } catch {
      // Bad regex in the agent .md — skip it rather than crash the
      // whole scan. The author should fix it; we surface a warning
      // in the caller if needed.
      continue;
    }
    for (let i = 0; i < lines.length; i++) {
      if (re.test(lines[i])) {
        hits.push({
          line: i + 1,
          label: label ?? regex,
          snippet: lines[i].trim().slice(0, 200),
        });
      }
    }
  }
  return hits;
}
