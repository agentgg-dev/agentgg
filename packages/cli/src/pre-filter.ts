import { type AgentPreFilterPattern, isRegexPreFilter } from "@agentgg/core";

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
  /** Last line of a multi-line anchor. A regex hit is one line and omits it. */
  endLine?: number;
  label: string;
  snippet: string;
  /**
   * The rule's own `message`, with metavariables already substituted by the
   * engine. Only a semgrep hit has one; a regex has no author intent to carry.
   * Omitted when it would repeat `label`.
   */
  message?: string;
  /** Allow-listed `metadata:` keys from the rule, flattened for display. */
  metadata?: Record<string, string>;
  /** Taint-mode dataflow path, source first and sink last. */
  taint?: TaintStep[];
}

/**
 * One node on a taint path. The code text comes from the engine, not from
 * the file, so it stays correct even when the step is a sub-expression.
 */
export interface TaintStep {
  /** `elided` stands in for the steps a length cap dropped. */
  kind: "source" | "through" | "sink" | "elided";
  /** For `elided`, the line of the first dropped step. */
  line: number;
  code: string;
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
  // Only the regex form is handled here. Semgrep entries are resolved by
  // `runSemgrepPreFilter`, which needs the whole file set at once; anything
  // else is a form this build does not know and is ignored rather than
  // mis-read as a regex.
  for (const entry of preFilter) {
    if (!isRegexPreFilter(entry)) continue;
    const { regex, label } = entry;
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
