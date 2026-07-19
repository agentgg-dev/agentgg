/**
 * Content-refusal recognition, shared by every detector backend.
 *
 * A refusal is the model declining to analyze code it read as harmful,
 * returned as prose instead of the expected structured output. It's expected
 * behavior, not an error: callers record it as "0 findings" (detection) or
 * "uncertain" (validation) so one squeamish agent doesn't fail the whole scan
 * and inflate the platform's agent-failure ratio.
 */

/** First-person decline. Third-person prose ("the parser will not reject...")
 *  is finding text, not a refusal, so every pattern is anchored to "I". */
const DECLINE =
  /\bi(?:'ll)? (?:can'?t|cannot|won'?t|will not|refuse to|must decline|have to decline|decline)\b|\bi(?:'m| am) (?:unable|not able|not comfortable|not going to|not willing)\b/;

/** Verbs of *epistemic* limitation. "I can't confirm the sink is reachable"
 *  hedges one conclusion and keeps going; it doesn't decline the task. */
const CAPABILITY_OBJECT =
  /^\s*(?:to\s+)?(?:confirm|determine|verify|validate|access|read|open|locate|find|tell|say|know|see|reach|resolve|reproduce|trace|inspect|rule\s+out|be\s+(?:sure|certain))\b/;

/** Structure only a real analysis produces. A refusal is a short standalone
 *  message; if the model emitted any of this it kept working after its caveat. */
const ANALYSIS_MARKERS = [
  /```/,
  /\b[\w./-]+\.(?:ts|tsx|js|jsx|py|go|rb|java|php|rs|c|cpp|cs|kt|swift|sql|yml|yaml|json)\b/i,
  /\b(?:severity|cwe-\d+|line\s+\d+|vulnerabilit|injection|xss|ssrf|idor)\b/i,
  /"?findings"?\s*:/i,
];

/**
 * Three checks, in order: a first-person decline in the opening ~600 chars (a
 * refusal leads with it); what the model declined to *do*; and whether the
 * message carries analysis structure anywhere. The last two exist to spare
 * capability caveats — "I'm unable to read src/config.ts, so I analyzed the
 * rest" opens like a refusal but is a real result. Callers run this only on a
 * failure path, where a false negative preserves the existing throw.
 */
export function looksLikeRefusal(text: string): boolean {
  if (!text) return false;
  const head = text.slice(0, 600).toLowerCase().replace(/[‘’`]/g, "'");
  const declined = head.match(DECLINE);
  if (!declined) return false;
  if (CAPABILITY_OBJECT.test(head.slice((declined.index ?? 0) + declined[0].length))) return false;
  // Markers run against the raw text, not `head`: the normalization above
  // rewrites backticks (killing the code-fence signal), and findings can arrive
  // well past the 600-char window.
  if (ANALYSIS_MARKERS.some((re) => re.test(text))) return false;
  return true;
}

/**
 * Thrown from a schema-generic call site that can't itself decide the fallback
 * (the Claude SDK's runStructured serves detection, validation, scoring and
 * dedup through one method). Phase-specific callers catch it and substitute
 * their own empty result; everyone else lets it propagate as a normal Error,
 * preserving today's fail-loud behavior.
 */
export class RefusalError extends Error {
  /** The model's refusal prose, for logging. */
  readonly responseText: string;

  constructor(responseText: string) {
    super(`Model refused the request: ${responseText.slice(0, 200)}…`);
    this.name = "RefusalError";
    this.responseText = responseText;
  }
}
