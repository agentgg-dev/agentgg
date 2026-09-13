/**
 * Compile a regex authored in an agent's frontmatter.
 *
 * Agent patterns are written PCRE-style, where a leading `(?i)` turns on
 * case-insensitive matching. JS `RegExp` has no inline flags and throws
 * "Invalid group", and every evaluator swallows that error and skips the
 * pattern — so such a pattern silently matches nothing. Hoist the inline
 * flag to the JS `i` flag instead.
 */

/** PCRE inline case-insensitive flag. Global: a few patterns repeat it. */
const INLINE_CASE_INSENSITIVE = /\(\?i\)/g;

/**
 * Throws the same way `new RegExp` does when the pattern is genuinely
 * malformed, so the catalog validator still reports real errors.
 */
export function compileAgentRegex(source: string): RegExp {
  const stripped = source.replace(INLINE_CASE_INSENSITIVE, "");
  // Every `(?i)` in the catalog is at position 0, or repeats inside a
  // pattern that already starts with one, so a whole-pattern flag keeps
  // the authored meaning.
  return stripped === source ? new RegExp(source) : new RegExp(stripped, "i");
}
