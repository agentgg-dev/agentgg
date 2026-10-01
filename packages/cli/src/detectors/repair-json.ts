import type { RepairTextFunction } from "ai";

/**
 * `generateObject` repair hook. A host that accepts `response_format` without
 * enforcing it lets the model wrap its JSON in a markdown fence or in prose,
 * which fails the SDK's parse. Recover the JSON value from that text.
 * Returns null when there is nothing to recover, so the SDK throws as before.
 */
export const repairJsonText: RepairTextFunction = async ({ text }) => {
  const trimmed = text.trim();
  const fenced = /^```[a-zA-Z]*\s*\n?([\s\S]*?)\n?\s*```$/.exec(trimmed);
  const candidate = fenced ? (fenced[1] as string).trim() : outermostJson(trimmed);
  if (candidate === null || candidate === text) return null;
  return candidate;
};

/** The span from the first `{` or `[` to its matching last closer, or null. */
function outermostJson(text: string): string | null {
  const start = text.search(/[{[]/);
  if (start < 0) return null;
  const end = text.lastIndexOf(text[start] === "{" ? "}" : "]");
  if (end <= start) return null;
  return text.slice(start, end + 1);
}
