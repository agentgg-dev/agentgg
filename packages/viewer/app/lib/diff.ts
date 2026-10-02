export type DiffLineKind = "file" | "hunk" | "add" | "del" | "context";

/**
 * What each line of a unified diff is, for colouring. Position decides the
 * `---` / `+++` file header: once a hunk has started, a line that begins
 * with `---` is a removed line whose own text starts with `--`.
 */
export function diffLineKinds(lines: ReadonlyArray<string>): DiffLineKind[] {
  let inHunk = false;
  return lines.map((line) => {
    if (line.startsWith("@@")) {
      inHunk = true;
      return "hunk";
    }
    if (!inHunk) return line.startsWith("--- ") || line.startsWith("+++ ") ? "file" : "context";
    if (line.startsWith("+")) return "add";
    if (line.startsWith("-")) return "del";
    return "context";
  });
}
