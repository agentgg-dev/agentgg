/**
 * The text-only check on a suggested fix. The model writes its code changes
 * as SEARCH/REPLACE blocks, each for one file; each SEARCH must match exactly
 * one place in that file. Blocks that pass are rendered as one unified diff
 * per file, so every line of code the report shows is known to apply to the
 * repository as scanned. That is all it proves: the check says nothing about
 * whether the fix is right.
 */

export type FixResult =
  /** `fix` is the Markdown to store. `edits` is 0 for an answer in words
   *  only. `files` are the files the edits change, the finding's file first. */
  | { kind: "fix"; fix: string; edits: number; files: string[] }
  | { kind: "empty" }
  /** `problems` is written for the model: it is sent back for one retry. */
  | { kind: "rejected"; problems: string[] };

/** The content of a file by its path from the repository root, or undefined
 *  for a path the fix may not edit: missing, or outside the repository. */
export type FileReader = (path: string) => string | undefined;

const FENCE = /^ {0,3}(`{3,}|~{3,})(.*)$/;

// A block, with the code fence a model often puts around it.
const BLOCK =
  /^(?:[ \t]*(?:`{3,}|~{3,})[^\n]*\n)?<{5,9} ?SEARCH[ \t]*\n([\s\S]*?)^={5,9}[ \t]*\n([\s\S]*?)^>{5,9} ?REPLACE[ \t]*(?:\n[ \t]*(?:`{3,}|~{3,})[ \t]*(?=\n|$))?/gm;

const MARKER = /^(?:<{5,9} ?SEARCH|>{5,9} ?REPLACE)\b/m;

interface Hunk {
  /** 1-based position of the block in the answer, for the problem text. */
  block: number;
  file: string;
  /** 0-based index of the first matched line. */
  start: number;
  old: string[];
  neu: string[];
}

const rtrim = (s: string): string => s.replace(/\s+$/, "");
const same = (a: string, b: string): boolean => rtrim(a) === rtrim(b);
const dropLastNewline = (s: string): string => (s.endsWith("\n") ? s.slice(0, -1) : s);

/** True when `line` closes a fence opened with `open`. */
function closes(line: string, open: string): boolean {
  const m = FENCE.exec(line);
  return !!m && m[1][0] === open[0] && m[1].length >= open.length && m[2].trim() === "";
}

function hasOpenFence(lines: string[]): boolean {
  let open: string | undefined;
  for (const line of lines) {
    if (open) {
      if (closes(line, open)) open = undefined;
    } else {
      open = FENCE.exec(line)?.[1];
    }
  }
  return open !== undefined;
}

/** A model sometimes wraps its whole answer in one `markdown` fence. */
function unwrap(text: string): string {
  const lines = text.trim().split("\n");
  const wrapper = FENCE.exec(lines[0]);
  if (!wrapper || !/^(?:markdown|md)$/i.test(wrapper[2].trim())) return lines.join("\n");
  const inner = lines.slice(1, -1);
  // The last line is the wrapper's own closing fence only when the content
  // between them is balanced; otherwise it closes a code block inside.
  const wrapped =
    lines.length > 1 && closes(lines[lines.length - 1], wrapper[1]) && !hasOpenFence(inner);
  return (wrapped ? inner : lines.slice(1)).join("\n");
}

/** Every index where `search` matches whole lines of `file`. Trailing
 *  whitespace is ignored; indentation is not. */
function matches(file: string[], search: string[]): number[] {
  const found: number[] = [];
  for (let i = 0; i + search.length <= file.length; i++) {
    if (search.every((line, k) => same(file[i + k], line))) found.push(i);
  }
  return found;
}

/** Where a hunk lands in the scanned file, in words. Counts only the lines
 *  that change: the lines a block repeats to anchor itself are not the fix. */
function place(start: number, oldLength: number, pre: number, post: number): string {
  const first = start + 1 + pre;
  const last = start + oldLength - post;
  if (last > first) return `lines ${first}–${last}`;
  if (last === first) return `line ${first}`;
  // Nothing removed: the block only adds lines next to the line it copied.
  return pre > 0 ? `after line ${start + pre}` : `before line ${start + 1}`;
}

/** One unified diff for the file, plus where each hunk lands. A hunk header
 *  alone (`@@ -68,1 +68,2 @@`) does not read as "line 68" to most people, so
 *  the place is also written after it, where patch tools ignore it. */
function renderDiff(filePath: string, hunks: Hunk[]): { diff: string; places: string[] } {
  const body = [`--- a/${filePath}`, `+++ b/${filePath}`];
  const places: string[] = [];
  let shift = 0;
  for (const { start, old, neu } of hunks) {
    // Lines the block repeats to anchor itself are context, not changes.
    const shared = Math.min(old.length, neu.length);
    let pre = 0;
    while (pre < shared && same(old[pre], neu[pre])) pre++;
    let post = 0;
    while (post < shared - pre && same(old[old.length - 1 - post], neu[neu.length - 1 - post])) {
      post++;
    }
    const where = place(start, old.length, pre, post);
    places.push(where);
    const newStart = start + 1 + shift;
    body.push(
      `@@ -${start + 1},${old.length} +${neu.length === 0 ? newStart - 1 : newStart},${neu.length} @@ ${where}`,
    );
    for (const line of old.slice(0, pre)) body.push(` ${line}`);
    for (const line of old.slice(pre, old.length - post)) body.push(`-${line}`);
    for (const line of neu.slice(pre, neu.length - post)) body.push(`+${line}`);
    for (const line of old.slice(old.length - post)) body.push(` ${line}`);
    shift += neu.length - old.length;
  }
  const text = body.join("\n");
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map((run) => run.length));
  const fence = "`".repeat(Math.max(3, longest + 1));
  return { diff: `${fence}diff\n${text}\n${fence}`, places };
}

const list = (items: string[]): string =>
  items.length < 2 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items.at(-1)}`;

/** A line that names a file: one token, with the wrappers a model adds
 *  (backticks, bold, a trailing colon) taken off. */
function asPath(line: string): string | undefined {
  const path = line
    .trim()
    .replace(/^[`*]+/, "")
    .replace(/[`*:]+$/, "")
    .replace(/\\/g, "/")
    .replace(/^\.\//, "");
  return path === "" || /[\s<>"|?*]/.test(path) || path.includes("://") ? undefined : path;
}

/**
 * The file a block is for: the path on the line above it. A last line that
 * is one word and names no file ("done.") is the end of a sentence, so it
 * stays text; one with a slash that names no file is a path the model got
 * wrong, and is returned so the block can be rejected for it.
 */
function takePath(
  before: string,
  isFile: (path: string) => boolean,
): { path?: string; text: string } {
  const lines = before.replace(/\n+$/, "").split("\n");
  const path = asPath(lines[lines.length - 1] ?? "");
  if (!path || !(isFile(path) || path.includes("/"))) return { text: before };
  lines.pop();
  // A fence the model opened around the path and its block.
  if (lines.length > 0 && FENCE.test(lines[lines.length - 1])) lines.pop();
  return { path, text: lines.join("\n") };
}

/**
 * Check the model's answer against the repository and build the Markdown to
 * store. `readFile` returns the content of a path from the repository root,
 * or undefined for anything the fix may not edit. A block with no path line
 * above it is for `defaultPath`, the finding's file.
 */
export function finishFix(
  answer: string | undefined,
  readFile: FileReader,
  defaultPath: string,
): FixResult {
  const text = unwrap((answer ?? "").replace(/\r\n/g, "\n"));
  if (text.trim() === "") return { kind: "empty" };

  const contents = new Map<string, string | undefined>();
  const contentOf = (path: string): string | undefined => {
    if (!contents.has(path)) contents.set(path, readFile(path)?.replace(/\r\n/g, "\n"));
    return contents.get(path);
  };
  const isFile = (path: string): boolean => path === defaultPath || contentOf(path) !== undefined;

  const problems: string[] = [];
  const hunks: Hunk[] = [];
  const prose: string[] = [];
  let cursor = 0;
  let block = 0;
  for (const m of text.matchAll(BLOCK)) {
    block++;
    const named = takePath(text.slice(cursor, m.index), isFile);
    prose.push(named.text);
    cursor = m.index + m[0].length;
    const filePath = named.path ?? defaultPath;
    const file = contentOf(filePath);
    if (file === undefined) {
      problems.push(
        `Block ${block}: \`${filePath}\` is not a file you can edit here. Write its path from the repository root, and edit only files that exist.`,
      );
      continue;
    }
    const search = dropLastNewline(m[1]);
    const replace = dropLastNewline(m[2]);
    if (search.trim() === "") {
      problems.push(
        `Block ${block}: SEARCH is empty. Put the existing line the new code goes next to in SEARCH, and repeat that line in REPLACE.`,
      );
      continue;
    }
    const fileLines = file.split("\n");
    const old = search.split("\n");
    const found = matches(fileLines, old);
    if (found.length === 0) {
      problems.push(
        file.includes(search)
          ? `Block ${block}: SEARCH copies part of a line. Copy whole lines from ${filePath}.`
          : `Block ${block}: the SEARCH lines do not occur in ${filePath}. Copy them from the file exactly, indentation included.`,
      );
      continue;
    }
    if (found.length > 1) {
      problems.push(
        `Block ${block}: the SEARCH lines occur ${found.length} times in ${filePath}. Add neighbouring lines until they match one place.`,
      );
      continue;
    }
    const neu = replace === "" ? [] : replace.split("\n");
    if (old.length === neu.length && old.every((line, k) => same(line, neu[k]))) {
      problems.push(`Block ${block}: REPLACE is the same as SEARCH, so the block changes nothing.`);
      continue;
    }
    // The file's own lines, not the model's copy of them.
    const start = found[0];
    hunks.push({
      block,
      file: filePath,
      start,
      old: fileLines.slice(start, start + old.length),
      neu,
    });
  }
  prose.push(text.slice(cursor));

  // The finding's file first, then the others in the order the model gave them.
  const files = [...new Set(hunks.map((h) => h.file))].sort(
    (a, b) => Number(b === defaultPath) - Number(a === defaultPath),
  );
  const byFile = files.map((file) => ({
    file,
    hunks: hunks.filter((h) => h.file === file).sort((a, b) => a.start - b.start),
  }));
  for (const { hunks: inFile } of byFile) {
    for (let i = 1; i < inFile.length; i++) {
      const prev = inFile[i - 1];
      if (inFile[i].start < prev.start + prev.old.length) {
        const [a, b] = [prev.block, inFile[i].block].sort((x, y) => x - y);
        problems.push(`Blocks ${a} and ${b} change the same lines. Merge them into one block.`);
      }
    }
  }

  const words = prose.map((part) => part.trim()).filter((part) => part !== "");
  if (words.some((part) => MARKER.test(part))) {
    problems.push(
      "A SEARCH/REPLACE block is not closed. Every block needs its <<<<<<< SEARCH, =======, and >>>>>>> REPLACE lines.",
    );
  } else if (words.some((part) => part.split("\n").some((line) => FENCE.test(line)))) {
    problems.push(
      "There is code outside a SEARCH/REPLACE block. Put every code change in a block, and use no other code fence.",
    );
  }
  if (problems.length > 0) return { kind: "rejected", problems };

  if (hunks.length === 0) return { kind: "fix", fix: words.join("\n\n"), edits: 0, files: [] };
  // The diffs go where the first block was: after the explanation.
  const lead = prose[0].trim();
  const rest = words.slice(lead === "" ? 0 : 1);
  const diffs = byFile.flatMap(({ file, hunks: inFile }) => {
    const { diff, places } = renderDiff(file, inFile);
    return [`**Location:** \`${file}\`, ${list(places)}`, diff];
  });
  const parts = [lead, ...diffs, ...rest].filter((part) => part !== "");
  return { kind: "fix", fix: parts.join("\n\n"), edits: hunks.length, files };
}
