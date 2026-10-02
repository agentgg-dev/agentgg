/**
 * The text-only check on a suggested fix. The model writes its code changes
 * as SEARCH/REPLACE blocks; each SEARCH must match exactly one place in the
 * scanned file. Blocks that pass are rendered as one unified diff, so every
 * line of code the report shows is known to apply to the file as scanned.
 * That is all it proves: the check says nothing about whether the fix is right.
 */

export type FixResult =
  /** `fix` is the Markdown to store. `edits` is 0 for an answer in words only. */
  | { kind: "fix"; fix: string; edits: number }
  | { kind: "empty" }
  /** `problems` is written for the model: it is sent back for one retry. */
  | { kind: "rejected"; problems: string[] };

const FENCE = /^ {0,3}(`{3,}|~{3,})(.*)$/;

// A block, with the code fence a model often puts around it.
const BLOCK =
  /^(?:[ \t]*(?:`{3,}|~{3,})[^\n]*\n)?<{5,9} ?SEARCH[ \t]*\n([\s\S]*?)^={5,9}[ \t]*\n([\s\S]*?)^>{5,9} ?REPLACE[ \t]*(?:\n[ \t]*(?:`{3,}|~{3,})[ \t]*(?=\n|$))?/gm;

const MARKER = /^(?:<{5,9} ?SEARCH|>{5,9} ?REPLACE)\b/m;

interface Hunk {
  /** 1-based position of the block in the answer, for the problem text. */
  block: number;
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

function renderDiff(filePath: string, hunks: Hunk[]): string {
  const body = [`--- a/${filePath}`, `+++ b/${filePath}`];
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
    const newStart = start + 1 + shift;
    body.push(
      `@@ -${start + 1},${old.length} +${neu.length === 0 ? newStart - 1 : newStart},${neu.length} @@`,
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
  return `${fence}diff\n${text}\n${fence}`;
}

/**
 * Check the model's answer against the file and build the Markdown to store.
 * `fileContent` is the file the prompt showed; `filePath` labels the diff.
 */
export function finishFix(
  answer: string | undefined,
  fileContent: string,
  filePath: string,
): FixResult {
  const text = unwrap((answer ?? "").replace(/\r\n/g, "\n"));
  if (text.trim() === "") return { kind: "empty" };

  const file = fileContent.replace(/\r\n/g, "\n");
  const fileLines = file.split("\n");
  const problems: string[] = [];
  const hunks: Hunk[] = [];
  const prose: string[] = [];
  let cursor = 0;
  let block = 0;
  for (const m of text.matchAll(BLOCK)) {
    block++;
    prose.push(text.slice(cursor, m.index));
    cursor = m.index + m[0].length;
    const search = dropLastNewline(m[1]);
    const replace = dropLastNewline(m[2]);
    if (search.trim() === "") {
      problems.push(
        `Block ${block}: SEARCH is empty. Put the existing line the new code goes next to in SEARCH, and repeat that line in REPLACE.`,
      );
      continue;
    }
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
    hunks.push({ block, start, old: fileLines.slice(start, start + old.length), neu });
  }
  prose.push(text.slice(cursor));

  hunks.sort((a, b) => a.start - b.start);
  for (let i = 1; i < hunks.length; i++) {
    const prev = hunks[i - 1];
    if (hunks[i].start < prev.start + prev.old.length) {
      const [a, b] = [prev.block, hunks[i].block].sort((x, y) => x - y);
      problems.push(`Blocks ${a} and ${b} change the same lines. Merge them into one block.`);
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

  if (hunks.length === 0) return { kind: "fix", fix: words.join("\n\n"), edits: 0 };
  // The diff goes where the first block was: after the explanation.
  const lead = prose[0].trim();
  const rest = words.slice(lead === "" ? 0 : 1);
  const parts = [lead, renderDiff(filePath, hunks), ...rest].filter((part) => part !== "");
  return { kind: "fix", fix: parts.join("\n\n"), edits: hunks.length };
}
