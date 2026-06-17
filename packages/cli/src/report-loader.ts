import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, extname, resolve } from "node:path";

/**
 * One past-incident report on disk, ready to feed the create agent.
 */
export interface LoadedReport {
  /** Absolute path to the report file. */
  path: string;
  /** Filename (no directory), used for diagnostics and slug fallbacks. */
  name: string;
  /** Full report text, UTF-8. */
  content: string;
}

const ALLOWED_EXTS = new Set([".md", ".txt"]);

/**
 * Resolve one user-supplied `--report` value into a list of report files.
 *
 *   - `.md` / `.txt` file      → that one file
 *   - directory                → every `.md` / `.txt` file inside (non-recursive)
 *   - `.txt` list file (its NAME contains "list" or "reports", OR every
 *     non-comment line is itself an existing path) is expanded line-by-line.
 *     We auto-detect this AFTER reading because a `.txt` may be a report
 *     OR a list. The check is: if every non-blank, non-comment line resolves
 *     to an existing file/dir, treat it as a list.
 *
 * Throws if nothing resolves to a real report.
 */
export function loadReports(reportInput: string): LoadedReport[] {
  const abs = resolve(reportInput);
  let st: ReturnType<typeof statSync>;
  try {
    st = statSync(abs);
  } catch {
    throw new Error(`--report: no such file or directory: ${reportInput}`);
  }

  if (st.isDirectory()) {
    return loadFromDir(abs);
  }

  const ext = extname(abs).toLowerCase();
  if (!ALLOWED_EXTS.has(ext)) {
    throw new Error(`--report: unsupported file type ${ext} (only .md and .txt are supported)`);
  }

  if (ext === ".txt" && looksLikeListFile(abs)) {
    return expandListFile(abs, new Set([abs]));
  }

  return [readReport(abs)];
}

function loadFromDir(dirAbs: string): LoadedReport[] {
  const out: LoadedReport[] = [];
  for (const name of readdirSync(dirAbs)) {
    const full = `${dirAbs}/${name}`.replace(/\\/g, "/");
    let s: ReturnType<typeof statSync>;
    try {
      s = statSync(full);
    } catch {
      continue;
    }
    if (!s.isFile()) continue;
    if (!ALLOWED_EXTS.has(extname(name).toLowerCase())) continue;
    out.push(readReport(full));
  }
  if (out.length === 0) {
    throw new Error(`--report: no .md or .txt files found in ${dirAbs}`);
  }
  return out;
}

function expandListFile(absListPath: string, seen: Set<string>): LoadedReport[] {
  const content = readFileSync(absListPath, "utf8");
  const out: LoadedReport[] = [];
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const lineAbs = resolve(line);
    if (seen.has(lineAbs)) continue;
    seen.add(lineAbs);

    let s: ReturnType<typeof statSync>;
    try {
      s = statSync(lineAbs);
    } catch {
      throw new Error(
        `--report: list file ${basename(absListPath)} references missing path: ${line}`,
      );
    }
    if (s.isDirectory()) {
      out.push(...loadFromDir(lineAbs));
      continue;
    }
    const ext = extname(lineAbs).toLowerCase();
    if (!ALLOWED_EXTS.has(ext)) {
      throw new Error(
        `--report: list file ${basename(absListPath)} references unsupported file type ${ext}: ${line}`,
      );
    }
    if (ext === ".txt" && looksLikeListFile(lineAbs)) {
      out.push(...expandListFile(lineAbs, seen));
    } else {
      out.push(readReport(lineAbs));
    }
  }
  if (out.length === 0) {
    throw new Error(`--report: list file ${basename(absListPath)} resolved to no reports`);
  }
  return out;
}

function readReport(absPath: string): LoadedReport {
  const content = readFileSync(absPath, "utf8");
  if (content.trim().length === 0) {
    throw new Error(`--report: ${absPath} is empty`);
  }
  return {
    path: absPath,
    name: basename(absPath),
    content,
  };
}

/**
 * Heuristic: is this `.txt` a list of report paths rather than the report
 * itself? True when every non-blank, non-comment line resolves to an
 * existing file or directory on disk. An empty file is NOT a list.
 *
 * This is deliberately strict — a single bad line means "treat as report"
 * so we never silently swallow report content as filenames.
 */
function looksLikeListFile(absPath: string): boolean {
  let content: string;
  try {
    content = readFileSync(absPath, "utf8");
  } catch {
    return false;
  }
  const lines = content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("#"));
  if (lines.length === 0) return false;
  for (const line of lines) {
    try {
      statSync(resolve(line));
    } catch {
      return false;
    }
  }
  return true;
}
