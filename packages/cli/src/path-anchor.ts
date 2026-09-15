import { excludeMatcher } from "./walker.js";

/**
 * Models write repo-relative paths, but the scan root can hold the repo
 * inside a top-level folder (a zip of the repo folder). A path that exists
 * is kept; one that does not gets the single top-level folder that holds
 * it. Several candidate folders are ambiguous, so the path stays as written.
 */
export interface PathAnchor {
  /** The anchored exclude glob, or null when it excludes nothing either way. */
  glob(pattern: string): string | null;
  /** `value` with each slash-separated path in it anchored. */
  text(value: string): string;
}

interface Entry {
  path: string;
  isDir: boolean;
}

// A path inside free text. The lookbehind stops a match inside a URL or a longer token.
const PATH_TOKEN = /(?<![\w.@/-])(?:[\w.@-]+\/)+[\w.@-]*/g;

export function createPathAnchor(files: string[]): PathAnchor {
  const dirs = new Set<string>();
  for (const f of files) {
    for (let i = f.indexOf("/"); i !== -1; i = f.indexOf("/", i + 1)) dirs.add(f.slice(0, i));
  }
  const known = new Set<string>([...files, ...dirs]);

  // Grouped by top-level folder, so a prefixed glob scans only its own folder.
  const all: Entry[] = [];
  const byTop = new Map<string, Entry[]>();
  const add = (entry: Entry) => {
    all.push(entry);
    const slash = entry.path.indexOf("/");
    if (slash === -1) return;
    const top = entry.path.slice(0, slash);
    const group = byTop.get(top);
    if (group) group.push(entry);
    else byTop.set(top, [entry]);
  };
  for (const d of dirs) add({ path: d, isDir: true });
  for (const f of files) add({ path: f, isDir: false });

  const excludes = (pattern: string, entries: Entry[]): boolean => {
    const m = excludeMatcher(pattern);
    return entries.some((e) => (e.isDir ? m.dir(e.path) : m.file(e.path)));
  };
  const soleTop = (holds: (top: string) => boolean): string | undefined => {
    const hits = [...byTop.keys()].filter(holds);
    return hits.length === 1 ? hits[0] : undefined;
  };

  return {
    glob(pattern) {
      if (excludes(pattern, all)) return pattern;
      const top = soleTop((t) => excludes(`${t}/${pattern}`, byTop.get(t) ?? []));
      return top === undefined ? null : `${top}/${pattern}`;
    },
    text(value) {
      return value.replace(PATH_TOKEN, (token) => {
        const path = token.replace(/\/+$/, "");
        if (known.has(path)) return token;
        const top = soleTop((t) => known.has(`${t}/${path}`));
        return top === undefined ? token : `${top}/${token}`;
      });
    },
  };
}
