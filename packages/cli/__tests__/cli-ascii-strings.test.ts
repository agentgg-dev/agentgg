// Guard: no em dash, en dash, or Unicode ellipsis in the recon command's
// user-visible strings. Comments are stripped first, so prose is unaffected.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const FILES = ["../src/commands/recon.ts", "../src/precondition.ts"];

function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

describe.each(FILES)("%s", (rel) => {
  it("uses ASCII punctuation in its user-visible strings", () => {
    const src = readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
    const offenders = stripComments(src)
      .split("\n")
      .map((line, i) => ({ line, n: i + 1 }))
      .filter(({ line }) => /[—–…]/.test(line))
      .map((o) => `${o.n}: ${o.line.trim()}`);
    expect(offenders).toEqual([]);
  });
});
