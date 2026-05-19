import { describe, expect, it } from "vitest";
import { listChangedFiles } from "../src/diff.js";

describe("listChangedFiles", () => {
  it("parses a clean git output into an array of paths", () => {
    const fakeGit = () => "src/login.ts\npublic/app.js\nserver.js\n";
    const out = listChangedFiles("abc123", "/repo", fakeGit);
    expect(out).toEqual(["src/login.ts", "public/app.js", "server.js"]);
  });

  it("trims blank lines and whitespace", () => {
    const fakeGit = () => "\n  src/foo.ts  \n\n\nsrc/bar.ts\n\n";
    const out = listChangedFiles("abc", "/repo", fakeGit);
    expect(out).toEqual(["src/foo.ts", "src/bar.ts"]);
  });

  it("returns empty array when nothing changed", () => {
    const fakeGit = () => "";
    expect(listChangedFiles("abc", "/repo", fakeGit)).toEqual([]);
  });

  it("propagates a friendly error when git is missing (ENOENT)", () => {
    const fakeGit = () => {
      const err = new Error("spawn git ENOENT") as Error & { code?: string };
      err.code = "ENOENT";
      throw err;
    };
    expect(() => listChangedFiles("abc", "/repo", fakeGit)).toThrow(/spawn git ENOENT/);
  });

  it("propagates errors from git verbatim (e.g. bad commit SHA)", () => {
    const fakeGit = () => {
      const err = new Error("fatal: bad object zzz") as Error & { stderr?: string };
      err.stderr = "fatal: bad object zzz";
      throw err;
    };
    expect(() => listChangedFiles("zzz", "/repo", fakeGit)).toThrow(/bad object zzz/);
  });
});
