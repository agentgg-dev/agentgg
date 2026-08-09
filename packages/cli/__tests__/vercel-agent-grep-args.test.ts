/**
 * Tests for the `Grep` tool's argument schema in detectors/vercel-agent.ts.
 *
 * Why this exists: `glob` used to be a required `z.string()` while its own
 * description told the model to "pass an empty string to search all files". A
 * model that took the simpler reading and called `Grep({pattern})` had the call
 * rejected outright with `AI_InvalidToolArgumentsError`, and one that reached
 * for `path` (the sibling Read tool's parameter name) was rejected too. Both
 * shapes were observed in prod on Ghost-6.57.0 — 17 rejections in one 2h scan,
 * 13 in another — and each one burns a turn out of the batch budget while
 * returning nothing.
 *
 * `toSearchGlob` covers the second half: `walkAndMatch` only ever tests FILE
 * paths, so a bare directory handed straight through as a glob matches zero of
 * them, and its `matchBase` shortcut would reinterpret a slash-less path as a
 * basename match against the whole tree.
 *
 * Pure-function tests — no LLM calls.
 */
import { minimatch } from "minimatch";
import { describe, expect, it } from "vitest";
import { toSearchGlob } from "../src/detectors/vercel-agent.js";

describe("toSearchGlob", () => {
  it("widens a bare directory to match the files under it", () => {
    const g = toSearchGlob("ghost/core");
    expect(minimatch("ghost/core/server/api.js", g, { dot: true })).toBe(true);
    expect(minimatch("ghost/core/deeply/nested/file.ts", g, { dot: true })).toBe(true);
  });

  it("does not leak into sibling directories that share a prefix", () => {
    const g = toSearchGlob("ghost/core");
    expect(minimatch("ghost/core-utils/thing.js", g, { dot: true })).toBe(false);
    expect(minimatch("apps/admin/thing.js", g, { dot: true })).toBe(false);
  });

  it("still matches when the path names a single file", () => {
    const g = toSearchGlob("ghost/core/shared/config/defaults.json");
    expect(minimatch("ghost/core/shared/config/defaults.json", g, { dot: true })).toBe(true);
  });

  it("always contains a slash, so walkAndMatch never enables matchBase", () => {
    // A slash-less pattern would make walkAndMatch match by basename, turning
    // `path: "core"` into "every file in the repo named core".
    expect(toSearchGlob("Ghost-6.57.0")).toContain("/");
    expect(minimatch("some/other/Ghost-6.57.0", toSearchGlob("Ghost-6.57.0"), { dot: true })).toBe(
      false,
    );
  });

  it("passes an existing glob through untouched", () => {
    expect(toSearchGlob("**/*.ts")).toBe("**/*.ts");
    expect(toSearchGlob("src/**")).toBe("src/**");
  });

  it("tolerates trailing slashes and an empty path", () => {
    expect(toSearchGlob("ghost/core/")).toBe(toSearchGlob("ghost/core"));
    expect(toSearchGlob("")).toBe("**/*");
    expect(toSearchGlob("/")).toBe("**/*");
  });
});
