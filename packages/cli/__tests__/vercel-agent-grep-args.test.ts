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
 * The schema then went the other way and broke OpenAI: `.optional()` drops the
 * key from `required`, which OpenAI's strict function schemas forbid, so every
 * batch and recon died on a 400. Nullable-but-required serves both.
 *
 * `toSearchGlob` covers the second half: `walkAndMatch` only ever tests FILE
 * paths, so a bare directory handed straight through as a glob matches zero of
 * them, and its `matchBase` shortcut would reinterpret a slash-less path as a
 * basename match against the whole tree.
 *
 * Pure-function tests — no LLM calls.
 */
import { zodSchema } from "ai";
import { minimatch } from "minimatch";
import { describe, expect, it } from "vitest";
import { GrepParameters, toSearchGlob } from "../src/detectors/vercel-agent.js";

describe("GrepParameters", () => {
  // The exact JSON Schema @ai-sdk sends as the tool's `parameters`.
  const schema = zodSchema(GrepParameters).jsonSchema as {
    properties: Record<string, { type: string | string[] }>;
    required: string[];
    additionalProperties: boolean;
  };

  it("satisfies OpenAI strict mode: every property is required", () => {
    // With `strict: true` — the @ai-sdk/openai default for reasoning models —
    // a property missing from `required` fails the request with HTTP 400
    // invalid_function_parameters, killing every batch and recon.
    expect([...schema.required].sort()).toEqual(Object.keys(schema.properties).sort());
    expect(schema.additionalProperties).toBe(false);
  });

  it("expresses optionality as a null union, not an absent key", () => {
    expect(schema.properties.glob.type).toEqual(["string", "null"]);
    expect(schema.properties.path.type).toEqual(["string", "null"]);
  });

  it("still accepts a call that omits both scoping arguments", () => {
    // Non-strict providers omit the key rather than sending null.
    expect(GrepParameters.parse({ pattern: "eval\\(" })).toEqual({
      pattern: "eval\\(",
      glob: null,
      path: null,
    });
  });

  it("accepts explicit nulls, a glob, or a path", () => {
    expect(GrepParameters.parse({ pattern: "x", glob: null, path: null })).toEqual({
      pattern: "x",
      glob: null,
      path: null,
    });
    expect(GrepParameters.parse({ pattern: "x", glob: "**/*.ts" })).toMatchObject({
      glob: "**/*.ts",
    });
    expect(GrepParameters.parse({ pattern: "x", path: "src/api" })).toMatchObject({
      path: "src/api",
    });
  });

  it("still rejects a call with no pattern", () => {
    expect(GrepParameters.safeParse({ glob: "**/*.ts" }).success).toBe(false);
  });
});

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
