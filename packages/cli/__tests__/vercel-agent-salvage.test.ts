/**
 * Tests for the two recovery helpers added after the 2026-08-26 staging scan,
 * where GLM-5.2 reached the right verdict, broke the JSON delimiters, then
 * repeated the object until the parser gave up.
 *
 * Both helpers are pure string functions, so no LLM call is involved. The
 * degenerate fixture below is shaped like the real staging response.
 */

import { describe, expect, it } from "vitest";
import { forReformat, salvageVerdict } from "../src/detectors/vercel-agent.js";

/** One copy of the broken object the model emitted: commas where the JSON
 *  delimiters belong, so no parser accepts it. */
const BROKEN_OBJECT =
  `{"verdict","confirmed","reasoning","The DELETE handler in src/api/users.ts:12-18 ` +
  `reads id directly from request.json() and passes it to the query builder with no ` +
  `ownership check, so any authenticated caller deletes any row.","confidence","0.95"}`;

describe("salvageVerdict", () => {
  it("reads a verdict out of the comma-for-colon shape", () => {
    expect(salvageVerdict(BROKEN_OBJECT)).toBe("confirmed");
  });

  it("reads a verdict out of well-formed JSON", () => {
    expect(salvageVerdict(`{"verdict":"false-positive","reasoning":"Guarded."}`)).toBe(
      "false-positive",
    );
  });

  it("survives the repetition loop, since every copy agrees", () => {
    expect(salvageVerdict(BROKEN_OBJECT.repeat(40))).toBe("confirmed");
  });

  it("takes the LAST match, so an echoed format example never wins", () => {
    // validationJsonInstruction() shows {"verdict":"confirmed",…} as its
    // example. A model that restates the format before answering would hand a
    // first-match reader that example instead of its real verdict.
    const echoed =
      `Output your verdict as a single JSON object matching EXACTLY this shape:\n` +
      `{"verdict":"confirmed","reasoning":"Short reasoning.","confidence":0.9}\n\n` +
      `{"verdict","out-of-scope","reasoning","The scope file excludes test fixtures."}`;
    expect(salvageVerdict(echoed)).toBe("out-of-scope");
  });

  it("returns null when no verdict appears, so the caller rethrows", () => {
    expect(salvageVerdict("I was unable to complete this analysis.")).toBeNull();
    expect(salvageVerdict("")).toBeNull();
  });

  it("ignores a value outside the verdict enum", () => {
    expect(salvageVerdict(`{"verdict":"probably-fine"}`)).toBeNull();
  });
});

describe("forReformat", () => {
  it("passes short text through untouched", () => {
    expect(forReformat(BROKEN_OBJECT)).toBe(BROKEN_OBJECT);
  });

  it("cuts a repetition loop down to one copy", () => {
    const looped = BROKEN_OBJECT.repeat(40);
    const trimmed = forReformat(looped);
    expect(trimmed).toBe(BROKEN_OBJECT);
    expect(trimmed.length).toBeLessThan(looped.length / 10);
  });

  it("keeps the head, because the first copy is the real answer", () => {
    expect(forReformat(BROKEN_OBJECT.repeat(40)).startsWith(`{"verdict","confirmed"`)).toBe(true);
  });

  it("caps non-repeating text and marks the cut", () => {
    // Distinct lines: nothing repeats, so only the length cap applies.
    const long = Array.from({ length: 400 }, (_, i) => `line ${i} of unique analysis prose`).join(
      "\n",
    );
    const trimmed = forReformat(long);
    expect(trimmed.length).toBeLessThan(long.length);
    expect(trimmed.endsWith("[truncated]")).toBe(true);
  });

  it("leaves genuine analysis prose alone", () => {
    const prose = "The handler validates ownership before the delete. No issue found.";
    expect(forReformat(prose)).toBe(prose);
  });
});
