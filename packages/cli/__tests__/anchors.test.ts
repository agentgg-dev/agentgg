import { describe, expect, it } from "vitest";
import {
  anchorLoad,
  packBatches,
  shardCandidate,
  shardKeyOf,
  toLocations,
} from "../src/anchors.js";
import type { AgentCandidate } from "../src/detect.js";
import type { PreFilterHit } from "../src/pre-filter.js";

function hit(line: number, label = "r", endLine?: number): PreFilterHit {
  return { line, label, snippet: `line ${line}`, ...(endLine !== undefined ? { endLine } : {}) };
}

function candidate(filePath: string, hits: PreFilterHit[]): AgentCandidate {
  return { filePath, content: "x\n".repeat(600), hits };
}

describe("toLocations", () => {
  it("collapses hits that point at the same line", () => {
    const locs = toLocations([hit(7, "regex-a"), hit(7, "semgrep-b"), hit(9)]);
    expect(locs.length).toBe(2);
    expect(locs[0].hits.length).toBe(2);
  });

  it("keeps a ranged anchor separate from a single-line one", () => {
    const locs = toLocations([hit(7), hit(7, "r", 12)]);
    expect(locs.length).toBe(2);
  });

  it("sorts by line regardless of build order", () => {
    // Real hits arrive pattern-major, then semgrep appended — never sorted.
    const locs = toLocations([hit(40), hit(2), hit(17)]);
    expect(locs.map((l) => l.line)).toEqual([2, 17, 40]);
  });
});

describe("anchorLoad", () => {
  it("charges once for several patterns matching one line", () => {
    expect(anchorLoad(candidate("a.ts", [hit(3, "a"), hit(3, "b"), hit(3, "c")]))).toBe(1);
  });
});

describe("shardCandidate", () => {
  const many = Array.from({ length: 500 }, (_, i) => hit(i + 1));

  it("returns the same object untouched when the file is under the cap", () => {
    const c = candidate("a.ts", [hit(5), hit(1)]);
    const shards = shardCandidate(c, 150);
    expect(shards.length).toBe(1);
    // Identity matters: an unsharded scan must render byte-identical prompts,
    // which means the original hit order survives.
    expect(shards[0]).toBe(c);
  });

  it("splits an over-cap file into contiguous line ranges", () => {
    const shards = shardCandidate(candidate("a.ts", many), 50);
    expect(shards.length).toBe(10);
    expect(shards[0].hits[0].line).toBe(1);
    expect(shards[0].hits.at(-1)?.line).toBe(50);
    expect(shards[1].hits[0].line).toBe(51);
    expect(shards.at(-1)?.hits.at(-1)?.line).toBe(500);
  });

  it("covers every anchor exactly once", () => {
    const shards = shardCandidate(candidate("a.ts", many), 33);
    const lines = shards.flatMap((s) => s.hits.map((h) => h.line));
    expect(lines.length).toBe(500);
    expect(new Set(lines).size).toBe(500);
  });

  it("never splits when the cap is disabled", () => {
    expect(shardCandidate(candidate("a.ts", many), Number.POSITIVE_INFINITY).length).toBe(1);
  });
});

describe("shardKeyOf", () => {
  it("gives disjoint shards of one file distinct keys", () => {
    const shards = shardCandidate(
      candidate(
        "a.ts",
        Array.from({ length: 120 }, (_, i) => hit(i + 1)),
      ),
      50,
    );
    const keys = shards.map(shardKeyOf);
    expect(new Set(keys).size).toBe(keys.length);
    expect(keys[0]).toBe("1-50:50");
  });

  it("is stable across rebuilds of the same candidate", () => {
    const hits = [hit(9), hit(2), hit(2, "other")];
    expect(shardKeyOf(candidate("a.ts", hits))).toBe(shardKeyOf(candidate("a.ts", [...hits])));
  });

  it("changes when the anchor set shifts, so a stale cut cannot resume", () => {
    const before = shardKeyOf(candidate("a.ts", [hit(1), hit(2)]));
    const after = shardKeyOf(candidate("a.ts", [hit(1), hit(2), hit(3)]));
    expect(before).not.toBe(after);
  });
});

describe("packBatches", () => {
  const light = (name: string) => candidate(name, [hit(1), hit(2)]);

  it("matches the fixed slice it replaces when the anchor cap is off", () => {
    const items = ["a", "b", "c", "d", "e", "f", "g"].map(light);
    const batches = packBatches(items, 5, Number.POSITIVE_INFINITY);
    expect(batches.map((b) => b.length)).toEqual([5, 2]);
  });

  it("closes a batch early when the anchor ceiling binds first", () => {
    const dense = (name: string) =>
      candidate(
        name,
        Array.from({ length: 40 }, (_, i) => hit(i + 1)),
      );
    const batches = packBatches([dense("a"), dense("b"), dense("c")], 5, 50);
    expect(batches.map((b) => b.length)).toEqual([1, 1, 1]);
  });

  it("keeps two shards of one file out of the same batch", () => {
    const shards = shardCandidate(
      candidate(
        "big.ts",
        Array.from({ length: 300 }, (_, i) => hit(i + 1)),
      ),
      100,
    );
    const batches = packBatches(shards, 5, 100);
    expect(batches.length).toBe(3);
    for (const b of batches) expect(b.length).toBe(1);
  });

  it("still emits an oversized candidate rather than dropping it", () => {
    const huge = candidate(
      "huge.ts",
      Array.from({ length: 80 }, (_, i) => hit(i + 1)),
    );
    const batches = packBatches([huge], 5, 10);
    expect(batches.length).toBe(1);
    expect(batches[0][0]).toBe(huge);
  });
});
