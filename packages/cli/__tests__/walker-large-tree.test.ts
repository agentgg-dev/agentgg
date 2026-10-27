import { basename } from "node:path";
import { describe, expect, it, vi } from "vitest";

// More files under one folder than V8 accepts as spread arguments (~125k).
const FILE_COUNT = 200_000;
const bigDir = Array.from({ length: FILE_COUNT }, (_, i) => `f${i}.ts`);

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    readdirSync: (dir: string) => (basename(dir) === "big" ? bigDir : ["big"]),
    statSync: (p: string) => {
      const isFile = /^f\d+\.ts$/.test(basename(p));
      return { isDirectory: () => !isFile, isFile: () => isFile, size: 1 };
    },
  };
});

const { collectAllFiles } = await import("../src/walker.js");

describe("collectAllFiles on a very large tree", () => {
  it("returns every file without a stack overflow", () => {
    const files = collectAllFiles("/virtual-root");
    expect(files).toHaveLength(FILE_COUNT);
    expect(files[0]).toBe("big/f0.ts");
  });
});
