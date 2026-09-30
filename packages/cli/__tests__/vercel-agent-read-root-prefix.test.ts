/**
 * Models prefix the repository folder name onto a path that is already
 * relative to the root (`myrepo/src/a.ts`). Every such Read used to fail, and
 * the model spent a Glob and a second Read finding its way back.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildTools } from "../src/detectors/vercel-agent.js";

describe("Read with a repository-folder prefix", () => {
  let root: string;

  beforeEach(() => {
    root = join(mkdtempSync(join(tmpdir(), "agentgg-read-")), "myrepo");
    mkdirSync(join(root, "src"), { recursive: true });
    writeFileSync(join(root, "src", "a.ts"), "export const a = 1;\n", "utf8");
  });

  afterEach(() => rmSync(root, { recursive: true, force: true }));

  const tools = () =>
    buildTools({
      cwd: root,
      maxFileSizeKb: undefined,
      verbose: false,
      label: "validate:x",
      phase: "validate",
    });
  // biome-ignore lint/suspicious/noExplicitAny: exercising the SDK's call shape
  const read = (t: any, args: unknown) => t.Read.execute(args, {} as any) as Promise<string>;

  it("reads the file when the path repeats the root folder name", async () => {
    expect(await read(tools(), { path: "myrepo/src/a.ts" })).toContain("export const a = 1;");
  });

  it("reads it when the prefixed path uses backslashes", async () => {
    expect(await read(tools(), { path: "myrepo\\src\\a.ts" })).toContain("export const a = 1;");
  });

  it("prefers a real folder of the same name over the stripped path", async () => {
    mkdirSync(join(root, "myrepo", "src"), { recursive: true });
    writeFileSync(join(root, "myrepo", "src", "a.ts"), "export const nested = 1;\n", "utf8");

    expect(await read(tools(), { path: "myrepo/src/a.ts" })).toContain("export const nested = 1;");
  });

  it("names the path convention when the file is really missing", async () => {
    const out = await read(tools(), { path: "src/gone.ts" });

    expect(out).toMatch(/^Error/);
    expect(out).toContain("relative to the repository root");
    expect(out).not.toContain(root);
  });
});
