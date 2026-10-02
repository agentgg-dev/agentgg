import { describe, expect, it } from "vitest";
import { diffLineKinds } from "../app/lib/diff";

describe("diffLineKinds", () => {
  it("tells the file header, the hunk header, and added, removed and unchanged lines apart", () => {
    const lines = [
      "--- a/src/server.ts",
      "+++ b/src/server.ts",
      "@@ -66,4 +66,5 @@ line 68",
      "     const row = getOne(",
      "-      `SELECT * FROM users`,",
      '+      "SELECT * FROM users WHERE id=?",',
      "+      [id],",
      "     );",
    ];
    expect(diffLineKinds(lines)).toEqual([
      "file",
      "file",
      "hunk",
      "context",
      "del",
      "add",
      "add",
      "context",
    ]);
  });

  it("reads a removed SQL comment and an added line of plus signs as changes, not as file headers", () => {
    const lines = [
      "--- a/q.sql",
      "+++ b/q.sql",
      "@@ -1,2 +1,2 @@ lines 1–2",
      "--- old note",
      "+++ new",
    ];
    expect(diffLineKinds(lines).slice(3)).toEqual(["del", "add"]);
  });

  it("treats an empty line inside a hunk as unchanged", () => {
    expect(diffLineKinds(["@@ -1,1 +1,1 @@", ""])).toEqual(["hunk", "context"]);
  });
});
