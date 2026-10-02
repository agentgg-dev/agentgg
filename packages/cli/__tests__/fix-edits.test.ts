import { describe, expect, it } from "vitest";
import { finishFix } from "../src/fix-edits.js";

const PATH = "src/login.ts";
// biome-ignore lint/suspicious/noTemplateCurlyInString: the fixture is source code that holds a template literal
const LOGIN = "  const row = getOne(db, `SELECT * FROM users WHERE username='${username}'`);";
const BOUND = '  const row = getOne(db, "SELECT * FROM users WHERE username=?", [username]);';
const GO = 'app.get("/go", (req, res) => res.redirect(String(req.query.next ?? "/")));';
const FILE = [
  'app.post("/login", (req, res) => {',
  "  const { username } = req.body;",
  LOGIN,
  '  if (row) return res.redirect("/");',
  '  res.status(401).send("bad");',
  "});",
  "",
  GO,
].join("\n");

const block = (search: string, replace: string) =>
  `<<<<<<< SEARCH\n${search}\n=======\n${replace}\n>>>>>>> REPLACE`;

/** A repository that holds the one file PATH, plus any `others`. */
const repo =
  (file: string, others: Record<string, string> = {}) =>
  (path: string): string | undefined =>
    path === PATH ? file : others[path];

const fix = (answer: string | undefined, file = FILE, others: Record<string, string> = {}) =>
  finishFix(answer, repo(file, others), PATH);

/** The problems of an answer the check rejected. */
function problems(answer: string, file = FILE): string {
  const result = fix(answer, file);
  if (result.kind !== "rejected") throw new Error(`expected a rejection, got ${result.kind}`);
  return result.problems.join("\n");
}

describe("finishFix", () => {
  it("turns a block that matches the file into a diff at the line it matched", () => {
    const result = fix(`Bind the value.\n\n${block(LOGIN, BOUND)}\n\n- Rotate the passwords.`);

    expect(result).toEqual({
      kind: "fix",
      edits: 1,
      files: [PATH],
      fix: [
        "Bind the value.",
        "",
        "**Location:** `src/login.ts`, line 3",
        "",
        "```diff",
        "--- a/src/login.ts",
        "+++ b/src/login.ts",
        "@@ -3,1 +3,1 @@ line 3",
        `-${LOGIN}`,
        `+${BOUND}`,
        "```",
        "",
        "- Rotate the passwords.",
      ].join("\n"),
    });
  });

  it("shows lines the block repeats unchanged as context, not as changes", () => {
    const before = `  const { username } = req.body;\n${LOGIN}`;
    const result = fix(block(before, `  const { username } = req.body;\n${BOUND}`));

    expect(result.kind === "fix" && result.fix).toContain(
      [
        "@@ -2,2 +2,2 @@ line 3",
        "   const { username } = req.body;",
        `-${LOGIN}`,
        `+${BOUND}`,
      ].join("\n"),
    );
  });

  it("orders the hunks by position and shifts the later one by the lines added before it", () => {
    const go = block(GO, 'app.get("/go", (req, res) => {\n  res.redirect("/");\n});');
    const login = block(LOGIN, `  const params = [username];\n${BOUND}`);

    const result = fix(`${go}\n\n${login}`);

    expect(result.kind === "fix" && result.edits).toBe(2);
    const text = result.kind === "fix" ? result.fix : "";
    expect(text.indexOf("@@ -3,1 +3,2 @@")).toBeGreaterThan(-1);
    expect(text.indexOf("@@ -8,1 +9,3 @@")).toBeGreaterThan(text.indexOf("@@ -3,1 +3,2 @@"));
    // One diff for the file, not one per block.
    expect(text.match(/^--- a\//gm)).toHaveLength(1);
  });

  describe("location", () => {
    const location = (answer: string) => {
      const result = fix(answer);
      return result.kind === "fix" ? (/^\*\*Location:\*\* (.*)$/m.exec(result.fix)?.[1] ?? "") : "";
    };

    it("names every place the fix changes, in file order", () => {
      const answer = `${block(GO, 'app.get("/go", safeRedirect);')}\n\n${block(LOGIN, BOUND)}`;
      expect(location(answer)).toBe("`src/login.ts`, line 3 and line 8");
    });

    it("gives a range when several lines in a row change, and leaves out the context lines", () => {
      const before = [
        LOGIN,
        '  if (row) return res.redirect("/");',
        '  res.status(401).send("bad");',
      ];
      const after = [
        BOUND,
        '  if (row) return res.redirect("/home");',
        '  res.status(401).send("bad");',
      ];
      const answer = block(before.join("\n"), after.join("\n"));
      expect(location(answer)).toBe("`src/login.ts`, lines 3–4");
      expect(fix(answer).kind === "fix" && fix(answer)).toMatchObject({
        fix: expect.stringContaining("@@ -3,3 +3,3 @@ lines 3–4"),
      });
    });

    it("says after which line new code goes when the block only adds lines", () => {
      expect(location(block(LOGIN, `${LOGIN}\n  audit(username);`))).toBe(
        "`src/login.ts`, after line 3",
      );
    });

    it("says before which line new code goes when it comes ahead of the copied line", () => {
      expect(location(block(LOGIN, `  audit(username);\n${LOGIN}`))).toBe(
        "`src/login.ts`, before line 3",
      );
    });

    it("has no location line for an answer in words only", () => {
      const result = fix("The fix belongs in the session middleware.");
      expect(result.kind === "fix" && result.fix).not.toContain("Location");
    });
  });

  it("renders a block with an empty REPLACE as a deletion", () => {
    const result = fix(block(GO, ""));
    expect(result.kind === "fix" && result.fix).toContain(`@@ -8,1 +7,0 @@ line 8\n-${GO}`);
  });

  it("matches a file with CRLF line endings, and ignores trailing whitespace", () => {
    const result = fix(block(`${LOGIN}  `, BOUND), FILE.replace(/\n/g, "\r\n"));
    expect(result.kind).toBe("fix");
  });

  it("drops a code fence the model put around a block", () => {
    const result = fix(`Bind the value.\n\n\`\`\`ts\n${block(LOGIN, BOUND)}\n\`\`\``);
    const text = result.kind === "fix" ? result.fix : "";
    expect(text.match(/```/g)).toHaveLength(2);
    expect(text).toContain("```diff");
  });

  it("unwraps an answer the model put in one markdown fence", () => {
    const result = fix(`\`\`\`markdown\nBind the value.\n\n${block(LOGIN, BOUND)}\n\`\`\``);
    expect(result.kind === "fix" && result.fix.startsWith("Bind the value.\n\n**Location:**")).toBe(
      true,
    );
  });

  it("fences the diff with more backticks than the code in it has", () => {
    const file = "const doc = `\n```\nold\n```\n`;";
    const result = fix(block("```\nold\n```", "```\nnew\n```"), file);
    expect(result.kind === "fix" && result.fix.includes("\n\n````diff\n")).toBe(true);
  });

  it("keeps an answer in words only, with no block", () => {
    const answer = "The fix belongs in the session middleware, which this file does not show.";
    expect(fix(answer)).toEqual({ kind: "fix", edits: 0, files: [], fix: answer });
  });

  it.each([undefined, "", "  \n\t"])("reports a blank answer as empty", (answer) => {
    expect(fix(answer)).toEqual({ kind: "empty" });
  });

  it("rejects a block whose SEARCH lines are not in the file", () => {
    const text = problems(block("  const row = getOne(db, sql);", BOUND));
    expect(text).toContain("Block 1");
    expect(text).toContain("do not occur");
  });

  it("rejects a SEARCH that copies part of a line", () => {
    expect(problems(block("getOne(db,", "getOne(db, [username],"))).toContain("whole lines");
  });

  it("rejects a SEARCH that matches more than one place", () => {
    expect(problems(block("a", "c"), "a\nb\na")).toContain("occur 2 times");
  });

  it("rejects an empty SEARCH", () => {
    expect(problems(block("", "const x = 1;"))).toContain("SEARCH is empty");
  });

  it("rejects a block that changes nothing", () => {
    expect(problems(block(LOGIN, LOGIN))).toContain("same as SEARCH");
  });

  it("rejects blocks that change the same lines", () => {
    const text = problems(`${block(LOGIN, BOUND)}\n\n${block(LOGIN, "  const row = null;")}`);
    expect(text).toContain("Blocks 1 and 2");
  });

  it("rejects code that is not in a block, because nothing checks it against the file", () => {
    const text = problems("Bind the value.\n\n```ts\nconst row = getOne(db, sql, [id]);\n```");
    expect(text).toContain("SEARCH/REPLACE");
  });

  it("rejects a block that is not closed", () => {
    expect(problems(`<<<<<<< SEARCH\n${LOGIN}\n=======\n${BOUND}`)).toContain("not closed");
  });

  it("names every bad block, so one retry can fix them all", () => {
    const text = problems(`${block("nope", "x")}\n\n${block("", "y")}`);
    expect(text).toContain("Block 1");
    expect(text).toContain("Block 2");
  });

  describe("several files", () => {
    const DB = "src/db.ts";
    const DB_FILE = [
      "export function getOne(db, sql) {",
      "  return db.prepare(sql).get();",
      "}",
    ].join("\n");
    const PREPARE = "  return db.prepare(sql).get();";
    const others = { [DB]: DB_FILE };
    const inDb = block(PREPARE, "  return db.prepare(sql).get(...params);");

    it("checks a block against the file named on the line above it", () => {
      const result = fix(`Pass the params.\n\n${DB}\n${inDb}`, FILE, others);

      expect(result).toMatchObject({ kind: "fix", edits: 1, files: [DB] });
      const text = result.kind === "fix" ? result.fix : "";
      expect(text).toContain("**Location:** `src/db.ts`, line 2");
      expect(text).toContain("--- a/src/db.ts\n+++ b/src/db.ts\n@@ -2,1 +2,1 @@ line 2");
      // The path line is the block's label, not part of the explanation.
      expect(text.startsWith("Pass the params.\n\n**Location:**")).toBe(true);
    });

    it("gives each file its own location line and diff, the finding's file first", () => {
      const answer = `Bind and pass.\n\n${DB}\n${inDb}\n${PATH}\n${block(LOGIN, BOUND)}`;
      const result = fix(answer, FILE, others);

      expect(result).toMatchObject({ kind: "fix", edits: 2, files: [PATH, DB] });
      const text = result.kind === "fix" ? result.fix : "";
      expect(text.indexOf("**Location:** `src/login.ts`, line 3")).toBeGreaterThan(-1);
      expect(text.indexOf("**Location:** `src/db.ts`, line 2")).toBeGreaterThan(
        text.indexOf("+++ b/src/login.ts"),
      );
      expect(text.match(/```diff/g)).toHaveLength(2);
    });

    it("uses the finding's file for a block with no path line", () => {
      const result = fix(`Bind it.\n\n${block(LOGIN, BOUND)}\n${DB}\n${inDb}`, FILE, others);
      expect(result).toMatchObject({ kind: "fix", files: [PATH, DB] });
    });

    it.each([
      ["in backticks with a colon", "`src/db.ts`:"],
      ["in bold", "**src/db.ts**"],
      ["with backslashes", "src\\db.ts"],
      ["with a leading ./", "./src/db.ts"],
    ])("reads a path written %s", (_how, line) => {
      expect(fix(`${line}\n${inDb}`, FILE, others)).toMatchObject({ kind: "fix", files: [DB] });
    });

    it("reads a path line that is inside the code fence around the block", () => {
      const result = fix(`Pass the params.\n\n\`\`\`ts\n${DB}\n${inDb}\n\`\`\``, FILE, others);
      expect(result).toMatchObject({ kind: "fix", files: [DB] });
    });

    it("rejects a block for a file that is not in the repository", () => {
      const text = problems(`src/missing.ts\n${inDb}`);
      expect(text).toContain("Block 1");
      expect(text).toContain("`src/missing.ts` is not a file");
    });

    it("does not call the same line numbers in two files an overlap", () => {
      const first = block(
        "export function getOne(db, sql) {",
        "export function getOne(db, sql, params) {",
      );
      const answer = `${block('app.post("/login", (req, res) => {', "// login")}\n${DB}\n${first}`;
      expect(fix(answer, FILE, others).kind).toBe("fix");
    });

    it("keeps a last word of the explanation that is not a file as text", () => {
      const result = fix(`Bind the value, then you are\ndone.\n${block(LOGIN, BOUND)}`);
      expect(result.kind === "fix" && result.fix).toContain("done.");
      expect(result).toMatchObject({ files: [PATH] });
    });
  });
});
