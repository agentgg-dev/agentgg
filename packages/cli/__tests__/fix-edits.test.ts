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

const fix = (answer: string | undefined, file = FILE) => finishFix(answer, file, PATH);

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
      fix: [
        "Bind the value.",
        "",
        "```diff",
        "--- a/src/login.ts",
        "+++ b/src/login.ts",
        "@@ -3,1 +3,1 @@",
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
      ["@@ -2,2 +2,2 @@", "   const { username } = req.body;", `-${LOGIN}`, `+${BOUND}`].join("\n"),
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

  it("renders a block with an empty REPLACE as a deletion", () => {
    const result = fix(block(GO, ""));
    expect(result.kind === "fix" && result.fix).toContain(`@@ -8,1 +7,0 @@\n-${GO}`);
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
    expect(result.kind === "fix" && result.fix.startsWith("Bind the value.\n\n```diff")).toBe(true);
  });

  it("fences the diff with more backticks than the code in it has", () => {
    const file = "const doc = `\n```\nold\n```\n`;";
    const result = fix(block("```\nold\n```", "```\nnew\n```"), file);
    expect(result.kind === "fix" && result.fix.startsWith("````diff\n")).toBe(true);
  });

  it("keeps an answer in words only, with no block", () => {
    const answer = "The fix belongs in the session middleware, which this file does not show.";
    expect(fix(answer)).toEqual({ kind: "fix", edits: 0, fix: answer });
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
});
