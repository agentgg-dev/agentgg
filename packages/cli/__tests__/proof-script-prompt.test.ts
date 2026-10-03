import { describe, expect, it } from "vitest";
import { buildProofScriptPrompt } from "../src/detect";
import { PROOF_PRINCIPLE } from "../src/validation/proof-rules";
import { CONTROL_TEST, EXPLOIT_TEST } from "../src/validation/proof-script";

const finding = {
  id: "f1",
  agentSlug: "xss",
  vulnSlug: "xss",
  title: "Reflected XSS in /search",
  filePath: "src/server.ts",
  lineRange: [31, 33],
  summary: "s",
  poc: "GET /search?q=<script>alert(1)</script>",
  impact: "i",
  references: ["CWE-79"],
} as never;

describe("buildProofScriptPrompt", () => {
  it("names both tests the runner reads back by title", () => {
    const p = buildProofScriptPrompt(finding, "http://t");
    expect(p).toContain(`test("${EXPLOIT_TEST}"`);
    expect(p).toContain(`test("${CONTROL_TEST}"`);
  });

  it("states the proof principle", () => {
    expect(buildProofScriptPrompt(finding, "http://t")).toContain(PROOF_PRINCIPLE);
  });

  it("carries the reporting agent's own rule when the catalog declares one", () => {
    const rule = "The request MUST come from a different origin than the target.";
    expect(buildProofScriptPrompt(finding, "http://t", undefined, rule)).toContain(rule);
  });

  it("tells the model to go straight to the endpoint rather than explore", () => {
    expect(buildProofScriptPrompt(finding, "http://t")).toMatch(/do not (explore|crawl)/i);
  });

  it("carries the target and the PoC the script has to drive", () => {
    const p = buildProofScriptPrompt(finding, "http://target.test");
    expect(p).toContain("http://target.test");
    expect(p).toContain("GET /search?q=<script>alert(1)</script>");
  });

  it("asks for the spec source alone, with no prose around it", () => {
    expect(buildProofScriptPrompt(finding, "http://t")).toMatch(/no prose|nothing else|only the/i);
  });

  it("tells the model to prove reflection in the raw response, not only a dialog", () => {
    const out = buildProofScriptPrompt(finding, "http://t");
    expect(out).toMatch(/page.request.get/);
    expect(out).toMatch(/unescaped|UNESCAPED/);
  });

  it("gives a breakout technique for a script-context reflection", () => {
    expect(buildProofScriptPrompt(finding, "http://t")).toContain("</script>");
  });

  it("offers a reliable execution sensor instead of relying on the dialog event", () => {
    const out = buildProofScriptPrompt(finding, "http://t");
    expect(out).toContain("__xssFired");
    expect(out).toContain("addInitScript");
  });

  it("explains that a browser navigation cannot set a request header", () => {
    expect(buildProofScriptPrompt(finding, "http://t")).toMatch(/header/i);
    expect(buildProofScriptPrompt(finding, "http://t")).toContain(
      "page.request.get(url, { headers",
    );
  });

  it("asks for pacing so the recording is watchable, not a sub-second blur", () => {
    const out = buildProofScriptPrompt(finding, "http://t");
    expect(out).toContain("slowMo");
    expect(out).toContain("waitForTimeout");
  });

  it("opens a page before any page.request call, so the recording does not start blank", () => {
    const out = buildProofScriptPrompt(finding, "http://t");
    expect(out).toMatch(/Open a page with `page\.goto\(\.\.\.\)` before any `page\.request` call/);
    expect(out).toContain("after the init scripts above");
  });

  it("sends an input a page can send through that page, so the recording shows it go in", () => {
    const out = buildProofScriptPrompt(finding, "http://t");
    expect(out).toContain("send the attack through that page");
    expect(out).toContain("page.fill(");
  });

  it("forbids the test to set session state itself, since that state proves nothing", () => {
    const out = buildProofScriptPrompt(finding, "http://t");
    expect(out).toContain("Do not set a session cookie or other state yourself");
    expect(out).toContain("context.addCookies");
  });

  it("keeps page.request for what a page cannot send and for the raw-response check", () => {
    expect(buildProofScriptPrompt(finding, "http://t")).toMatch(
      /Use `page\.request` only for what a page cannot send/,
    );
  });

  it("tests only this finding, whatever the notes about the target describe", () => {
    const p = buildProofScriptPrompt(finding, "http://t", "Sign in at /login as alice.");
    expect(p).toContain("Sign in at /login as alice.");
    expect(p).toContain("Prove only the finding below, through the input it names.");
  });

  it("omits the notes section when the target came with no notes", () => {
    expect(buildProofScriptPrompt(finding, "http://t")).not.toContain(
      "Notes about the application",
    );
  });

  it("does not count a reflection the browser never runs as cross-site scripting", () => {
    const out = buildProofScriptPrompt(finding, "http://t");
    expect(out).not.toMatch(/either one alone counts/i);
    expect(out).toContain("Reflection alone is not the effect");
  });

  it("forbids the test to draw its own proof on the page", () => {
    expect(buildProofScriptPrompt(finding, "http://t")).toContain(
      "Do not add your own banner, overlay or label to the page.",
    );
  });
});
