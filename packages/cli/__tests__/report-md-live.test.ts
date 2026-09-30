import { describe, expect, it } from "vitest";
import { renderFindingMd } from "../src/reporters/md";

const f = {
  id: "x",
  agentSlug: "a",
  title: "t",
  vulnSlug: "xss",
  filePath: "p",
  summary: "s",
  details: "d",
  poc: "p",
  impact: "i",
  references: [],
  confidence: 0.5,
  notifications: [],
  validation: {
    verdict: "uncertain",
    reasoning: "r",
  },
  live: {
    result: "reproduced",
    reasoning: "reproduced in browser",
    counterevidence: "The redirect could also be a coincidental navigation.",
    evidence: {
      trace: "trace.zip",
      screenshots: [],
      script: { path: "repro.spec.ts", executed: true, passed: true },
    },
  },
} as any;
describe("renderFindingMd live validation", () => {
  it("renders the live validation section for a reproduced result", () => {
    const md = renderFindingMd(f);
    expect(md).toContain("### Live validation");
    expect(md).toContain("**Result:** `reproduced`");
    expect(md).toContain("reproduced in browser");
    expect(md).toContain(
      "**Counterevidence:** The redirect could also be a coincidental navigation.",
    );
    expect(md).toContain("repro.spec.ts");
  });

  it("calls a refuted finding's script a negative control, not a reproduction", () => {
    const refuted = {
      ...f,
      live: {
        result: "refuted",
        reasoning: "the payload was escaped",
        counterevidence: "",
        evidence: {
          trace: "trace.zip",
          screenshots: ["shot.png"],
          script: { path: "repro.spec.ts", executed: false, passed: false },
        },
      },
    };
    const md = renderFindingMd(refuted, undefined, "ev-dir");
    expect(md).toContain("**Result:** `refuted`");
    expect(md).toContain("- Negative control script: [repro.spec.ts](ev-dir/repro.spec.ts)");
    // "Reproduction script (unverified)" would read as a partial exploit.
    expect(md).not.toContain("Reproduction script");
    expect(md).toContain("- Trace: [trace.zip](ev-dir/trace.zip)");
    expect(md).not.toContain("- Video:");
  });

  it("renders the request table and links the full dump when requests were captured", () => {
    const withReqs = {
      ...f,
      live: {
        ...f.live,
        evidence: {
          ...f.live.evidence,
          requests: [
            { method: "GET", url: "http://app/notes/2", status: 200 },
            { method: "GET", url: "http://app/go?next=https://evil.com", status: 302 },
          ],
          requestsFile: "requests.http",
        },
      },
    };
    const md = renderFindingMd(withReqs, undefined, "ev-dir");
    expect(md).toContain("### Requests");
    expect(md).toContain("| GET | `http://app/notes/2` | 200 |");
    expect(md).toContain("| GET | `http://app/go?next=https://evil.com` | 302 |");
    expect(md).toContain("[requests.http](ev-dir/requests.http)");
  });
});

describe("renderFindingMd meta line and counterevidence", () => {
  it("prints no verdict when nothing settled one", () => {
    const md = renderFindingMd({
      ...f,
      validation: undefined,
      live: { result: "inconclusive", reasoning: "the login never completed", counterevidence: "" },
    });
    expect(md).toContain("**Validation:** _not settled_");
    expect(md).not.toContain("**Validation:** `uncertain`");
  });

  it("prints the combined verdict, not the static one", () => {
    const md = renderFindingMd({
      ...f,
      validation: { verdict: "false-positive", reasoning: "the token is checked" },
      live: {
        result: "reproduced",
        reasoning: "the forged POST went through",
        counterevidence: "",
      },
    });
    expect(md).toContain("**Validation:** `uncertain`");
  });

  it("skips the counterevidence line when the agent gave none", () => {
    const md = renderFindingMd({
      ...f,
      live: { ...f.live, counterevidence: "   " },
    });
    expect(md).not.toContain("**Counterevidence:**");
  });

  it("shows the control that separates the effect from the agent own setup", () => {
    const withControl = {
      ...f,
      live: {
        ...f.live,
        negativeControl: "Without the session cookie the same POST returned 401.",
      },
    } as any;
    expect(renderFindingMd(withControl)).toContain(
      "**Negative control:** Without the session cookie the same POST returned 401.",
    );
  });

  it("omits the control line when the agent reported none", () => {
    expect(renderFindingMd(f)).not.toContain("**Negative control:**");
  });
});
