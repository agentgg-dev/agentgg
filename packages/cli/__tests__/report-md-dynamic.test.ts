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
    dynamic: {
      verdict: "confirmed",
      reasoning: "reproduced in browser",
      evidence: {
        trace: "trace.zip",
        script: { path: "repro.spec.ts", executed: true, passed: true },
      },
    },
  },
} as any;
describe("renderFindingMd live validation", () => {
  it("renders the live validation section for a dynamic confirm", () => {
    const md = renderFindingMd(f);
    expect(md).toContain("### Live validation");
    expect(md).toContain("reproduced in browser");
    expect(md).toContain("repro.spec.ts");
  });

  it("renders the request table and links the full dump when requests were captured", () => {
    const withReqs = {
      ...f,
      validation: {
        ...f.validation,
        dynamic: {
          ...f.validation.dynamic,
          evidence: {
            ...f.validation.dynamic.evidence,
            requests: [
              { method: "GET", url: "http://app/notes/2", status: 200 },
              { method: "GET", url: "http://app/go?next=https://evil.com", status: 302 },
            ],
            requestsFile: "requests.http",
          },
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
