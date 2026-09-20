import type { Finding } from "@agentgg/core";
import { normalizeVulnSlug } from "./web-reachable.js";

const GENERIC = `- Show the vulnerable behavior you observed, not only that a page or an
  endpoint responded.
- Run one negative control: the same steps without the attacker's input, or
  without the session, and show that the result differs.`;

const RULES: Record<string, string> = {
  csrf: `- The request MUST come from a different origin than the target. A request
  the target's own page sends proves nothing here.
- The victim's session must carry the request. Run the same request
  without the victim's session: if it still succeeds, the bug is missing
  authorization, not CSRF, so the result is 'inconclusive'.`,
  idor: `- Use one account to read or change another account's object, and show the
  data belongs to the other account.
- Negative control: the same request with no session, or with a random id,
  must not return the other account's data.`,
  xss: `- Show the injected script executing in the page, not only reflected text.
- Negative control: a benign value in the same parameter must render as text.`,
  "sql-injection": `- Show a response that only a database-level change of the query explains,
  for example a different row set or a database error naming the syntax.
- Negative control: the same request with the payload escaped must behave
  normally.`,
  "open-redirect": `- Show the target issuing a redirect to the external host you supplied.
- Negative control: an internal path in the same parameter must stay internal.`,
};

const BY_CWE: Record<number, string> = {
  352: "csrf",
  639: "idor",
  862: "idor",
  863: "idor",
  79: "xss",
  89: "sql-injection",
  601: "open-redirect",
};

export function proofRulesFor(finding: Finding): string {
  for (const ref of finding.references ?? []) {
    for (const m of ref.matchAll(/\bCWE-(\d+)\b/gi)) {
      const key = BY_CWE[Number(m[1])];
      if (key) return RULES[key] as string;
    }
  }
  return RULES[normalizeVulnSlug(finding.vulnSlug)] ?? GENERIC;
}
