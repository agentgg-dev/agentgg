import type { Finding } from "@agentgg/core";

const ALIASES: Record<string, string> = {
  sqli: "sql-injection",
  "sql-inj": "sql-injection",
  xss: "xss",
  "cross-site-scripting": "xss",
  "reflected-xss": "xss",
  "stored-xss": "xss",
  idor: "idor",
  "insecure-direct-object-reference": "idor",
  "broken-access-control": "idor",
  ssrf: "ssrf",
  "open-redirect": "open-redirect",
  csrf: "csrf",
  "path-traversal": "path-traversal",
  "directory-traversal": "path-traversal",
  "auth-bypass": "auth-bypass",
  "authentication-bypass": "auth-bypass",
  "command-injection": "command-injection",
  rce: "command-injection",
};
const WEB_REACHABLE = new Set([
  "sql-injection",
  "xss",
  "idor",
  "ssrf",
  "open-redirect",
  "csrf",
  "path-traversal",
  "auth-bypass",
  "command-injection",
]);

// CWE is a controlled vocabulary, so it is checked first; `vulnSlug` is free
// text and the same class arrives under many spellings.
const WEB_REACHABLE_CWES = new Set([
  22, // path traversal
  77, // command injection
  78, // OS command injection
  79, // XSS
  89, // SQL injection
  284, // improper access control
  285, // improper authorization
  287, // improper authentication
  352, // CSRF
  601, // open redirect
  639, // IDOR: authorization bypass through a user-controlled key
  862, // missing authorization
  863, // incorrect authorization
  918, // SSRF
]);

export function normalizeVulnSlug(slug: string): string {
  const s = slug.trim().toLowerCase();
  return ALIASES[s] ?? s;
}

function cweIds(references: readonly string[]): number[] {
  const ids: number[] = [];
  for (const ref of references) {
    for (const m of ref.matchAll(/\bCWE-(\d+)\b/gi)) ids.push(Number(m[1]));
  }
  return ids;
}

export function isWebReachable(f: Finding): boolean {
  if (f.dedup) return false;
  if (cweIds(f.references ?? []).some((id) => WEB_REACHABLE_CWES.has(id))) return true;
  return WEB_REACHABLE.has(normalizeVulnSlug(f.vulnSlug));
}
export function selectWebReachable(findings: Finding[]) {
  const selected: Finding[] = [];
  const skipped: Finding[] = [];
  for (const f of findings) (isWebReachable(f) ? selected : skipped).push(f);
  return { selected, skipped };
}
export function logSkips(skipped: Finding[]): void {
  if (skipped.length === 0) return;
  console.log(`  live validation: skipped ${skipped.length} finding(s) (not web-reachable)`);
}
