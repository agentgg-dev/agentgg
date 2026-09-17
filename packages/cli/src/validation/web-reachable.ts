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

export function normalizeVulnSlug(slug: string): string {
  const s = slug.trim().toLowerCase();
  return ALIASES[s] ?? s;
}
export function isWebReachable(f: Finding): boolean {
  if (f.dedup) return false;
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
  console.log(
    `  live validation: skipped ${skipped.length} finding(s) (not web-reachable or duplicate)`,
  );
}
