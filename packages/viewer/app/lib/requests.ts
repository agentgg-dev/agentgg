// Read `requests.http` back into the parts the evidence table needs. The
// finding record carries only method, URL, status and a truncated payload;
// the full headers and the response body stay in the file, which the local
// evidence route serves.

export interface HttpExchange {
  method: string;
  url: string;
  /** Decoded form fields the renderer wrote as `# name=value` comments. */
  decoded: string[];
  requestHeaders: [string, string][];
  requestBody: string;
  status: number;
  responseHeaders: [string, string][];
  responseBody: string;
}

const BLOCK_SEPARATOR = /\n###\n/;
const REQUEST_LINE = /^([A-Z]+) (\S+)$/;

/** Split the file into one string per exchange, in capture order. */
export function splitHttpBlocks(text: string): string[] {
  return text
    .split(BLOCK_SEPARATOR)
    .map((b) => b.trim())
    .filter(Boolean);
}

export function parseHttpBlock(block: string): HttpExchange | null {
  const lines = block.split("\n");
  const decoded: string[] = [];
  let i = 0;
  for (; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (!line.startsWith("#")) break;
    const text = line.slice(1).trim();
    if (text) decoded.push(text);
  }

  const match = lines[i]?.match(REQUEST_LINE);
  if (!match) return null;
  i++;

  const requestHeaders = readHeaders(lines, i, "");
  i = requestHeaders.next;

  // Everything up to the response marker is the body, blank lines included.
  const bodyLines: string[] = [];
  for (; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (line.startsWith("< HTTP ")) break;
    bodyLines.push(line);
  }

  const status = Number(lines[i]?.slice("< HTTP ".length) ?? 0);
  i++;
  const responseHeaders = readHeaders(lines, i, "< ");
  i = responseHeaders.next;
  if (lines[i] === "<") i++; // The bare marker between response headers and body.

  const [, method = "", url = ""] = match;
  return {
    method,
    url,
    decoded,
    requestHeaders: requestHeaders.headers,
    requestBody: bodyLines.join("\n").trim(),
    status: Number.isFinite(status) ? status : 0,
    responseHeaders: responseHeaders.headers,
    responseBody: lines
      .slice(i)
      .map((l) => (l.startsWith("< ") ? l.slice(2) : l))
      .join("\n")
      .trim(),
  };
}

function readHeaders(lines: string[], from: number, prefix: string) {
  const headers: [string, string][] = [];
  let i = from;
  for (; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (prefix && !line.startsWith(prefix)) break;
    const text = line.slice(prefix.length);
    if (!text.trim()) {
      if (!prefix) i++; // Consume the blank line that ends a request head.
      break;
    }
    const at = text.indexOf(": ");
    if (at < 0) break;
    headers.push([text.slice(0, at), text.slice(at + 2)]);
  }
  return { headers, next: i };
}

/** Headers that carry a live session. Shown, but marked, so nobody pastes
 *  one into a ticket by accident. */
const SECRET_HEADERS = new Set(["cookie", "authorization", "x-api-key", "proxy-authorization"]);

export function isSecretHeader(name: string): boolean {
  return SECRET_HEADERS.has(name.toLowerCase());
}

// Headers the browser adds that add noise to a hand-run command.
const CURL_SKIP = new Set(["host", "content-length", "connection", "accept-encoding"]);

function shellQuote(value: string): string {
  return `'${value.split("'").join(`'\\''`)}'`;
}

/** The exchange as a command a developer can paste into a terminal. This is
 *  the point of the evidence table: a finding they can run, not read about. */
export function toCurl(x: HttpExchange): string {
  const parts = [`curl -i -X ${x.method} ${shellQuote(x.url)}`];
  for (const [name, value] of x.requestHeaders) {
    if (CURL_SKIP.has(name.toLowerCase())) continue;
    parts.push(`  -H ${shellQuote(`${name}: ${value}`)}`);
  }
  if (x.requestBody) parts.push(`  --data-raw ${shellQuote(x.requestBody)}`);
  return parts.join(" \\\n");
}

export interface CollapsedRequest {
  /** Index into the original list, which is also the block index in the file. */
  index: number;
  method: string;
  url: string;
  status: number;
  requestBody?: string;
}

/**
 * Fold a run of identical back-to-back exchanges into one row. Only adjacent
 * ones: the order of a live run is the argument it makes, so an attempt that
 * failed and the later one that succeeded must stay where they happened.
 */
export function collapseRequests(
  requests: readonly { method: string; url: string; status: number; requestBody?: string }[],
): CollapsedRequest[] {
  const key = (r: { method: string; url: string; status: number; requestBody?: string }) =>
    `${r.method} ${r.url} ${r.status} ${r.requestBody ?? ""}`;
  const out: CollapsedRequest[] = [];
  let previous: string | undefined;
  requests.forEach((r, index) => {
    const k = key(r);
    if (k === previous) return;
    previous = k;
    out.push({ index, ...r });
  });
  return out;
}

/** The path and query a reviewer scans down the table, not the whole URL. */
export function shortPath(url: string): string {
  try {
    const u = new URL(url);
    return `${u.pathname}${u.search}`;
  } catch {
    return url;
  }
}
