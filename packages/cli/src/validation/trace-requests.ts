// Turn the Playwright trace's `.network` JSONL into the HTTP exchanges a
// reviewer needs, and render them as a replayable .http file. This is what
// makes live validation useful for an API with no visible UI: the video shows
// nothing, but the request and its response are the proof.

export interface TraceHeader {
  name: string;
  value: string;
}

export interface TraceRequest {
  method: string;
  url: string;
  status: number;
  requestHeaders: TraceHeader[];
  responseHeaders: TraceHeader[];
}

interface SnapshotHeader {
  name?: unknown;
  value?: unknown;
}

function headers(raw: unknown): TraceHeader[] {
  if (!Array.isArray(raw)) return [];
  const out: TraceHeader[] = [];
  for (const h of raw as SnapshotHeader[]) {
    if (typeof h?.name === "string") out.push({ name: h.name, value: String(h.value ?? "") });
  }
  return out;
}

/** Parse the network JSONL. One request per resource snapshot, in order. */
export function parseTraceRequests(networkText: string): TraceRequest[] {
  const out: TraceRequest[] = [];
  for (const rawLine of networkText.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    let obj: {
      snapshot?: { request?: Record<string, unknown>; response?: Record<string, unknown> };
    };
    try {
      obj = JSON.parse(line);
    } catch {
      continue;
    }
    const req = obj.snapshot?.request;
    if (!req || typeof req.method !== "string" || typeof req.url !== "string") continue;
    const res = obj.snapshot?.response;
    out.push({
      method: req.method,
      url: req.url,
      status: typeof res?.status === "number" ? res.status : 0,
      requestHeaders: headers(req.headers),
      responseHeaders: headers(res?.headers),
    });
  }
  return out;
}

/** Render the exchanges as a `.http` file: the request line, its headers, then
 *  the response status and headers, replayable and complete. */
export function renderRequestsHttp(requests: TraceRequest[]): string {
  const blocks = requests.map((r) => {
    const lines = [`${r.method} ${r.url}`];
    for (const h of r.requestHeaders) lines.push(`${h.name}: ${h.value}`);
    lines.push("");
    lines.push(`< HTTP ${r.status}`);
    for (const h of r.responseHeaders) lines.push(`< ${h.name}: ${h.value}`);
    return lines.join("\n");
  });
  return `${blocks.join("\n\n###\n\n")}\n`;
}
