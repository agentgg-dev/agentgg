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
  /** Raw wire body, so the rendered .http replays exactly what was sent. */
  requestBody?: string;
  /** Playwright's decoded form fields. The readable view of `requestBody`:
   *  the wire form is percent-encoded, which hides the payload from a reader. */
  requestParams?: TraceHeader[];
  responseBody?: string;
  /** Set when the response body was dropped or cut. Explains the gap. */
  responseBodyNote?: string;
}

/** Trace-zip `resources/` entries keyed by the name a snapshot `_sha1` holds. */
export type TraceResources = Map<string, Buffer>;

/** Response bodies are unbounded. Keep enough to prove a reflection or a leak
 *  without writing a megabyte of markup per exchange. */
const MAX_RESPONSE_BODY = 16_384;

const TEXTUAL = /^(text\/|application\/(json|javascript|xml|xhtml|x-www-form-urlencoded))/i;

interface SnapshotHeader {
  name?: unknown;
  value?: unknown;
}

interface PostData {
  text?: unknown;
  params?: unknown;
  _sha1?: unknown;
  mimeType?: unknown;
}

interface ResponseContent {
  _sha1?: unknown;
  mimeType?: unknown;
  size?: unknown;
}

function headers(raw: unknown): TraceHeader[] {
  if (!Array.isArray(raw)) return [];
  const out: TraceHeader[] = [];
  for (const h of raw as SnapshotHeader[]) {
    if (typeof h?.name === "string") out.push({ name: h.name, value: String(h.value ?? "") });
  }
  return out;
}

function resource(resources: TraceResources | undefined, sha1: unknown): Buffer | undefined {
  return typeof sha1 === "string" && sha1 ? resources?.get(sha1) : undefined;
}

/** Playwright empties `postData.text` and stores the body in `resources/`, so
 *  the sha1 lookup is the usual path, not the fallback. */
function requestBody(post: PostData | undefined, resources?: TraceResources): string | undefined {
  if (!post) return undefined;
  if (typeof post.text === "string" && post.text) return post.text;
  return resource(resources, post._sha1)?.toString("utf8");
}

function requestParams(post: PostData | undefined): TraceHeader[] | undefined {
  if (!Array.isArray(post?.params)) return undefined;
  const out = headers(post.params);
  return out.length > 0 ? out : undefined;
}

function responseBody(
  content: ResponseContent | undefined,
  resources?: TraceResources,
): Pick<TraceRequest, "responseBody" | "responseBodyNote"> {
  const buf = resource(resources, content?._sha1);
  if (!buf) return {};
  const mime = typeof content?.mimeType === "string" ? content.mimeType : "";
  if (mime && !TEXTUAL.test(mime)) {
    return { responseBodyNote: `[${mime} body, ${buf.length} bytes, not shown]` };
  }
  if (buf.length > MAX_RESPONSE_BODY) {
    return {
      responseBody: buf.subarray(0, MAX_RESPONSE_BODY).toString("utf8"),
      responseBodyNote: `[cut after ${MAX_RESPONSE_BODY} of ${buf.length} bytes]`,
    };
  }
  return { responseBody: buf.toString("utf8") };
}

/**
 * Parse the network JSONL. One request per resource snapshot, in order.
 * `resources` comes from the trace zip; without it the exchanges carry headers
 * only, which cannot show which payload was sent.
 */
export function parseTraceRequests(
  networkText: string,
  resources?: TraceResources,
): TraceRequest[] {
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
    const body = requestBody(req.postData as PostData | undefined, resources);
    const params = requestParams(req.postData as PostData | undefined);
    out.push({
      method: req.method,
      url: req.url,
      status: typeof res?.status === "number" ? res.status : 0,
      requestHeaders: headers(req.headers),
      responseHeaders: headers(res?.headers),
      ...(body ? { requestBody: body } : {}),
      ...(params ? { requestParams: params } : {}),
      ...responseBody(res?.content as ResponseContent | undefined, resources),
    });
  }
  return out;
}

/** The decoded payload a reviewer reads, for example
 *  `username=' OR '1'='1' --`. Only worth printing when it differs from the
 *  wire body, which is percent-encoded. */
function decodedComment(r: TraceRequest): string[] {
  if (!r.requestParams) return [];
  const lines = r.requestParams.map((p) => `# ${p.name}=${p.value}`);
  return [...lines, "#"];
}

/** Render the exchanges as a `.http` file: the request line, its headers and
 *  body, then the response status, headers and body. Replayable and complete. */
export function renderRequestsHttp(requests: TraceRequest[]): string {
  const blocks = requests.map((r) => {
    const lines = [...decodedComment(r), `${r.method} ${r.url}`];
    for (const h of r.requestHeaders) lines.push(`${h.name}: ${h.value}`);
    lines.push("");
    if (r.requestBody) lines.push(r.requestBody, "");
    lines.push(`< HTTP ${r.status}`);
    for (const h of r.responseHeaders) lines.push(`< ${h.name}: ${h.value}`);
    if (r.responseBody || r.responseBodyNote) {
      lines.push("<");
      for (const l of (r.responseBody ?? "").split("\n")) lines.push(`< ${l}`);
      if (r.responseBodyNote) lines.push(`< ${r.responseBodyNote}`);
    }
    return lines.join("\n");
  });
  return `${blocks.join("\n\n###\n\n")}\n`;
}

/** The short, readable payload for the finding record and the list view.
 *  Prefers the decoded fields; the wire body is percent-encoded. */
export function requestBodyPreview(r: TraceRequest, max: number): string | undefined {
  const text = r.requestParams
    ? r.requestParams.map((p) => `${p.name}=${p.value}`).join("&")
    : r.requestBody;
  if (!text) return undefined;
  return text.length > max ? `${text.slice(0, max)}…` : text;
}
