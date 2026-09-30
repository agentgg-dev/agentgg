// The Playwright trace's `.network` file is JSONL of resource snapshots. These
// tests pin the parse and the .http rendering against that real shape.
import { describe, expect, it } from "vitest";
import {
  parseTraceRequests,
  renderRequestsHttp,
  requestBodyPreview,
  type TraceResources,
} from "../src/validation/trace-requests.js";

// One real-shaped resource-snapshot line, trimmed to the fields we read.
const line = (
  method: string,
  url: string,
  status: number,
  reqHeaders: [string, string][] = [],
  resHeaders: [string, string][] = [],
  extra: { postData?: unknown; content?: unknown } = {},
) =>
  JSON.stringify({
    type: "resource-snapshot",
    snapshot: {
      request: {
        method,
        url,
        headers: reqHeaders.map(([name, value]) => ({ name, value })),
        ...(extra.postData ? { postData: extra.postData } : {}),
      },
      response: {
        status,
        headers: resHeaders.map(([name, value]) => ({ name, value })),
        ...(extra.content ? { content: extra.content } : {}),
      },
    },
  });

// The real shape: Playwright leaves `text` empty and points at resources/.
const SQLI = "username=%27+OR+%271%27%3D%271%27+--&password=x";
const loginPost = (sha1: string) =>
  line("POST", "http://app/login", 302, [], [], {
    postData: {
      mimeType: "application/x-www-form-urlencoded",
      text: "",
      params: [
        { name: "username", value: "' OR '1'='1' --" },
        { name: "password", value: "x" },
      ],
      _sha1: sha1,
    },
  });

const resources = (entries: Record<string, string>): TraceResources =>
  new Map(Object.entries(entries).map(([k, v]) => [k, Buffer.from(v, "utf8")]));

describe("parseTraceRequests", () => {
  it("extracts method, url and status in order", () => {
    const net = [
      line("GET", "http://host.docker.internal:3000/notes/2", 200),
      line("GET", "http://host.docker.internal:3000/go?next=https://evil.com", 302),
    ].join("\n");

    expect(parseTraceRequests(net)).toEqual([
      {
        method: "GET",
        url: "http://host.docker.internal:3000/notes/2",
        status: 200,
        requestHeaders: [],
        responseHeaders: [],
      },
      {
        method: "GET",
        url: "http://host.docker.internal:3000/go?next=https://evil.com",
        status: 302,
        requestHeaders: [],
        responseHeaders: [],
      },
    ]);
  });

  it("keeps the cookie header verbatim, so an auth-scoped request proves who made it", () => {
    const net = line("GET", "http://app/notes/2", 200, [["Cookie", "user=alice"]]);
    expect(parseTraceRequests(net)[0]?.requestHeaders).toContainEqual({
      name: "Cookie",
      value: "user=alice",
    });
  });

  it("skips blank lines and non-request snapshots without throwing", () => {
    const net = [
      "",
      JSON.stringify({ type: "context-options" }),
      line("POST", "http://app/x", 201),
    ].join("\n");
    expect(parseTraceRequests(net).map((r) => r.method)).toEqual(["POST"]);
  });

  it("returns nothing for an empty trace", () => {
    expect(parseTraceRequests("")).toEqual([]);
  });

  // Without the body, every login attempt looks the same and nothing proves
  // which payload got in.
  it("reads the request body out of resources/ when postData.text is empty", () => {
    const net = loginPost("caf752.dat");
    const [r] = parseTraceRequests(net, resources({ "caf752.dat": SQLI }));
    expect(r?.requestBody).toBe(SQLI);
  });

  it("keeps the decoded form fields, because the wire body is percent-encoded", () => {
    const net = loginPost("caf752.dat");
    const [r] = parseTraceRequests(net, resources({ "caf752.dat": SQLI }));
    expect(r?.requestParams).toEqual([
      { name: "username", value: "' OR '1'='1' --" },
      { name: "password", value: "x" },
    ]);
  });

  it("prefers a non-empty postData.text over the resource", () => {
    const net = line("POST", "http://app/x", 200, [], [], {
      postData: { text: "a=1", _sha1: "other.dat" },
    });
    const [r] = parseTraceRequests(net, resources({ "other.dat": "IGNORED" }));
    expect(r?.requestBody).toBe("a=1");
  });

  it("reads the response body, which is the proof for a reflected payload", () => {
    const net = line("GET", "http://app/search?q=<script>", 200, [], [], {
      content: { mimeType: "text/html", _sha1: "page.html" },
    });
    const [r] = parseTraceRequests(net, resources({ "page.html": "<p><script>alert(1)</script>" }));
    expect(r?.responseBody).toContain("<script>alert(1)</script>");
  });

  it("names a binary response instead of inlining it", () => {
    const net = line("GET", "http://app/logo.png", 200, [], [], {
      content: { mimeType: "image/png", _sha1: "logo.png" },
    });
    const [r] = parseTraceRequests(net, resources({ "logo.png": "\u0089PNG binary" }));
    expect(r?.responseBody).toBeUndefined();
    expect(r?.responseBodyNote).toContain("image/png");
  });

  it("cuts an oversized response body and says so", () => {
    const big = "x".repeat(20_000);
    const net = line("GET", "http://app/big", 200, [], [], {
      content: { mimeType: "text/html", _sha1: "big.html" },
    });
    const [r] = parseTraceRequests(net, resources({ "big.html": big }));
    expect(r?.responseBody).toHaveLength(16_384);
    expect(r?.responseBodyNote).toContain("20000 bytes");
  });

  it("parses without resources, carrying headers only", () => {
    const [r] = parseTraceRequests(loginPost("caf752.dat"));
    expect(r?.requestBody).toBeUndefined();
    expect(r?.requestParams).toHaveLength(2);
  });
});

describe("renderRequestsHttp", () => {
  it("renders a replayable request/response block with all headers", () => {
    const http = renderRequestsHttp([
      {
        method: "GET",
        url: "http://app/notes/2",
        status: 200,
        requestHeaders: [{ name: "Cookie", value: "user=alice" }],
        responseHeaders: [{ name: "Content-Type", value: "text/html" }],
      },
    ]);
    expect(http).toContain("GET http://app/notes/2");
    expect(http).toContain("Cookie: user=alice");
    expect(http).toContain("< HTTP 200");
    expect(http).toContain("< Content-Type: text/html");
  });

  it("writes the wire body and the decoded payload above it", () => {
    const http = renderRequestsHttp(
      parseTraceRequests(loginPost("caf752.dat"), resources({ "caf752.dat": SQLI })),
    );
    expect(http).toContain("# username=' OR '1'='1' --");
    expect(http).toContain(SQLI);
  });

  it("prefixes the response body with `< `, like the response headers", () => {
    const http = renderRequestsHttp([
      {
        method: "GET",
        url: "http://app/x",
        status: 200,
        requestHeaders: [],
        responseHeaders: [],
        responseBody: "<b>hi</b>",
      },
    ]);
    expect(http).toContain("< <b>hi</b>");
  });
});

describe("requestBodyPreview", () => {
  const base = { method: "POST", url: "http://app/login", status: 302 };

  it("shows the decoded fields, not the percent-encoded wire body", () => {
    const preview = requestBodyPreview(
      {
        ...base,
        requestHeaders: [],
        responseHeaders: [],
        requestBody: SQLI,
        requestParams: [
          { name: "username", value: "' OR '1'='1' --" },
          { name: "password", value: "x" },
        ],
      },
      512,
    );
    expect(preview).toBe("username=' OR '1'='1' --&password=x");
  });

  it("falls back to the wire body when there are no form fields", () => {
    const preview = requestBodyPreview(
      { ...base, requestHeaders: [], responseHeaders: [], requestBody: '{"id":2}' },
      512,
    );
    expect(preview).toBe('{"id":2}');
  });

  it("truncates to the cap, so the mirrored record stays small", () => {
    const preview = requestBodyPreview(
      { ...base, requestHeaders: [], responseHeaders: [], requestBody: "y".repeat(600) },
      512,
    );
    expect(preview).toHaveLength(513);
    expect(preview?.endsWith("…")).toBe(true);
  });

  it("returns nothing for a body-less request", () => {
    expect(
      requestBodyPreview({ ...base, requestHeaders: [], responseHeaders: [] }, 512),
    ).toBeUndefined();
  });
});
