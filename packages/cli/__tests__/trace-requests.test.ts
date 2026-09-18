// The Playwright trace's `.network` file is JSONL of resource snapshots. These
// tests pin the parse and the .http rendering against that real shape.
import { describe, expect, it } from "vitest";
import { parseTraceRequests, renderRequestsHttp } from "../src/validation/trace-requests.js";

// One real-shaped resource-snapshot line, trimmed to the fields we read.
const line = (
  method: string,
  url: string,
  status: number,
  reqHeaders: [string, string][] = [],
  resHeaders: [string, string][] = [],
) =>
  JSON.stringify({
    type: "resource-snapshot",
    snapshot: {
      request: { method, url, headers: reqHeaders.map(([name, value]) => ({ name, value })) },
      response: { status, headers: resHeaders.map(([name, value]) => ({ name, value })) },
    },
  });

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
});
