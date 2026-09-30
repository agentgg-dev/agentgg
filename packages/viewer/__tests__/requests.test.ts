// The evidence table reads `requests.http` back. These tests pin that round
// trip against the shape the CLI renderer writes.
import { describe, expect, it } from "vitest";
import {
  collapseRequests,
  isSecretHeader,
  parseHttpBlock,
  shortPath,
  splitHttpBlocks,
  toCurl,
} from "../app/lib/requests";

const LOGIN_BLOCK = [
  "# username=' OR '1'='1' --",
  "# password=x",
  "#",
  "POST http://host.docker.internal:3000/login",
  "Content-Type: application/x-www-form-urlencoded",
  "Cookie: user=alice",
  "",
  "username=%27+OR+%271%27%3D%271%27+--&password=x",
  "",
  "< HTTP 302",
  "< Location: /",
  "< set-cookie: user=admin; Path=/",
].join("\n");

const GET_BLOCK = [
  "GET http://app/notes/2",
  "Accept: text/html",
  "",
  "< HTTP 200",
  "< Content-Type: text/html",
  "<",
  "< <p>someone else's note</p>",
].join("\n");

describe("splitHttpBlocks", () => {
  it("splits on the separator the renderer writes", () => {
    expect(splitHttpBlocks(`${GET_BLOCK}\n\n###\n\n${LOGIN_BLOCK}\n`)).toHaveLength(2);
  });

  it("returns nothing for an empty file", () => {
    expect(splitHttpBlocks("")).toEqual([]);
  });
});

describe("parseHttpBlock", () => {
  it("reads the request line, headers and the wire body", () => {
    const x = parseHttpBlock(LOGIN_BLOCK)!;
    expect(x.method).toBe("POST");
    expect(x.url).toBe("http://host.docker.internal:3000/login");
    expect(x.requestHeaders).toContainEqual(["Cookie", "user=alice"]);
    expect(x.requestBody).toBe("username=%27+OR+%271%27%3D%271%27+--&password=x");
  });

  it("keeps the decoded payload the renderer wrote as comments", () => {
    expect(parseHttpBlock(LOGIN_BLOCK)!.decoded).toEqual([
      "username=' OR '1'='1' --",
      "password=x",
    ]);
  });

  it("reads the response status and headers", () => {
    const x = parseHttpBlock(LOGIN_BLOCK)!;
    expect(x.status).toBe(302);
    expect(x.responseHeaders).toContainEqual(["set-cookie", "user=admin; Path=/"]);
  });

  it("reads a response body, which is the proof for a data leak", () => {
    expect(parseHttpBlock(GET_BLOCK)!.responseBody).toBe("<p>someone else's note</p>");
  });

  it("handles a body-less request", () => {
    expect(parseHttpBlock(GET_BLOCK)!.requestBody).toBe("");
  });

  it("returns null for text that is not an exchange", () => {
    expect(parseHttpBlock("not an http block")).toBeNull();
  });
});

describe("toCurl", () => {
  it("builds a runnable command with the session header kept", () => {
    const curl = toCurl(parseHttpBlock(LOGIN_BLOCK)!);
    expect(curl).toContain("curl -i -X POST 'http://host.docker.internal:3000/login'");
    expect(curl).toContain("-H 'Cookie: user=alice'");
    expect(curl).toContain("--data-raw 'username=%27+OR+%271%27%3D%271%27+--&password=x'");
  });

  it("drops the headers the browser adds, which only add noise", () => {
    const x = parseHttpBlock(LOGIN_BLOCK)!;
    x.requestHeaders.push(["Host", "app"], ["Content-Length", "35"]);
    const curl = toCurl(x);
    expect(curl).not.toContain("Host:");
    expect(curl).not.toContain("Content-Length:");
  });

  it("escapes a quote in the payload so the command still runs", () => {
    const x = parseHttpBlock(GET_BLOCK)!;
    x.requestBody = "a='b'";
    expect(toCurl(x)).toContain(`--data-raw 'a='\\''b'\\'''`);
  });
});

describe("isSecretHeader", () => {
  it("catches the session headers whatever their case", () => {
    expect(isSecretHeader("cookie")).toBe(true);
    expect(isSecretHeader("Authorization")).toBe(true);
    expect(isSecretHeader("Accept")).toBe(false);
  });
});

describe("collapseRequests", () => {
  const get = (status = 200) => ({ method: "GET", url: "http://app/", status });
  const post = (body: string, status: number) => ({
    method: "POST",
    url: "http://app/login",
    status,
    requestBody: body,
  });

  it("folds a run of identical back-to-back page reads", () => {
    const rows = collapseRequests([get(), get(), get(), post("a=1", 401)]);
    expect(rows.map((r) => r.method)).toEqual(["GET", "POST"]);
  });

  // The order of a live run is the argument it makes: attempt failed, attempt
  // succeeded. Merging the two 302s into one row would erase that.
  it("keeps identical exchanges apart when something happened between them", () => {
    const rows = collapseRequests([post("a=1", 302), post("a=2", 401), post("a=1", 302)]);
    expect(rows).toHaveLength(3);
    expect(rows.map((r) => r.status)).toEqual([302, 401, 302]);
  });

  it("keeps two attempts apart when only the payload differs", () => {
    const rows = collapseRequests([post("a=1", 401), post("a=2", 302)]);
    expect(rows).toHaveLength(2);
  });

  it("keeps the first index, so the row still points at its block in the file", () => {
    const rows = collapseRequests([get(), get(), post("a=1", 302)]);
    expect(rows[1]?.index).toBe(2);
  });

  it("returns nothing for no requests", () => {
    expect(collapseRequests([])).toEqual([]);
  });
});

describe("shortPath", () => {
  it("drops the origin but keeps the query, where a payload often sits", () => {
    expect(shortPath("http://app:3000/go?next=https://evil.com")).toBe("/go?next=https://evil.com");
  });

  it("returns the input when it is not a URL", () => {
    expect(shortPath("not a url")).toBe("not a url");
  });
});
