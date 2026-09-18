// Fake-sandbox tests for the evidence copy. The real thing needs Docker, so
// these model /out as a path -> bytes map and assert the copy's decisions.

import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import AdmZip from "adm-zip";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { clearSandboxOut, copyEvidence } from "../src/validation/reproduce.js";
import type { Sandbox } from "../src/validation/sandbox.js";

/**
 * Minimal /out model. `files` maps an absolute container path to its bytes, in
 * oldest-first insertion order, which is what `ls -1t` reverses.
 */
function fakeSandbox(files: Map<string, Buffer>): Sandbox & { files: Map<string, Buffer> } {
  const under = (dir: string) =>
    [...files.keys()].filter(
      (p) => p.startsWith(`${dir}/`) && !p.slice(dir.length + 1).includes("/"),
    );
  return {
    files,
    browserEndpoint: () => "http://localhost:8931/sse",
    async exec(cmd) {
      const line = cmd.join(" ");
      if (line.startsWith("ls -1t /out")) {
        // Newest first: reverse insertion order.
        const names = under("/out").map((p) => p.slice("/out/".length));
        return { code: 0, stdout: `${names.reverse().join("\n")}\n`, stderr: "" };
      }
      if (line.includes("find /out/traces")) {
        const hits = [...files.keys()].filter((p) => p.startsWith("/out/traces/"));
        if (hits.length === 0) return { code: 1, stdout: "", stderr: "no such dir" };
        return { code: 0, stdout: `${hits.join("\n")}\n`, stderr: "" };
      }
      if (line.includes("rm -rf")) {
        for (const p of [...files.keys()]) if (p.startsWith("/out/")) files.delete(p);
        return { code: 0, stdout: "", stderr: "" };
      }
      return { code: 0, stdout: "", stderr: "" };
    },
    async readFile(path) {
      const buf = files.get(path);
      if (!buf) throw new Error(`no such file: ${path}`);
      return buf;
    },
    async writeFile() {},
    async logs() {
      return "";
    },
    async dispose() {},
  };
}

const FAST = { videoWaitMs: 60, pollMs: 5 };

describe("copyEvidence", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "agentgg-evidence-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("records the newest video, not the oldest left over from an earlier finding", async () => {
    const sb = fakeSandbox(
      new Map([
        ["/out/page-2026-09-18T05-06-29-556Z.webm", Buffer.from("older finding")],
        ["/out/page-2026-09-18T05-07-18-157Z.webm", Buffer.from("this finding")],
      ]),
    );
    const ev = await copyEvidence(sb, dir, FAST);
    expect(ev.video).toBe("page-2026-09-18T05-07-18-157Z.webm");
  });

  it("captures the playwright trace directory as a zip", async () => {
    const sb = fakeSandbox(
      new Map([
        ["/out/page-a.webm", Buffer.from("vid")],
        ["/out/traces/trace-1789708818297.trace", Buffer.from("trace events")],
        ["/out/traces/trace-1789708818297.network", Buffer.from("")],
        ["/out/traces/resources/page@abc-123.jpeg", Buffer.from("jpeg bytes")],
      ]),
    );
    const ev = await copyEvidence(sb, dir, FAST);

    expect(ev.trace).toBe("trace.zip");
    const zipPath = join(dir, "trace.zip");
    expect(existsSync(zipPath)).toBe(true);
    const entries = new AdmZip(zipPath)
      .getEntries()
      .map((e) => e.entryName)
      .sort();
    expect(entries).toEqual([
      "resources/page@abc-123.jpeg",
      "trace-1789708818297.network",
      "trace-1789708818297.trace",
    ]);
    // The trace dir itself must not be copied out as loose files.
    expect(readdirSync(dir)).not.toContain("traces");
  });

  it("leaves trace unset when the session wrote no trace", async () => {
    const sb = fakeSandbox(new Map([["/out/page-a.webm", Buffer.from("vid")]]));
    const ev = await copyEvidence(sb, dir, FAST);
    expect(ev.trace).toBeUndefined();
  });

  it("waits for a video that is still being flushed when the copy starts", async () => {
    const files = new Map<string, Buffer>([["/out/shot.png", Buffer.from("png")]]);
    const sb = fakeSandbox(files);
    // Playwright writes the video when the page closes, which can land after
    // the agent's turn has already returned.
    setTimeout(() => files.set("/out/page-late.webm", Buffer.from("late video")), 20);

    const ev = await copyEvidence(sb, dir, FAST);
    expect(ev.video).toBe("page-late.webm");
    expect(readFileSync(join(dir, "page-late.webm"), "utf8")).toBe("late video");
  });

  it("gives up waiting when the session produced no video at all", async () => {
    const sb = fakeSandbox(new Map([["/out/shot.png", Buffer.from("png")]]));
    const ev = await copyEvidence(sb, dir, FAST);
    expect(ev.video).toBeUndefined();
    expect(ev.screenshots).toEqual(["shot.png"]);
  });

  it("pulls the HTTP exchanges out of the trace and writes a replayable dump", async () => {
    const snap = JSON.stringify({
      type: "resource-snapshot",
      snapshot: {
        request: {
          method: "GET",
          url: "http://app/notes/2",
          headers: [{ name: "Cookie", value: "user=alice" }],
        },
        response: { status: 200, headers: [{ name: "Content-Type", value: "text/html" }] },
      },
    });
    const sb = fakeSandbox(
      new Map([
        ["/out/page-a.webm", Buffer.from("vid")],
        ["/out/traces/trace-1.trace", Buffer.from("t")],
        ["/out/traces/trace-1.network", Buffer.from(snap)],
      ]),
    );
    const ev = await copyEvidence(sb, dir, FAST);

    expect(ev.requests).toEqual([{ method: "GET", url: "http://app/notes/2", status: 200 }]);
    expect(ev.requestsFile).toBe("requests.http");
    const http = readFileSync(join(dir, "requests.http"), "utf8");
    expect(http).toContain("GET http://app/notes/2");
    // "show everything": the real cookie is in the linked file.
    expect(http).toContain("Cookie: user=alice");
  });

  it("leaves requests unset when the trace has no network data", async () => {
    const sb = fakeSandbox(new Map([["/out/page-a.webm", Buffer.from("vid")]]));
    const ev = await copyEvidence(sb, dir, FAST);
    expect(ev.requests).toBeUndefined();
    expect(ev.requestsFile).toBeUndefined();
  });
});

describe("clearSandboxOut", () => {
  it("empties /out so the next finding cannot inherit these artifacts", async () => {
    const sb = fakeSandbox(
      new Map([
        ["/out/page-a.webm", Buffer.from("vid")],
        ["/out/shot.png", Buffer.from("png")],
        ["/out/traces/trace-1.trace", Buffer.from("t")],
      ]),
    );
    await clearSandboxOut(sb);
    expect([...sb.files.keys()]).toEqual([]);
  });
});
