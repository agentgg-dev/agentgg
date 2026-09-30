// Fake-sandbox tests for the evidence copy. The real thing needs Docker, so
// these model /out as a path -> bytes map and assert the copy's decisions.

import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync as writeFileSyncNode,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import AdmZip from "adm-zip";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  clearSandboxOut,
  copyEvidence,
  evidenceName,
  orderScreenshots,
} from "../src/validation/reproduce.js";
import type { Sandbox } from "../src/validation/sandbox.js";

/**
 * Minimal /out model. `files` maps an absolute container path to its bytes, in
 * oldest-first insertion order, which is what `ls -1t` reverses.
 */
function fakeSandbox(files: Map<string, Buffer>): Sandbox & { files: Map<string, Buffer> } {
  return {
    files,
    browserEndpoint: () => "http://localhost:8931/sse",
    async exec(cmd) {
      const line = cmd.join(" ");
      if (line.includes("find /out -type f") && line.includes("-printf")) {
        // Recursive, newest first, excluding the trace dir — the real command's
        // shape. Newest first is reverse insertion order; timestamps descend.
        const paths = [...files.keys()].filter(
          (p) => p.startsWith("/out/") && !p.includes("/traces/"),
        );
        const out = paths
          .reverse()
          .map((p, i) => `${1000 - i} ${p}`)
          .join("\n");
        return { code: 0, stdout: `${out}\n`, stderr: "" };
      }
      if (line.includes("-name trace.zip")) {
        const hits = [...files.keys()].filter((p) => p.endsWith("/trace.zip"));
        if (hits.length === 0) return { code: 1, stdout: "", stderr: "" };
        return { code: 0, stdout: `${hits.join("\n")}\n`, stderr: "" };
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

  it("skips the video when the caller does not want it kept", async () => {
    const sb = fakeSandbox(
      new Map([
        ["/out/shot.png", Buffer.from("png")],
        ["/out/page-a.webm", Buffer.from("vid")],
      ]),
    );
    const ev = await copyEvidence(sb, dir, { ...FAST, keepVideo: false });
    expect(ev.video).toBeUndefined();
    expect(existsSync(join(dir, "page-a.webm"))).toBe(false);
    // Everything else still lands: a refutation needs the trace and the shots.
    expect(ev.screenshots).toEqual(["shot.png"]);
    expect(existsSync(join(dir, "shot.png"))).toBe(true);
  });

  it("does not wait for a video it will not keep", async () => {
    const sb = fakeSandbox(new Map([["/out/shot.png", Buffer.from("png")]]));
    const started = Date.now();
    await copyEvidence(sb, dir, { videoWaitMs: 5_000, pollMs: 50, keepVideo: false });
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  it("leaves requests unset when the trace has no network data", async () => {
    const sb = fakeSandbox(new Map([["/out/page-a.webm", Buffer.from("vid")]]));
    const ev = await copyEvidence(sb, dir, FAST);
    expect(ev.requests).toBeUndefined();
    expect(ev.requestsFile).toBeUndefined();
  });

  it("redacts the target password from requests.http and trace.zip", async () => {
    const pw = "hunter2secret";
    const network = JSON.stringify({
      type: "resource-snapshot",
      snapshot: {
        request: {
          method: "POST",
          url: "http://t/login",
          headers: [],
          postData: { text: `u=alice&p=${pw}` },
        },
        response: { status: 302, headers: [] },
      },
    });
    const files = new Map<string, Buffer>([
      ["/out/traces/trace.network", Buffer.from(`${network}\n`)],
      ["/out/traces/trace.trace", Buffer.from(`{"type":"action","params":{"value":"${pw}"}}\n`)],
    ]);
    const dir = mkdtempSync(join(tmpdir(), "ev-"));
    await copyEvidence(fakeSandbox(files), dir, {
      ...FAST,
      auth: { username: "alice", password: pw },
    });
    expect(readFileSync(join(dir, "requests.http"), "utf8")).not.toContain(pw);
    const zip = new AdmZip(join(dir, "trace.zip"));
    for (const e of zip.getEntries()) expect(e.getData().toString("utf8")).not.toContain(pw);
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

describe("a trace.zip written by the test runner", () => {
  let dir2: string;
  beforeEach(() => {
    dir2 = mkdtempSync(join(tmpdir(), "agentgg-zip-"));
  });
  afterEach(() => rmSync(dir2, { recursive: true, force: true }));

  const snap = JSON.stringify({
    type: "resource-snapshot",
    snapshot: {
      request: { method: "GET", url: "http://app/search?q=x", headers: [] },
      response: { status: 200, headers: [] },
    },
  });

  const zipped = () => {
    const z = new AdmZip();
    z.addFile("trace.trace", Buffer.from("t"));
    z.addFile("trace.network", Buffer.from(snap));
    return z.toBuffer();
  };

  it("copies it out and reads its requests, like a loose trace directory", async () => {
    const sb = fakeSandbox(new Map([["/out/exploit-chromium/trace.zip", zipped()]]));
    const ev = await copyEvidence(sb, dir2, FAST);
    expect(ev.trace).toBe("trace.zip");
    expect(existsSync(join(dir2, "trace.zip"))).toBe(true);
    expect(ev.requests).toEqual([{ method: "GET", url: "http://app/search?q=x", status: 200 }]);
  });
});

describe("orderScreenshots", () => {
  it("puts the proof first and the negative control last", () => {
    const out = orderScreenshots(["control-offset-0.png", "xss-offset-bbox.png"]);
    expect(out).toEqual(["xss-offset-bbox.png", "control-offset-0.png"]);
  });

  it("keeps the original order when nothing looks like a control", () => {
    const out = orderScreenshots(["step-1.png", "step-2.png"]);
    expect(out).toEqual(["step-1.png", "step-2.png"]);
  });

  it("treats benign and baseline names as controls too", () => {
    const out = orderScreenshots(["baseline.png", "attack.png", "benign-input.png"]);
    expect(out[0]).toBe("attack.png");
  });
});

describe("orphan cleanup", () => {
  let odir: string;
  beforeEach(() => {
    odir = mkdtempSync(join(tmpdir(), "agentgg-orphan-"));
  });
  afterEach(() => rmSync(odir, { recursive: true, force: true }));

  it("removes a prior run's files before copying the new ones", async () => {
    // A leftover from an earlier --force run.
    writeFileSyncNode(join(odir, "stale-proof.png"), Buffer.from("old"));
    const sb = fakeSandbox(new Map([["/out/fresh.png", Buffer.from("new")]]));
    const ev = await copyEvidence(sb, odir, FAST);
    expect(ev.screenshots).toEqual(["fresh.png"]);
    expect(existsSync(join(odir, "stale-proof.png"))).toBe(false);
  });
});

describe("nested playwright-test artifacts", () => {
  let ndir: string;
  beforeEach(() => {
    ndir = mkdtempSync(join(tmpdir(), "agentgg-nested-"));
  });
  afterEach(() => rmSync(ndir, { recursive: true, force: true }));

  it("collects the video and screenshot from per-test folders with clean names", async () => {
    const sb = fakeSandbox(
      new Map([
        ["/out/proof-exploit-chromium/video.webm", Buffer.from("v1")],
        ["/out/proof-exploit-chromium/test-finished-1.png", Buffer.from("s1")],
        ["/out/proof-control-chromium/video.webm", Buffer.from("v2")],
        ["/out/proof-control-chromium/test-finished-1.png", Buffer.from("s2")],
      ]),
    );
    const ev = await copyEvidence(sb, ndir, FAST);
    expect(ev.video).toBe("exploit.webm");
    expect(ev.screenshots).toEqual(["exploit.png", "control.png"]);
    expect(existsSync(join(ndir, "exploit.png"))).toBe(true);
    expect(existsSync(join(ndir, "control.webm"))).toBe(true);
  });
});

describe("evidenceName", () => {
  it("keeps a top-level MCP filename unchanged", () => {
    expect(evidenceName("xss-proof.png")).toBe("xss-proof.png");
  });
  it("names a nested exploit artifact by its test", () => {
    expect(evidenceName("proof-exploit-chromium/video.webm")).toBe("exploit.webm");
  });
  it("flattens a nested artifact that names no test", () => {
    expect(evidenceName("run-1/foo/shot.png")).toBe("run-1-foo-shot.png");
  });
});
