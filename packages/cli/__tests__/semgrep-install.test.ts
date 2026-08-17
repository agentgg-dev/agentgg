import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getSemgrepCorePath } from "@agentgg/core";
import AdmZip from "adm-zip";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  installSemgrepCore,
  SEMGREP_VERSION,
  WHEELS,
  type WheelEntry,
  wheelForCurrentPlatform,
} from "../src/semgrep-install.js";

describe("pinned wheel table", () => {
  it("pins one wheel per supported platform", () => {
    expect(Object.keys(WHEELS).sort()).toEqual([
      "darwin-arm64",
      "linux-arm64",
      "linux-x64",
      "win32-x64",
    ]);
  });

  it("names a wheel matching the pinned version, with a 64-char sha256", () => {
    for (const [key, entry] of Object.entries(WHEELS)) {
      expect(entry.filename, key).toContain(`semgrep-${SEMGREP_VERSION}-`);
      expect(entry.filename, key).toMatch(/\.whl$/);
      expect(entry.sha256, key).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("gives every supported platform a distinct wheel", () => {
    const names = Object.values(WHEELS).map((w) => w.filename);
    expect(new Set(names).size).toBe(names.length);
  });

  it("resolves the current platform to an entry or null, never undefined", () => {
    const entry = wheelForCurrentPlatform();
    expect(entry === null || typeof entry.sha256 === "string").toBe(true);
  });
});

/** A minimal wheel containing the one entry the installer extracts. */
function fakeWheel(binaryBody: string): Buffer {
  const zip = new AdmZip();
  const name = process.platform === "win32" ? "semgrep-core.exe" : "semgrep-core";
  zip.addFile(`semgrep/bin/${name}`, Buffer.from(binaryBody));
  zip.addFile("semgrep/__init__.py", Buffer.from("# unrelated, must not be extracted"));
  return zip.toBuffer();
}

function sha256(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

/** A fetch that serves PyPI metadata, then the wheel bytes. */
function fakeFetch(wheel: Buffer, entry: WheelEntry): typeof fetch {
  return (async (url: string | URL) => {
    if (String(url).includes("pypi.org")) {
      return new Response(
        JSON.stringify({
          urls: [
            {
              packagetype: "bdist_wheel",
              filename: entry.filename,
              url: "https://files.example/w.whl",
              digests: { sha256: entry.sha256 },
            },
          ],
        }),
        { status: 200 },
      );
    }
    return new Response(wheel, { status: 200 });
  }) as unknown as typeof fetch;
}

describe("installSemgrepCore", () => {
  let home: string;
  let env: NodeJS.ProcessEnv;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "agentgg-sgi-"));
    env = { AGENTGG_HOME: home };
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  it("extracts only semgrep-core when the digest matches", async () => {
    const wheel = fakeWheel("BINARY");
    const entry: WheelEntry = { filename: "fake.whl", sha256: sha256(wheel) };
    const result = await installSemgrepCore(env, { fetchImpl: fakeFetch(wheel, entry), entry });
    expect(result).toEqual({ ok: true, path: getSemgrepCorePath(SEMGREP_VERSION, env) });
    expect(readFileSync(getSemgrepCorePath(SEMGREP_VERSION, env), "utf8")).toBe("BINARY");
    expect(existsSync(join(home, "semgrep", SEMGREP_VERSION, "semgrep", "__init__.py"))).toBe(
      false,
    );
  });

  it("writes a version marker so a later call can short-circuit", async () => {
    const wheel = fakeWheel("BINARY");
    const entry: WheelEntry = { filename: "fake.whl", sha256: sha256(wheel) };
    await installSemgrepCore(env, { fetchImpl: fakeFetch(wheel, entry), entry });
    const marker = join(home, "semgrep", SEMGREP_VERSION, ".version.json");
    expect(JSON.parse(readFileSync(marker, "utf8")).version).toBe(SEMGREP_VERSION);
  });

  it("refuses a wheel whose bytes do not match the pinned digest", async () => {
    const wheel = fakeWheel("TAMPERED");
    // The pinned digest is what authenticates the file. The digest PyPI reports
    // is never trusted, so serving a matching one here must not help.
    const entry: WheelEntry = { filename: "fake.whl", sha256: "0".repeat(64) };
    const result = await installSemgrepCore(env, {
      fetchImpl: fakeFetch(wheel, { filename: "fake.whl", sha256: sha256(wheel) }),
      entry,
    });
    expect(result).toEqual({ ok: false, reason: "verification failed" });
    expect(existsSync(getSemgrepCorePath(SEMGREP_VERSION, env))).toBe(false);
  });

  it("reports unsupported platform without any network call", async () => {
    let calls = 0;
    const counting = (async () => {
      calls++;
      return new Response("", { status: 200 });
    }) as unknown as typeof fetch;
    const result = await installSemgrepCore(env, { fetchImpl: counting, entry: null });
    expect(result).toEqual({ ok: false, reason: "unsupported platform" });
    expect(calls).toBe(0);
  });

  it("reports download failed when the wheel request is not ok", async () => {
    const entry: WheelEntry = { filename: "fake.whl", sha256: "0".repeat(64) };
    const failing = (async (url: string | URL) =>
      String(url).includes("pypi.org")
        ? new Response(
            JSON.stringify({
              urls: [
                {
                  packagetype: "bdist_wheel",
                  filename: "fake.whl",
                  url: "https://files.example/w",
                },
              ],
            }),
            { status: 200 },
          )
        : new Response("", { status: 503 })) as unknown as typeof fetch;
    const result = await installSemgrepCore(env, { fetchImpl: failing, entry });
    expect(result).toEqual({ ok: false, reason: "download failed" });
  });

  it("reports download failed when the metadata lists no matching wheel", async () => {
    const entry: WheelEntry = { filename: "fake.whl", sha256: "0".repeat(64) };
    const empty = (async () =>
      new Response(JSON.stringify({ urls: [] }), { status: 200 })) as unknown as typeof fetch;
    const result = await installSemgrepCore(env, { fetchImpl: empty, entry });
    expect(result).toEqual({ ok: false, reason: "download failed" });
  });

  it("reports download failed when fetch throws", async () => {
    const entry: WheelEntry = { filename: "fake.whl", sha256: "0".repeat(64) };
    const throwing = (async () => {
      throw new Error("ENOTFOUND");
    }) as unknown as typeof fetch;
    const result = await installSemgrepCore(env, { fetchImpl: throwing, entry });
    expect(result).toEqual({ ok: false, reason: "download failed" });
  });

  it("reports verification failed when the wheel has no semgrep-core entry", async () => {
    const zip = new AdmZip();
    zip.addFile("semgrep/__init__.py", Buffer.from("no binary here"));
    const wheel = zip.toBuffer();
    const entry: WheelEntry = { filename: "fake.whl", sha256: sha256(wheel) };
    const result = await installSemgrepCore(env, { fetchImpl: fakeFetch(wheel, entry), entry });
    expect(result).toEqual({ ok: false, reason: "verification failed" });
  });
});
