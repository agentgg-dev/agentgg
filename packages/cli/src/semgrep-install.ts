import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { getSemgrepCorePath, getSemgrepDir } from "@agentgg/core";
import AdmZip from "adm-zip";

/**
 * Acquisition of the semgrep analysis binary. Knows nothing about agents or
 * preFilters — it downloads, verifies, and caches, and that is all.
 *
 * The version and every digest below are pinned at build time, so they ship
 * inside the provenance-attested `agentgg` tarball rather than being fetched
 * from the same server as the file they authenticate. Bumping semgrep means
 * changing the version AND all four digests in one commit.
 *
 * Digests come from `https://pypi.org/pypi/semgrep/<version>/json`.
 */
export const SEMGREP_VERSION = "1.173.0";

/** Wheel filenames share this interpreter-compatibility segment. */
const TAGS = "cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none";

export interface WheelEntry {
  filename: string;
  sha256: string;
}

/**
 * Keyed by `${process.platform}-${process.arch}`. A platform absent from this
 * table is unsupported: no wheel exists for it upstream, or we chose not to
 * carry it (Intel Mac, musl). Callers degrade without a network call.
 */
export const WHEELS: Readonly<Record<string, WheelEntry>> = {
  "darwin-arm64": {
    filename: `semgrep-${SEMGREP_VERSION}-${TAGS}-macosx_11_0_arm64.whl`,
    sha256: "c62eb7c13257c3cc58106b8f6afab152f9f99bfe36fdfebd6f09809fa1c50966",
  },
  "linux-x64": {
    filename: `semgrep-${SEMGREP_VERSION}-${TAGS}-manylinux_2_34_x86_64.whl`,
    sha256: "cb21aa06246bdd79d3e9e7f9118ec7baecb1be39cf89c46e07af13b4128d7b79",
  },
  "linux-arm64": {
    filename: `semgrep-${SEMGREP_VERSION}-${TAGS}-manylinux_2_34_aarch64.whl`,
    sha256: "e1a508dd8bccaff05482bb2968d4ae84a432f932e502d3caccdb3d525da51f22",
  },
  "win32-x64": {
    filename: `semgrep-${SEMGREP_VERSION}-${TAGS}-win_amd64.whl`,
    sha256: "29a7371b27ed57f464e57c85c2fcfac4352fa67241092405daa21e21f9dea629",
  },
};

/** `${platform}-${arch}`, the key shape used by `WHEELS`. */
export function currentPlatformKey(): string {
  return `${process.platform}-${process.arch}`;
}

/** The pinned wheel for this machine, or null when unsupported. */
export function wheelForCurrentPlatform(): WheelEntry | null {
  return WHEELS[currentPlatformKey()] ?? null;
}

const PYPI_JSON = `https://pypi.org/pypi/semgrep/${SEMGREP_VERSION}/json`;

/** Why a scan could not use semgrep. Each calls for a different user response. */
export type SemgrepFailure =
  | "unsupported platform"
  | "binary failed to start"
  | "download failed"
  | "verification failed";

export type InstallResult = { ok: true; path: string } | { ok: false; reason: SemgrepFailure };

export interface InstallDeps {
  fetchImpl?: typeof fetch;
  /**
   * Overrides the pinned wheel. Tests supply a digest matching their fixture,
   * since no fake archive can ever hash to the real pinned value. An explicit
   * `null` simulates an unsupported platform.
   */
  entry?: WheelEntry | null;
}

interface PypiFile {
  packagetype?: string;
  filename?: string;
  url?: string;
}

/**
 * Download the pinned wheel, verify it against the pinned digest, and extract
 * `semgrep-core` into the versioned cache. Never throws: every failure comes
 * back as a typed reason the caller records.
 */
export async function installSemgrepCore(
  env: NodeJS.ProcessEnv = process.env,
  deps: InstallDeps = {},
): Promise<InstallResult> {
  const entry = deps.entry !== undefined ? deps.entry : wheelForCurrentPlatform();
  if (!entry) return { ok: false, reason: "unsupported platform" };

  const doFetch = deps.fetchImpl ?? fetch;
  let bytes: Buffer;
  try {
    const meta = await doFetch(PYPI_JSON, { headers: { "User-Agent": "agentgg-cli" } });
    if (!meta.ok) return { ok: false, reason: "download failed" };
    const files = ((await meta.json()) as { urls?: PypiFile[] }).urls ?? [];
    const match = files.find(
      (f) => f.packagetype === "bdist_wheel" && f.filename === entry.filename,
    );
    if (!match?.url) return { ok: false, reason: "download failed" };

    const res = await doFetch(match.url, { headers: { "User-Agent": "agentgg-cli" } });
    if (!res.ok) return { ok: false, reason: "download failed" };
    bytes = Buffer.from(await res.arrayBuffer());
  } catch {
    return { ok: false, reason: "download failed" };
  }

  // Verify BEFORE opening the archive, and against the digest pinned in this
  // file rather than the one PyPI reports beside the file it describes. An
  // unverified binary is never written to the cache, let alone executed.
  if (createHash("sha256").update(bytes).digest("hex") !== entry.sha256) {
    return { ok: false, reason: "verification failed" };
  }

  const dir = getSemgrepDir(SEMGREP_VERSION, env);
  const target = getSemgrepCorePath(SEMGREP_VERSION, env);
  try {
    const zip = new AdmZip(bytes);
    // The binary sits under a wheel data prefix, e.g.
    // `semgrep-1.173.0.data/purelib/semgrep/bin/semgrep-core.exe`, so match on
    // the tail rather than the whole path.
    const binEntries = zip
      .getEntries()
      .filter((e) => !e.isDirectory && /(^|\/)semgrep\/bin\/[^/]+$/.test(e.entryName));
    const core = binEntries.find((e) => /\/semgrep-core(\.exe)?$/.test(`/${e.entryName}`));
    if (!core) return { ok: false, reason: "verification failed" };

    // Take the whole bin/ directory, not just the executable. On Windows
    // semgrep-core loads sibling DLLs (libcrypto, libcurl, libgmp, …) and will
    // not start without them.
    mkdirSync(dir, { recursive: true });
    for (const e of binEntries) {
      const name = e.entryName.split("/").pop();
      if (!name) continue;
      writeFileSync(join(dir, name), e.getData());
    }
    if (process.platform !== "win32") chmodSync(target, 0o755);
    writeFileSync(
      join(dir, ".version.json"),
      `${JSON.stringify({ version: SEMGREP_VERSION, installedAt: new Date().toISOString() }, null, 2)}\n`,
    );
  } catch {
    rmSync(dir, { recursive: true, force: true });
    return { ok: false, reason: "download failed" };
  }

  return { ok: true, path: target };
}
