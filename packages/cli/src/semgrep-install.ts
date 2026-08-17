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
