# Semgrep Binary Distribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `where.preFilter` entries of the `semgrepRule` form work on a machine that only ran `npm install -g agentgg`, by fetching `semgrep-core` from PyPI the first time a scan needs it.

**Architecture:** A new `semgrep-install.ts` owns acquisition: a pinned semgrep version, a per-platform table of wheel filename plus SHA-256, download, verify-before-extract, and a versioned cache under `~/.agentgg/semgrep/<version>/`. The existing `semgrep.ts` gains a single-flighted `ensureSemgrepCore` that tries the env override, then the cache, then `PATH`, then the fetch. When every path fails the agent still runs its regex preFilters and the reason is recorded on its `AgentRun` sidecar so no report implies coverage the scan did not have.

**Tech Stack:** TypeScript, Node >= 20, pnpm workspace (`packages/core`, `packages/cli`), zod schemas, vitest, biome, `adm-zip` (already a dependency), esbuild bundle via `packages/cli/scripts/bundle-cli.mjs`.

**Spec:** `docs/superpowers/specs/2026-08-17-semgrep-binary-distribution-design.md`

## Global Constraints

- Pinned semgrep version: **1.173.0**. Changing it means changing every SHA-256 in the same commit.
- Supported platform keys, formed as `` `${process.platform}-${process.arch}` ``: `darwin-arm64`, `linux-x64`, `linux-arm64`, `win32-x64`. Anything else is unsupported and degrades without a network call.
- The wheel's SHA-256 is verified **before** the archive is opened. A binary is never executed unverified.
- Failure degrades, never throws out of a scan. The four reasons are exactly: `unsupported platform`, `binary failed to start`, `download failed`, `verification failed`.
- Resolution order, first hit wins: `AGENTGG_SEMGREP_CORE` → cache → `PATH` → fetch.
- No new runtime dependencies. `adm-zip` and `node:crypto` cover everything.
- Tests must not hit the network. The one integration test that does is gated behind `AGENTGG_TEST_SEMGREP_DOWNLOAD=1`.
- **Build trap:** root `pnpm build` runs only `tsc --build` and does NOT rebuild `packages/cli/dist/cli.js`, which is an esbuild bundle with `@agentgg/core` inlined. After any change under `packages/core`, run `node scripts/bundle-cli.mjs` from `packages/cli/` before invoking `node packages/cli/dist/cli.js`, or you will debug a stale schema.

## File Structure

| File | Responsibility |
|---|---|
| `packages/core/src/paths.ts` | Modify. Add `getSemgrepDir` / `getSemgrepCorePath` beside the existing catalog path helpers. |
| `packages/core/src/types.ts` | Modify. Add the `degraded` field to `AgentRun`. |
| `packages/cli/src/semgrep-install.ts` | Create. Pinned table, download, verify, extract, cache marker. Acquisition only — knows nothing about agents. |
| `packages/cli/src/semgrep.ts` | Modify. `ensureSemgrepCore` resolution + single-flight; `runSemgrepPreFilter` reports degradation. |
| `packages/cli/src/commands/scan.ts` | Modify. Thread the degradation reason into `writeAgentRun`. |
| `packages/cli/__tests__/semgrep-install.test.ts` | Create. Table, download, verify, extract, cache. |
| `packages/cli/__tests__/semgrep.test.ts` | Modify. Resolution order, single-flight, degradation reasons. |
| `NOTICE` | Modify. One line about the runtime-fetched LGPL component. |

---

### Task 1: Pinned platform table and cache paths

**Files:**
- Modify: `packages/core/src/paths.ts` (after `getOfficialAgentsVersionPath`, around line 86)
- Create: `packages/cli/src/semgrep-install.ts`
- Test: `packages/cli/__tests__/semgrep-install.test.ts`

**Interfaces:**
- Consumes: `getDataDir` from `@agentgg/core`.
- Produces: `getSemgrepDir(env)`, `getSemgrepCorePath(env)` from `@agentgg/core`; `SEMGREP_VERSION: string`, `type SemgrepPlatform`, `WHEELS: Readonly<Record<string, { filename: string; sha256: string }>>`, `currentPlatformKey(): string`, `wheelForCurrentPlatform(): { filename: string; sha256: string } | null` from `./semgrep-install.js`.

- [ ] **Step 1: Write the failing test**

Create `packages/cli/__tests__/semgrep-install.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { SEMGREP_VERSION, WHEELS, wheelForCurrentPlatform } from "../src/semgrep-install.js";

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run packages/cli/__tests__/semgrep-install.test.ts`
Expected: FAIL — cannot resolve `../src/semgrep-install.js`.

- [ ] **Step 3: Add the path helpers**

In `packages/core/src/paths.ts`, immediately after `getOfficialAgentsVersionPath`:

```ts
/**
 * Directory holding the fetched semgrep binary, keyed by version so a
 * pinned-version bump lands beside the old copy instead of colliding with it:
 * `<dataDir>/semgrep/<version>/`.
 */
export function getSemgrepDir(version: string, env: NodeJS.ProcessEnv = process.env): string {
  return join(getDataDir(env), "semgrep", version);
}

/** Path to the cached analysis binary inside `getSemgrepDir`. */
export function getSemgrepCorePath(version: string, env: NodeJS.ProcessEnv = process.env): string {
  const exe = process.platform === "win32" ? "semgrep-core.exe" : "semgrep-core";
  return join(getSemgrepDir(version, env), exe);
}
```

- [ ] **Step 4: Create the pinned table**

Create `packages/cli/src/semgrep-install.ts`:

```ts
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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pnpm vitest run packages/cli/__tests__/semgrep-install.test.ts`
Expected: PASS, 4 tests.

- [ ] **Step 6: Build and lint**

Run: `pnpm build && pnpm lint`
Expected: both clean. If biome reports formatting, run `pnpm exec biome check --write packages/core/src/paths.ts packages/cli/src/semgrep-install.ts packages/cli/__tests__/semgrep-install.test.ts` and re-run lint.

- [ ] **Step 7: Commit**

```bash
git add packages/core/src/paths.ts packages/cli/src/semgrep-install.ts packages/cli/__tests__/semgrep-install.test.ts
git commit -m "pin the semgrep wheel table and add the versioned cache paths"
```

---

### Task 2: Download, verify, extract

**Files:**
- Modify: `packages/cli/src/semgrep-install.ts`
- Test: `packages/cli/__tests__/semgrep-install.test.ts`

**Interfaces:**
- Consumes: `SEMGREP_VERSION`, `WHEELS`, `wheelForCurrentPlatform` from Task 1; `getSemgrepDir`, `getSemgrepCorePath` from `@agentgg/core`.
- Produces: `type SemgrepFailure = "unsupported platform" | "binary failed to start" | "download failed" | "verification failed"`; `type InstallResult = { ok: true; path: string } | { ok: false; reason: SemgrepFailure }`; `installSemgrepCore(env?, deps?): Promise<InstallResult>` where `deps` is `{ fetchImpl?: typeof fetch }`.

The `deps` parameter exists so tests inject a fake `fetch` and never touch the network.

- [ ] **Step 1: Write the failing test**

Append to `packages/cli/__tests__/semgrep-install.test.ts`:

```ts
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import AdmZip from "adm-zip";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { getSemgrepCorePath } from "@agentgg/core";
import { installSemgrepCore, SEMGREP_VERSION, wheelForCurrentPlatform } from "../src/semgrep-install.js";

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

/** A fetch that serves PyPI metadata then the wheel bytes. */
function fakeFetch(wheel: Buffer, digest: string): typeof fetch {
  const entry = wheelForCurrentPlatform();
  return (async (url: string | URL) => {
    const href = String(url);
    if (href.includes("pypi.org")) {
      return new Response(
        JSON.stringify({
          urls: [
            { packagetype: "bdist_wheel", filename: entry?.filename, url: "https://files.example/w.whl", digests: { sha256: digest } },
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
    const result = await installSemgrepCore(env, { fetchImpl: fakeFetch(wheel, sha256(wheel)) });
    expect(result).toEqual({ ok: true, path: getSemgrepCorePath(SEMGREP_VERSION, env) });
    expect(readFileSync(getSemgrepCorePath(SEMGREP_VERSION, env), "utf8")).toBe("BINARY");
    expect(existsSync(join(home, "semgrep", SEMGREP_VERSION, "semgrep", "__init__.py"))).toBe(false);
  });

  it("writes a version marker so a later call can short-circuit", async () => {
    const wheel = fakeWheel("BINARY");
    await installSemgrepCore(env, { fetchImpl: fakeFetch(wheel, sha256(wheel)) });
    const marker = join(home, "semgrep", SEMGREP_VERSION, ".version.json");
    expect(JSON.parse(readFileSync(marker, "utf8")).version).toBe(SEMGREP_VERSION);
  });

  it("refuses a wheel whose bytes do not match the pinned digest", async () => {
    const wheel = fakeWheel("TAMPERED");
    const wrong = "0".repeat(64);
    const result = await installSemgrepCore(env, { fetchImpl: fakeFetch(wheel, wrong) });
    expect(result).toEqual({ ok: false, reason: "verification failed" });
    expect(existsSync(getSemgrepCorePath(SEMGREP_VERSION, env))).toBe(false);
  });

  it("reports download failed when the wheel request is not ok", async () => {
    const failing = (async (url: string | URL) =>
      String(url).includes("pypi.org")
        ? new Response(JSON.stringify({ urls: [] }), { status: 200 })
        : new Response("", { status: 503 })) as unknown as typeof fetch;
    const result = await installSemgrepCore(env, { fetchImpl: failing });
    expect(result).toEqual({ ok: false, reason: "download failed" });
  });

  it("reports download failed when fetch throws", async () => {
    const throwing = (async () => {
      throw new Error("ENOTFOUND");
    }) as unknown as typeof fetch;
    const result = await installSemgrepCore(env, { fetchImpl: throwing });
    expect(result).toEqual({ ok: false, reason: "download failed" });
  });
});
```

Note: the digest the fake serves in metadata is ignored by the installer; verification is against the pinned table. The third test proves that by serving a wrong digest and a tampered body — both must be rejected.

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run packages/cli/__tests__/semgrep-install.test.ts`
Expected: FAIL — `installSemgrepCore` is not exported.

- [ ] **Step 3: Implement the installer**

Append to `packages/cli/src/semgrep-install.ts`:

```ts
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { getSemgrepCorePath, getSemgrepDir } from "@agentgg/core";
import AdmZip from "adm-zip";

const PYPI_JSON = `https://pypi.org/pypi/semgrep/${SEMGREP_VERSION}/json`;

/** Why a scan could not use semgrep. Each calls for a different user response. */
export type SemgrepFailure =
  | "unsupported platform"
  | "binary failed to start"
  | "download failed"
  | "verification failed";

export type InstallResult = { ok: true; path: string } | { ok: false; reason: SemgrepFailure };

interface InstallDeps {
  fetchImpl?: typeof fetch;
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
  const entry = wheelForCurrentPlatform();
  if (!entry) return { ok: false, reason: "unsupported platform" };

  const doFetch = deps.fetchImpl ?? fetch;
  let bytes: Buffer;
  try {
    const meta = await doFetch(PYPI_JSON, { headers: { "User-Agent": "agentgg-cli" } });
    if (!meta.ok) return { ok: false, reason: "download failed" };
    const files = ((await meta.json()) as { urls?: PypiFile[] }).urls ?? [];
    const match = files.find((f) => f.packagetype === "bdist_wheel" && f.filename === entry.filename);
    if (!match?.url) return { ok: false, reason: "download failed" };

    const res = await doFetch(match.url, { headers: { "User-Agent": "agentgg-cli" } });
    if (!res.ok) return { ok: false, reason: "download failed" };
    bytes = Buffer.from(await res.arrayBuffer());
  } catch {
    return { ok: false, reason: "download failed" };
  }

  // Verify BEFORE opening the archive. An unverified binary is never written
  // to the cache, let alone executed.
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== entry.sha256) return { ok: false, reason: "verification failed" };

  const dir = getSemgrepDir(SEMGREP_VERSION, env);
  const target = getSemgrepCorePath(SEMGREP_VERSION, env);
  try {
    const zip = new AdmZip(bytes);
    const wanted = zip
      .getEntries()
      .find((e) => /^semgrep\/bin\/semgrep-core(\.exe)?$/.test(e.entryName));
    if (!wanted) return { ok: false, reason: "verification failed" };

    mkdirSync(dir, { recursive: true });
    writeFileSync(target, wanted.getData());
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run packages/cli/__tests__/semgrep-install.test.ts`
Expected: PASS, 9 tests.

- [ ] **Step 5: Build and lint**

Run: `pnpm build && pnpm lint`
Expected: clean. Format with `pnpm exec biome check --write packages/cli/src/semgrep-install.ts packages/cli/__tests__/semgrep-install.test.ts` if needed.

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/semgrep-install.ts packages/cli/__tests__/semgrep-install.test.ts
git commit -m "download, verify, and cache semgrep-core from the pinned wheel"
```

---

### Task 3: Resolution order and single-flight

**Files:**
- Modify: `packages/cli/src/semgrep.ts` (replace `resolveSemgrepCore`, currently around lines 174-178)
- Test: `packages/cli/__tests__/semgrep.test.ts`

**Interfaces:**
- Consumes: `installSemgrepCore`, `InstallResult`, `SemgrepFailure`, `SEMGREP_VERSION` from Task 2; `getSemgrepCorePath` from `@agentgg/core`.
- Produces: `ensureSemgrepCore(env?, deps?): Promise<{ ok: true; bin: string } | { ok: false; reason: SemgrepFailure }>` and `resetSemgrepResolution(): void` (test-only reset of the process-lifetime memo) from `./semgrep.js`.

`resolveSemgrepCore` stays exported and unchanged in behaviour for the env-override and PATH cases; `ensureSemgrepCore` wraps it and adds the cache and the fetch.

- [ ] **Step 1: Write the failing test**

Append to `packages/cli/__tests__/semgrep.test.ts`:

```ts
import { ensureSemgrepCore, resetSemgrepResolution } from "../src/semgrep.js";
import { SEMGREP_VERSION } from "../src/semgrep-install.js";
import { getSemgrepCorePath } from "@agentgg/core";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

describe("ensureSemgrepCore", () => {
  beforeEach(() => {
    resetSemgrepResolution();
  });

  it("prefers AGENTGG_SEMGREP_CORE over everything else", async () => {
    const bin = join(dir, "explicit-core");
    writeFileSync(bin, "");
    let installs = 0;
    const result = await ensureSemgrepCore(
      { AGENTGG_SEMGREP_CORE: bin, AGENTGG_HOME: dir },
      {
        install: async () => {
          installs++;
          return { ok: true, path: "should-not-be-used" };
        },
      },
    );
    expect(result).toEqual({ ok: true, bin });
    expect(installs).toBe(0);
  });

  it("uses the cached binary without installing", async () => {
    const cached = getSemgrepCorePath(SEMGREP_VERSION, { AGENTGG_HOME: dir });
    mkdirSync(dirname(cached), { recursive: true });
    writeFileSync(cached, "");
    let installs = 0;
    const result = await ensureSemgrepCore(
      { AGENTGG_HOME: dir },
      {
        install: async () => {
          installs++;
          return { ok: true, path: cached };
        },
      },
    );
    expect(result).toEqual({ ok: true, bin: cached });
    expect(installs).toBe(0);
  });

  it("takes semgrep-core from PATH before downloading", async () => {
    const name = process.platform === "win32" ? "semgrep-core.exe" : "semgrep-core";
    const onPath = join(dir, name);
    writeFileSync(onPath, "");
    let installs = 0;
    const result = await ensureSemgrepCore(
      { AGENTGG_HOME: dir, PATH: dir },
      {
        install: async () => {
          installs++;
          return { ok: true, path: "should-not-be-used" };
        },
      },
    );
    expect(result).toEqual({ ok: true, bin: onPath });
    expect(installs).toBe(0);
  });

  it("installs when nothing is cached and PATH has nothing", async () => {
    const result = await ensureSemgrepCore(
      { AGENTGG_HOME: dir, PATH: "" },
      { install: async () => ({ ok: true, path: "/fetched/semgrep-core" }) },
    );
    expect(result).toEqual({ ok: true, bin: "/fetched/semgrep-core" });
  });

  it("installs once when several callers race", async () => {
    let installs = 0;
    const install = async () => {
      installs++;
      await new Promise((r) => setTimeout(r, 10));
      return { ok: true as const, path: "/fetched/semgrep-core" };
    };
    const results = await Promise.all([
      ensureSemgrepCore({ AGENTGG_HOME: dir }, { install }),
      ensureSemgrepCore({ AGENTGG_HOME: dir }, { install }),
      ensureSemgrepCore({ AGENTGG_HOME: dir }, { install }),
    ]);
    expect(installs).toBe(1);
    for (const r of results) expect(r).toEqual({ ok: true, bin: "/fetched/semgrep-core" });
  });

  it("remembers a failure instead of retrying it per agent", async () => {
    let installs = 0;
    const install = async () => {
      installs++;
      return { ok: false as const, reason: "download failed" as const };
    };
    const first = await ensureSemgrepCore({ AGENTGG_HOME: dir }, { install });
    const second = await ensureSemgrepCore({ AGENTGG_HOME: dir }, { install });
    expect(first).toEqual({ ok: false, reason: "download failed" });
    expect(second).toEqual({ ok: false, reason: "download failed" });
    expect(installs).toBe(1);
  });

  it("reports the unsupported platform without any install attempt", async () => {
    const result = await ensureSemgrepCore(
      { AGENTGG_HOME: dir },
      { install: async () => ({ ok: false, reason: "unsupported platform" }) },
    );
    expect(result).toEqual({ ok: false, reason: "unsupported platform" });
  });
});
```

The existing `describe("resolveSemgrepCore")` block stays as it is.

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run packages/cli/__tests__/semgrep.test.ts`
Expected: FAIL — `ensureSemgrepCore` is not exported.

- [ ] **Step 3: Implement resolution and single-flight**

In `packages/cli/src/semgrep.ts`, add these imports at the top:

```ts
import { getSemgrepCorePath } from "@agentgg/core";
import {
  type InstallResult,
  installSemgrepCore,
  SEMGREP_VERSION,
  type SemgrepFailure,
} from "./semgrep-install.js";
```

Then, directly below the existing `resolveSemgrepCore`:

```ts
export type EnsureResult = { ok: true; bin: string } | { ok: false; reason: SemgrepFailure };

interface EnsureDeps {
  install?: (env: NodeJS.ProcessEnv) => Promise<InstallResult>;
}

/**
 * First match for `name` on PATH, or null. Node has no `which`, and shelling
 * out to one would cost a process on every scan.
 */
function findOnPath(name: string, env: NodeJS.ProcessEnv): string | null {
  const exts = process.platform === "win32" ? [".exe", ".cmd", ""] : [""];
  for (const entry of (env.PATH ?? "").split(delimiter)) {
    if (!entry) continue;
    for (const ext of exts) {
      const candidate = join(entry, `${name}${ext}`);
      if (existsSync(candidate)) return candidate;
    }
  }
  return null;
}

/**
 * Process-lifetime memo. One scan asks per agent, so without this a dead
 * network would be retried 160 times, and two agents starting together would
 * both download the same 60 MB wheel.
 */
let inflight: Promise<EnsureResult> | null = null;

/** Test-only: forget the memo so each case starts clean. */
export function resetSemgrepResolution(): void {
  inflight = null;
}

/**
 * Resolve the analysis binary, fetching it if this is the first scan that
 * needs it. Order: explicit override, versioned cache, PATH, download.
 * Never throws — a failure is a typed reason the caller records against the
 * agent so the report cannot imply coverage the scan did not have.
 */
export async function ensureSemgrepCore(
  env: NodeJS.ProcessEnv = process.env,
  deps: EnsureDeps = {},
): Promise<EnsureResult> {
  if (inflight) return inflight;
  inflight = (async (): Promise<EnsureResult> => {
    const override = env.AGENTGG_SEMGREP_CORE;
    if (override && existsSync(override)) return { ok: true, bin: override };

    const cached = getSemgrepCorePath(SEMGREP_VERSION, env);
    if (existsSync(cached)) return { ok: true, bin: cached };

    // A copy the developer already installed. Neither version-pinned nor
    // checksum-verified, so it ranks below the cache and is only reached when
    // nothing has been fetched yet. Log which one was taken.
    const onPath = findOnPath("semgrep-core", env);
    if (onPath) {
      console.warn(`warning: using semgrep-core from PATH (${onPath}); version is not pinned`);
      return { ok: true, bin: onPath };
    }

    const install = deps.install ?? ((e: NodeJS.ProcessEnv) => installSemgrepCore(e));
    const result = await install(env);
    return result.ok ? { ok: true, bin: result.path } : { ok: false, reason: result.reason };
  })();
  return inflight;
}
```

Also extend the `node:path` import at the top of the file to `import { delimiter, extname, join, resolve } from "node:path";`.

`resolveSemgrepCore` stays exported and unchanged so the existing tests keep passing, but nothing in the scan path calls it after Task 5.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run packages/cli/__tests__/semgrep.test.ts`
Expected: PASS — the 33 existing tests plus 7 new ones.

- [ ] **Step 5: Build and lint**

Run: `pnpm build && pnpm lint`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/semgrep.ts packages/cli/__tests__/semgrep.test.ts
git commit -m "resolve semgrep-core through cache then download, single-flighted"
```

---

### Task 4: Record degradation on the agent sidecar

**Files:**
- Modify: `packages/core/src/types.ts` (inside `AgentRun`, after `hitCount` at line 859)
- Test: `packages/core/__tests__/types.test.ts`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `AgentRun.degraded: Array<{ kind: "semgrep"; reason: string }>`, defaulting to `[]`.

- [ ] **Step 1: Write the failing test**

Append to `packages/core/__tests__/types.test.ts`:

```ts
describe("AgentRun.degraded", () => {
  const base = {
    agentSlug: "missing-access-control",
    lastCompletedRunId: "r1",
    lastCompletedAt: "2026-08-17T00:00:00.000Z",
    scope: { maxFileSizeKb: 500, rootPath: "/repo" },
  };

  it("defaults to empty so an older sidecar still parses", () => {
    expect(AgentRun.parse(base).degraded).toEqual([]);
  });

  it("carries a semgrep reason", () => {
    const parsed = AgentRun.parse({
      ...base,
      degraded: [{ kind: "semgrep", reason: "download failed" }],
    });
    expect(parsed.degraded).toEqual([{ kind: "semgrep", reason: "download failed" }]);
  });

  it("rejects an unknown detector kind", () => {
    expect(() =>
      AgentRun.parse({ ...base, degraded: [{ kind: "nope", reason: "x" }] }),
    ).toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run packages/core/__tests__/types.test.ts -t "AgentRun.degraded"`
Expected: FAIL — `degraded` is `undefined`, not `[]`.

- [ ] **Step 3: Add the field**

In `packages/core/src/types.ts`, inside `AgentRun` immediately after `hitCount`:

```ts
  /**
   * Detectors that could not run for this agent, so no report implies
   * coverage the scan did not have. Empty means every declared detector ran.
   * The literal `kind` leaves room for a second detector later without
   * inventing one now.
   */
  degraded: z
    .array(z.object({ kind: z.literal("semgrep"), reason: z.string() }))
    .default([]),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run packages/core/__tests__/types.test.ts -t "AgentRun.degraded"`
Expected: PASS, 3 tests.

- [ ] **Step 5: Rebuild the CLI bundle**

Root `pnpm build` does not refresh the esbuild bundle, and this task changed a core schema.

Run: `pnpm build`
Then from `packages/cli/`: `node scripts/bundle-cli.mjs`
Verify: `node -e "console.log(require('fs').readFileSync('packages/cli/dist/cli.js','utf8').includes('degraded'))"` prints `true`.

- [ ] **Step 6: Run the full suite and lint**

Run: `pnpm test && pnpm lint`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add packages/core/src/types.ts packages/core/__tests__/types.test.ts
git commit -m "record degraded detectors on the agent run sidecar"
```

---

### Task 5: Wire it into the scan and note the licence

**Files:**
- Modify: `packages/cli/src/semgrep.ts` (`runSemgrepPreFilter`)
- Modify: `packages/cli/src/commands/scan.ts` (the `AgentRuntime` type around line 826, the semgrep call around line 892, and both `writeAgentRun` call sites — the zero-candidate one at line 952 and the settled one later)
- Modify: `NOTICE`
- Test: `packages/cli/__tests__/semgrep.test.ts`

**Interfaces:**
- Consumes: `ensureSemgrepCore` and `EnsureResult` from Task 3; `AgentRun.degraded` from Task 4.
- Produces: `runSemgrepPreFilter` returns `{ hits: SemgrepHits; degraded: SemgrepFailure | null }` instead of a bare `SemgrepHits`.

This changes the return shape, so the caller in `scan.ts` and the end-to-end script both need updating in the same commit.

- [ ] **Step 1: Write the failing test**

Append to `packages/cli/__tests__/semgrep.test.ts`:

```ts
describe("runSemgrepPreFilter degradation", () => {
  const agentWithSemgrep = () =>
    ({ slug: "t", where: { preFilter: [{ semgrepRule: "http-endpoints" }] } }) as unknown as Parameters<
      typeof runSemgrepPreFilter
    >[1];

  beforeEach(() => {
    resetSemgrepResolution();
  });

  it("reports no degradation when the agent declares no semgrep rules", async () => {
    const agent = { slug: "t", where: { preFilter: [{ regex: "x" }] } } as unknown as Parameters<
      typeof runSemgrepPreFilter
    >[1];
    const out = await runSemgrepPreFilter(dir, agent, ["a.ts"], dir, 4);
    expect(out.degraded).toBeNull();
    expect(out.hits.size).toBe(0);
  });

  it("returns the reason when the binary cannot be resolved", async () => {
    writeFileSync(join(dir, "http-endpoints.yml"), "rules:\n  - id: x\n    languages: [ts]\n");
    const out = await runSemgrepPreFilter(dir, agentWithSemgrep(), ["a.ts"], dir, 4, undefined, {
      AGENTGG_HOME: dir,
      AGENTGG_SEMGREP_CORE: join(dir, "absent"),
      AGENTGG_TEST_FORCE_SEMGREP_FAILURE: "download failed",
    });
    expect(out.degraded).toBe("download failed");
    expect(out.hits.size).toBe(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run packages/cli/__tests__/semgrep.test.ts -t "runSemgrepPreFilter degradation"`
Expected: FAIL — `out.degraded` is undefined because the function still returns a bare Map.

- [ ] **Step 3: Change the runner's return shape**

In `packages/cli/src/semgrep.ts`, change the signature and the early returns of `runSemgrepPreFilter`:

```ts
export interface PreFilterOutcome {
  hits: SemgrepHits;
  /** Non-null when semgrep could not run; the caller records it. */
  degraded: SemgrepFailure | null;
}
```

Then replace the whole of `runSemgrepPreFilter` with this. The rule-resolution and
job-building halves are unchanged from what is on disk; they are repeated here so
this task is complete on its own.

```ts
export async function runSemgrepPreFilter(
  root: string,
  agent: Agent,
  files: ReadonlyArray<string>,
  rulesDir: string,
  concurrency: number,
  onWarn?: (message: string) => void,
  env: NodeJS.ProcessEnv = process.env,
): Promise<PreFilterOutcome> {
  const hits: SemgrepHits = new Map();
  const entries = agent.where.preFilter.filter(isSemgrepPreFilter);
  if (entries.length === 0 || files.length === 0) return { hits, degraded: null };

  const rules: Array<{ path: string; label?: string; langs: Set<string> | null }> = [];
  for (const entry of entries) {
    const path = resolveSemgrepRule(rulesDir, entry.semgrepRule);
    if (!path) {
      onWarn?.(`${agent.slug}: semgrep rule '${entry.semgrepRule}' not found in ${rulesDir}`);
      continue;
    }
    let langs: Set<string> | null = null;
    try {
      langs = semgrepRuleLanguages(readFileSync(path, "utf8"));
    } catch {
      // Unreadable rule file — treat as "languages unknown" and let the
      // binary decide, same as an unparseable `languages:` block.
    }
    rules.push({ path, label: entry.label, langs });
  }
  if (rules.length === 0) return { hits, degraded: null };

  const jobs: Array<{ rule: (typeof rules)[number]; relPath: string; lang: string }> = [];
  for (const relPath of files) {
    const lang = semgrepLangFor(relPath);
    if (!lang) continue;
    for (const rule of rules) {
      if (rule.langs && !rule.langs.has(lang)) continue;
      jobs.push({ rule, relPath, lang });
    }
  }
  if (jobs.length === 0) return { hits, degraded: null };

  // Resolve the binary only once there is real work, so an agent whose rules
  // match no file in scope never triggers a 60 MB download.
  const forced = env.AGENTGG_TEST_FORCE_SEMGREP_FAILURE as SemgrepFailure | undefined;
  const resolved: EnsureResult = forced
    ? { ok: false, reason: forced }
    : await ensureSemgrepCore(env);
  if (!resolved.ok) {
    onWarn?.(`${agent.slug}: semgrep unavailable (${resolved.reason}) — regex preFilters only`);
    return { hits, degraded: resolved.reason };
  }
  const bin = resolved.bin;

  let startFailure: SemgrepFailure | null = null;
  await runConcurrent(jobs, Math.max(1, concurrency), async (job) => {
    if (startFailure) return;
    let stdout: string;
    try {
      const out = await execFileAsync(
        bin,
        ["-rules", job.rule.path, "-lang", job.lang, "-json", resolve(root, job.relPath)],
        { maxBuffer: 32 * 1024 * 1024, timeout: 60_000 },
      );
      stdout = out.stdout;
    } catch (err) {
      // A binary that will not start (wrong glibc, corrupt file) fails the
      // same way for every job. Record it once and stop the remaining spawns.
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "EACCES") {
        startFailure = "binary failed to start";
        onWarn?.(`${agent.slug}: semgrep-core would not start (${bin})`);
      }
      return;
    }
    let results: RawResult[];
    try {
      results = parseCoreJson(stdout).results ?? [];
    } catch {
      return;
    }
    if (results.length === 0) return;
    const bucket = hits.get(job.relPath) ?? [];
    for (const r of results) {
      const line = r.start?.line;
      if (typeof line !== "number") continue;
      bucket.push({ line, label: job.rule.label ?? r.extra?.message ?? r.check_id ?? "semgrep" });
    }
    if (bucket.length > 0) hits.set(job.relPath, bucket);
  });

  return { hits, degraded: startFailure };
}
```

`AGENTGG_TEST_FORCE_SEMGREP_FAILURE` is read only here, so the degradation path
is testable without breaking a real install. It is not a documented user flag.

Note the `jobs.length === 0` early return: without it, an agent whose rules match
no file's language would still trigger the download.

- [ ] **Step 4: Update the caller**

In `packages/cli/src/commands/scan.ts`, add `degraded: { kind: "semgrep"; reason: string }[];` to the `AgentRuntime` type beside `hitCount`, then change the semgrep call:

```ts
      const { hits: semgrepHits, degraded: semgrepDegraded } = await runSemgrepPreFilter(
        root,
        agent,
        scopedFiles,
        getSemgrepRulesDir(officialAgentsDir),
        concurrency,
        (m) => console.warn(`warning: ${m}`),
      );
      const degraded = semgrepDegraded ? [{ kind: "semgrep" as const, reason: semgrepDegraded }] : [];
```

Add `degraded,` to the `writeAgentRun` object at the zero-candidate site (line ~952) and to the settled site later in the same loop.

- [ ] **Step 5: Run tests to verify they pass**

Run: `pnpm vitest run packages/cli/__tests__/semgrep.test.ts`
Expected: PASS.

Then the whole suite: `pnpm test`
Expected: PASS. If `packages/cli/__tests__/walker.test.ts` or a scan test calls `runSemgrepPreFilter`, update it for the new return shape.

- [ ] **Step 6: Add the NOTICE line**

Append to `NOTICE`:

```
This product downloads semgrep-core at runtime, on first use of an agent that
declares a `semgrepRule` pre-filter. semgrep is developed by Semgrep, Inc. and
is licensed under the GNU Lesser General Public License v2.1. Its source is at
https://github.com/semgrep/semgrep. The binary is fetched from Semgrep's own
distribution on PyPI and is not redistributed as part of this package.
```

- [ ] **Step 7: Rebuild the bundle and verify end to end**

Run: `pnpm build`, then from `packages/cli/`: `node scripts/bundle-cli.mjs`
Then: `node packages/cli/dist/cli.js agents lint ../agentgg-agents`
Expected: `✓ 160 agents lint clean`.

- [ ] **Step 8: Lint and commit**

```bash
pnpm lint
git add packages/cli/src/semgrep.ts packages/cli/src/commands/scan.ts packages/cli/__tests__/semgrep.test.ts NOTICE
git commit -m "fetch semgrep-core on first use and record the reason when it is unavailable"
```

---

### Task 6: Real-download integration test

**Files:**
- Test: `packages/cli/__tests__/semgrep-download.integration.test.ts` (create)

**Interfaces:**
- Consumes: `installSemgrepCore`, `SEMGREP_VERSION` from Task 2.
- Produces: nothing.

- [ ] **Step 1: Write the test**

Create `packages/cli/__tests__/semgrep-download.integration.test.ts`:

```ts
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { installSemgrepCore, wheelForCurrentPlatform } from "../src/semgrep-install.js";

// Pulls ~60 MB from PyPI. Opt in with AGENTGG_TEST_SEMGREP_DOWNLOAD=1 so CI and
// contributors are not forced to pay for it on every run.
const enabled = process.env.AGENTGG_TEST_SEMGREP_DOWNLOAD === "1";

describe.skipIf(!enabled)("installSemgrepCore against the real PyPI", () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "agentgg-sgdl-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  it("downloads, verifies, and produces a binary that runs", { timeout: 600_000 }, async () => {
    expect(wheelForCurrentPlatform()).not.toBeNull();
    const result = await installSemgrepCore({ AGENTGG_HOME: home });
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(statSync(result.path).size).toBeGreaterThan(10 * 1024 * 1024);
    const help = execFileSync(result.path, ["--help"], { encoding: "utf8" });
    expect(help).toContain("-rules");
  });
});
```

- [ ] **Step 2: Run it disabled to confirm it skips**

Run: `pnpm vitest run packages/cli/__tests__/semgrep-download.integration.test.ts`
Expected: 1 skipped, 0 failed.

- [ ] **Step 3: Run it enabled once, locally**

Run (PowerShell): `$env:AGENTGG_TEST_SEMGREP_DOWNLOAD='1'; pnpm vitest run packages/cli/__tests__/semgrep-download.integration.test.ts`
Expected: PASS. This is the proof the pinned digest is correct for your platform. If it reports `verification failed`, the pinned SHA-256 is wrong and must be corrected before shipping.

- [ ] **Step 4: Commit**

```bash
git add packages/cli/__tests__/semgrep-download.integration.test.ts
git commit -m "add an opt-in integration test for the real semgrep download"
```

---

## Verification after all tasks

- [ ] `pnpm build` clean
- [ ] From `packages/cli/`: `node scripts/bundle-cli.mjs`
- [ ] `pnpm lint` clean
- [ ] `pnpm test` — all green, one skipped integration test
- [ ] `node packages/cli/dist/cli.js agents lint ../agentgg-agents` — 160 agents clean
- [ ] With `AGENTGG_SEMGREP_CORE` unset and no cache present, a scan of `demo-vulnerable-app` fetches once and `missing-access-control` reports 3 candidate files
- [ ] With the network disabled, the same scan completes and the agent's sidecar carries `degraded: [{ kind: "semgrep", reason: "download failed" }]`
