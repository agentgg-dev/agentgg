# Semgrep binary distribution

Date: 2026-08-17
Status: approved, not yet implemented

## Problem

`where.preFilter` gained a `semgrepRule` form. It works, but only on a machine
that already has `semgrep-core` and an `AGENTGG_SEMGREP_CORE` pointing at it.
A user who runs `npm install -g agentgg` gets nothing, and the agents that
declare a `semgrepRule` quietly lose the coverage that rule provides.

This spec covers how the analysis binary reaches a user's machine.

## Constraints

Four decisions were settled before this design and are not revisited here.

1. **Acquisition is lazy.** The binary is fetched the first time a scan
   actually needs it, cached under `~/.agentgg`, exactly as the agent catalog
   already behaves. Not at install, and not via a `postinstall` script, which
   breaks under `npm --ignore-scripts` and in locked-down CI images.
2. **Failure degrades and is recorded.** An agent whose semgrep rule cannot
   run still runs its regex preFilters. The scan does not fail, and the record
   says coverage was reduced so no report implies coverage the scan lacked.
3. **Four platforms:** `darwin-arm64`, `linux-x64`, `linux-arm64`,
   `win32-x64`. CI covers three of them (`ubuntu-latest`, `macos-latest`,
   `windows-latest`); `linux-arm64` ships without CI coverage by choice.
4. **Fetched from PyPI, not mirrored.** Semgrep publishes wheels for all four
   targets. The user's machine pulls from Semgrep's own distribution, so
   agentgg never redistributes the binary.

The alternative considered and rejected was the esbuild pattern: four
per-platform npm packages in `optionalDependencies`. It gives a working binary
with no runtime fetch and inherits npm's integrity, but it ends the
one-published-package setup, requires a Trusted Publisher registration per new
package name before the OIDC release workflow can publish it, and charges every
install about 55 MB of download and 230 MB of disk for a feature most scans do
not currently reach.

## Sizes

Wheels are 47 to 69 MB compressed. The extracted `semgrep-core` is about
230 MB on Windows; other platforms are the same order and have not been
measured.

| Platform | Wheel | Download |
|---|---|---|
| darwin-arm64 | `macosx_11_0_arm64` | 47.2 MB |
| linux-x64 | `manylinux_2_34_x86_64` | 66.6 MB |
| linux-arm64 | `manylinux_2_34_aarch64` | 68.6 MB |
| win32-x64 | `win_amd64` | 54.8 MB |

`manylinux_2_34` requires glibc 2.34 or newer. Older distributions get a binary
that will not start; that path degrades (see below). musl builds exist upstream
and are out of scope while the platform's images are Debian based.

## Resolution order

First hit wins:

1. `AGENTGG_SEMGREP_CORE` — an explicit path. This is the escape hatch for the
   platform's container image, which bakes its own binary, and for any user who
   does not want the download.
2. `~/.agentgg/semgrep/<semgrep-version>/semgrep-core[.exe]` — the cache,
   keyed by version so a pinned-version bump does not collide with an old copy.
3. `semgrep-core` on `PATH` — a developer who already has semgrep installed.
4. Fetch from PyPI.

## Pinned constants

The CLI carries the target semgrep version and a per-platform table of wheel
filename plus expected SHA-256. Both are fixed at build time, so they are
covered by the existing npm provenance attestation on the `agentgg` tarball.
Bumping semgrep is a deliberate edit to that table, not an automatic follow of
upstream.

## Fetch

1. Request the PyPI JSON metadata for the pinned version.
2. Select the wheel whose filename matches the pinned filename for this
   platform. A platform with no entry is unsupported; degrade immediately
   without any network call.
3. Download the wheel.
4. Verify the bytes against the pinned SHA-256 **before** opening the archive.
   A mismatch deletes the download and degrades. The binary is never executed
   unverified.
5. Extract only `semgrep/bin/semgrep-core` with `adm-zip`, already a
   dependency.
6. Set the executable bit on POSIX.
7. Write a `.version.json` marker, matching what `installOfficialAgents` does.

Resolution is attempted once per scan process, not once per agent, and is
single-flighted so concurrent agents cannot race into two downloads. The
trigger is lazy: nothing is fetched unless an agent with a `semgrepRule`
preFilter is about to run.

## Degradation

When resolution fails, the agent runs with its regex preFilters only and the
reason is recorded on its `AgentRun` sidecar, beside the existing
`precondition`, `findingCount`, and `filesReviewed` fields that the reporters
already read.

```ts
/**
 * Detectors that could not run this scan, so no report implies coverage the
 * scan did not have. Empty means every declared detector ran.
 */
degraded: z
  .array(z.object({ kind: z.literal("semgrep"), reason: z.string() }))
  .default([]),
```

The literal `kind` leaves room for a second detector later without inventing
one now.

Four reasons, kept distinct because each calls for a different user response:

| Cause | Reason |
|---|---|
| No pinned wheel for this platform (Intel Mac, musl, other arch) | unsupported platform |
| Downloaded but will not start (glibc older than 2.34) | binary failed to start |
| Network failure, or PyPI unreachable | download failed |
| SHA-256 mismatch | verification failed |

The first failure is cached in memory for the process, so a scan with 160
agents does not retry a dead network 160 times.

Agents that declare no `semgrepRule` are untouched by all of this and never
trigger a fetch.

## Testing

Unit tests, with the fetch injected so nothing touches the network:

- platform to wheel-entry mapping, including the unsupported case
- resolution order, including the `AGENTGG_SEMGREP_CORE` override winning
- cache hit skipping the fetch entirely
- checksum mismatch rejecting the file and not extracting it
- single-flight: two concurrent callers produce one download
- the degraded record carrying the right reason for each of the four causes

One integration test performs a real download and runs the binary, gated behind
an environment flag so CI and contributors are not forced to pull 60 MB.

## Licensing

agentgg does not redistribute the binary under this design, so the LGPL-2.1
duties that bundling would carry largely fall away. `NOTICE` gains a line
stating that semgrep is fetched at runtime, is LGPL-2.1, and where its source
is. This is not required, but it is cheap and honest.

Separately and already settled: only rules written by us ship in
`agentgg-agents/semgrep-rules/`. Semgrep's registry rules are licensed for
internal business use only and cannot be served to others as a service, so the
`semgrepRule` field takes a name resolved against the local rules directory and
can never reference a registry pack.

## Out of scope

- Per-platform npm packages.
- Intel Mac (`darwin-x64`) and musl builds.
- A prefetch or `agentgg semgrep install` command.
- The platform's Dockerfile, which sets `AGENTGG_SEMGREP_CORE`.

## Known risks

- `linux-arm64` ships without CI coverage.
- Users behind a proxy that blocks PyPI get the degraded path on every scan.
  If that becomes a real complaint, mirroring the binaries to the agentgg
  GitHub release is the fallback, at the cost of hosting and the full LGPL
  duties.
- The pinned SHA-256 table must be updated whenever the semgrep version is
  bumped, or every fetch fails verification. A test should assert the table has
  an entry for each supported platform.
- A `semgrep-core` picked up from `PATH` (resolution step 3) is neither
  version-pinned nor checksum-verified. It may be older or newer than the
  version the rules were written against, which can change results. It ranks
  below the cache deliberately, so it is only reached when nothing has been
  fetched yet, and its version should be logged when used.
