---
slug: openclaw-audit-allowlist-identity
name: Allowlist Identity Audit (OpenClaw chat-channel extensions)
description: Audits chat-channel extensions for allowlist-bypass bugs where inbound sender/group identity is matched against a mutable field (display name, username, handle, email, group title) without the operator's `dangerouslyAllowNameMatching` opt-in. An attacker who can rename themselves to an allowlisted value slips past the allowlist without the operator ever flipping a dangerous flag.
version: 0.1.0
mode: hunt
noiseTier: normal
filePatterns: []
references:
  - GHSA-8c59-hr4w-qg69
  - GHSA-mj5r-hh7j-4gxf
  - GHSA-c29c-2q9c-pc86
---

You are auditing channel extensions in `extensions/` for one specific
class of CVE: the inbound-message authorization path silently resolves
sender (or group) identity to a mutable field, even though the operator
did not enable `dangerouslyAllowNameMatching`. The operator believes
they're on the hardened ID-only path; the code is actually matching on
something an attacker can change.

This is a code review of the extension source. Operator-config audits
already exist at `src/security/audit-channel.ts` and per-extension
`security-audit.ts` files — do not duplicate those. Focus on the
*implementation*.

## Scope — where the bug actually lives

Every channel extension follows the same layout: `extensions/<channel>/src/`.
Both audit layers concentrate in a small set of well-named files inside
that directory. Open these *first*, in this order, before doing any
wider grep:

1. **`monitor.ts`** — the canonical entry point. Almost always exports
   `monitor<Channel>Provider` / `start<Channel>` and contains both the
   startup resolution pass (Layer 2) and the runtime sender check
   (Layer 1, often as `isSenderAllowed` defined at the top of the file).
   The Zalouser zero-day lived entirely here.
2. **`monitor-*.ts` / `monitor.*.ts` siblings** — channels split this
   file when it gets large (e.g. `bluebubbles/src/monitor-processing.ts`,
   `feishu/src/monitor.message-handler.ts`, `googlechat/src/monitor-access.ts`,
   `telegram/src/monitor-polling.runtime.ts`). The runtime gate often
   migrates to the `*-access.ts` / `*-handler.ts` / `*-processing.ts`
   variant; the startup pass usually stays in `monitor.ts`. Skip
   `*.test.ts` and `*.test-*.ts` unless you need a worked example of
   intended behavior.
3. **`group-policy.ts`** — when present, encapsulates group-route
   matching helpers (e.g. `findZalouserGroupEntry`,
   `buildZalouserGroupCandidates`). Frequently the place where
   `allowNameMatching` becomes a parameter and where forgetting to
   pass it is the bug.
4. **`pairing.ts` / `account-resolve.ts` / `accounts.ts`** —
   secondary surfaces that occasionally hold the runtime check or
   rewrite `account.config`. Worth a glance if `monitor.ts` doesn't
   seem to be doing the matching itself.

Likely-safe-to-skip in most channels (transport/format/codec code, no
authorization decisions): `send.ts`, `client.ts` (the bare API
client, not the wrapper), `attachments.ts`, `media-*`, `*-types.ts`,
ingestion shims. **But:** if the per-channel sweep below finds a
candidate Layer-2 binding step that touches `account.config` or `ctx`,
follow the call graph through *whatever* file holds it — including
`doctor.ts`, `config-schema.ts`, `runtime.ts`,
`account-refresh.ts`, `pairing.ts`, `directory*.ts`,
`resolve*.ts`. The bug-class fingerprint (see Layer 2 below) can
persist authorization state from any of those.

Concretely, the per-channel sweep is: read `monitor.ts` end-to-end,
then `monitor-*.ts` / `monitor.*.ts` siblings end-to-end, then
`group-policy.ts` if present, then any file matching `resolve*.ts` /
`directory*.ts` / `account*.ts` / `refresh*.ts` / `pairing*.ts`.
That is enough source to render a verdict for the channel; broader grep
across `src/` is justified when any of those files imports an
authorization helper or directory-API helper from a less obvious path.

## Two layers — audit both

There are **two separate places** mutable identity can leak past the
flag. The runtime gate is the obvious one; a startup pre-resolution
pass is the sneaky one. A clean runtime gate does not make a channel
safe — confirm both.

### Layer 1 — Runtime sender matching

The `isSenderAllowed`-style helper called per inbound message.
Compares the live sender ID to entries in `allowFrom`/`groupAllowFrom`.
This is what the existing checklist below covers.

### Layer 2 — Identity resolution that mutates authorization state

A code path that takes operator-configured *names* and resolves them to
provider IDs, then **persists those IDs into the data structure the
runtime gate reads from** (`allowFrom` / `groupAllowFrom` / `groups` /
`channelsConfig` / `teamsConfig` / per-channel `users`). Even if the
runtime check is strict ID-only, the IDs it sees can have been derived
from a mutable display-name lookup, and the operator's
`dangerouslyAllowNameMatching` flag was never consulted along the way.

The canonical shape is a once-at-startup pass, but **the design flaw
is not "happens at startup."** It's that **mutable→stable identity
binding is performed without the operator's name-matching flag being
enforced at the binding step.** Anywhere that binding can happen is a
candidate site. See "Where the pattern can hide" below for the
non-obvious variants.

#### Pattern fingerprint

A code site is suspect if it does *all* of these, and is not wrapped
in `isDangerousNameMatchingEnabled` (or equivalent):

1. **Reads operator-configured allowlist entries** — usually `allowFrom`,
   `groupAllowFrom`, `groups`, `channels`, `teams`, or any per-route
   `users`.
2. **Calls a provider directory/roster/search API** that returns
   objects carrying both a stable ID and one or more mutable identity
   fields (`displayName`, `name`, `realName`, `username`,
   `nickname`, `email`, `topic`, `subject`, `groupName`,
   `roomName`, `channelName`, `displayName`, `friendlyName`).
3. **Selects an entry whose mutable field matches the configured name**
   — directly, case-insensitively, or via a search/filter API where the
   *server* does the mutable match (Microsoft Graph
   `$search "displayName:..."`, Matrix `/user_directory/search`,
   Slack `users.list` + filter).
4. **Writes the matched stable ID into authorization state the runtime
   gate later consults** — either by mutating `account.config`, by
   setting `ctx.allowFrom` / `ctx.channelsConfig`, by updating an
   in-memory map keyed by route, or by emitting a side-effect into a
   cache.

If 1–4 are all present and there is no flag check on the binding step,
this is a Layer-2 break regardless of *when* it runs.

#### Reference shape — GHSA-8c59-hr4w-qg69 (zalouser, patched)

```ts
const friends = await listZaloFriends(profile);
const byName = buildNameIndex(friends, (friend) => friend.displayName);
const { additions, mapping } = resolveUserAllowlistEntries(allowFromEntries, byName);
const allowFrom = mergeAllowlist({ existing: account.config.allowFrom, additions });
account = { ...account, config: { ...account.config, allowFrom } };
summarizeMapping("zalouser users", mapping, unresolved, runtime);
```

Each non-numeric `allowFrom` entry was looked up in a name index and
the **first** matching friend's `userId` was injected into the
effective allowlist — without `dangerouslyAllowNameMatching` ever
being checked. Two friends with the same display name → first one back
from the API receives the agent's responses; the legitimate user is
silently denied. Binding flips on each gateway restart based on roster
ordering. The same monitor file already imported and gated other paths
on `isDangerousNameMatchingEnabled(account.config)`; the binding step
was simply missed. The fix gated the resolution block (and the parallel
`groups` block immediately below it) behind that same flag. Telegram
counterpart: GHSA-mj5r-hh7j-4gxf, which additionally validated
non-numeric entries at config-load and surfaced them through
`openclaw doctor`.

#### Where the pattern can hide

The agent should hunt for sites 1–4 above in *all* of these surfaces,
not just the boot pass in `monitor.ts`:

- **Periodic re-resolution.** A `setInterval`/`setTimeout` that
  re-fetches the roster on a schedule and re-runs the binding. The flag
  may be checked at boot but not on the timer callback.
- **Reactive refresh on auth/token rotate.** Account refresh,
  OAuth-renewal, or session-restore hooks that re-resolve names. The
  bind can move when a token rotates.
- **Lazy / first-message resolution.** A cache that resolves a name on
  first inbound message rather than at startup. The runtime gate reads
  the cache after it's been populated by a mutable lookup.
- **Webhook / pairing handlers.** Channels that pair an account by
  clicking a link or scanning a QR code may resolve allowlist entries
  during the pairing step.
- **Roster-mutation event handlers.** Real-time events like
  `member_joined_channel`, `presence`, `roster.update`,
  `room.member` that auto-add resolved IDs to a route's allowlist.
- **`doctor` / config-validate / config-load hooks.** Some channels
  resolve at config-load to "verify" entries; if that resolution writes
  back into the persisted config (instead of just warning), it's the
  same bug.
- **Group / channel name resolution.** The same shape but for *groups*:
  operator writes `groupAllowFrom: ["#general"]` or
  `teams: { "Engineering": {...} }`, code resolves the group/team name
  to a stable channel/conversation ID and merges. Group display names
  are typically settable by group owners.
- **Shadow allowlists in per-route config.** A channel-scoped users
  array (`channels.<id>.users`, `teams.<id>.channels.<id>.users`,
  `rooms.<id>.allowFrom`) that has its *own* resolution block,
  separately from the top-level allowFrom. Adjacent blocks are commonly
  fixed independently — gate the first, miss the second.
- **Synonym fields.** When an entry can carry a typed prefix (`@`,
  `#`, `email:`, `id:`, `mxid:`, `open_id:`), branches that
  strip the prefix and route to a name lookup. The numeric-only
  short-circuit is *not* protection — the non-numeric/non-prefixed
  branch is the vulnerable one.

## What to grep for

The greps below are *entry points* — once you find a candidate site,
walk the call graph until you've identified each of the four
fingerprint elements (configured allowlist read → directory call →
mutable-field match → write into runtime-readable state). The exact
helper names will vary per channel; treat the names below as a starting
set and generalize.

Run these across `extensions/`:

**Layer 1 — runtime gate inputs:**
- `allowFrom`, `groupAllowFrom`, `ownerAllowFrom` — the allowlist
  arrays
- `dmPolicy`, `groupPolicy` — the gates whose `"allowlist"` value
  triggers the matching
- `dangerouslyAllowNameMatching`, `isDangerousNameMatchingEnabled`,
  `allowNameMatching` — every code path that branches on this flag,
  AND every helper that takes it as a parameter (the bug is often
  "caller didn't pass it")
- Identifier-resolution helpers: `resolve*Allowlist*`,
  `normalize*UserId`, `match*Sender`, `is*Allowed`,
  `senderIdentity`, `senderId`, `userKey`,
  `buildAllowlistCandidates`, `buildSender*`

**Layer 2 — identity binding that mutates authorization state:**
- `mergeAllowlist`, `summarizeMapping`, `canonicalizeAllowlist*`,
  `patchAllowlist*` from `plugin-sdk/allow-from` (or local
  equivalents) — every caller. These are the canaries; their presence
  on a path that isn't flag-gated at the binding step is almost always
  a finding.
- Generic name-index helpers: `buildNameIndex`, `byName.get(`, any
  `Map<string, …>` keyed off a mutable field (`displayName`,
  `name`, `nickname`, `username`, `realName`, `topic`,
  `subject`, `groupName`, `roomName`, `channelName`,
  `friendlyName`)
- Resolver helpers by convention: `resolve*Entries`,
  `resolve*AllowlistEntries`, `resolve*Names`, `resolve*Targets`,
  `expand*Allowlist`, `bind*Allowlist`,
  `canonicalize*WithResolved*`
- Provider directory/search calls — anything that returns a list of
  `{id, ...mutableFields}`: `list*Friends`, `list*Contacts`,
  `list*Groups`, `list*Rooms`, `list*Channels`, `list*Members`,
  `list*Peers`, `list*Users`, `list*Teams`, `getRoster`,
  `fetch*Directory`, `getMembers`, `searchUsers`,
  `searchGraphUsers`, `userDirectorySearch`, `users.list`,
  `/users?$filter=displayName`, `/user_directory/search`
- Reassignment of authorization-bearing state:
  `account.config.allowFrom`, `account.config.groupAllowFrom`,
  `account.config.groups`, `ctx.allowFrom`, `ctx.channelsConfig`,
  `ctx.teamsConfig`, `cfg.channels.<channel>.allowFrom`, or any
  `{ ...account, config: { ...account.config, allowFrom: ... } }` /
  `{ ...cfg, channels: { ...cfg.channels, <channel>: { ...allowFrom: ... } } }`
  spread shape

**Cross-cutting:**
- Anything inside a `setInterval` / `setTimeout` / scheduled job in a
  `monitor*` / `account*` / `pairing*` file that calls a directory
  API.
- Handlers wired to roster events (`member_joined`, `presence`,
  `roster.update`, `m.room.member`, `conversationUpdate`).

Also enumerate the extensions directly:
`Glob: extensions/*/src/**/monitor*.ts`, `**/handler*.ts`,
`**/allowlist*.ts`, `**/start*.ts`, `**/init*.ts`, `**/account*.ts`,
`**/pairing*.ts`, `**/refresh*.ts`, `**/resolve*.ts`,
`**/directory*.ts`. The binding step almost always lives in one of
those.

## For each channel, determine

1. **Where authorization happens at runtime.** Find the code that
   decides whether an inbound message is acted on. It usually calls
   something like `allowFrom.includes(senderKey)` or a helper that
   wraps that.
2. **What `senderKey` actually is.** Trace it back to the inbound
   payload. Categorize as:
   - **Immutable** — provider-issued opaque IDs the user cannot change:
     Telegram numeric `from.id`, Discord snowflakes, Slack `U…` IDs,
     Matrix `@user:server`, Nostr pubkey, IRC `account-tag` (NOT nick),
     Mattermost user UUID, LINE `userId`, Synology user ID, QQ
     `tiny_id`/`open_id`, Zalo numeric `userId`.
   - **Mutable** — display names, handles/usernames, emails, group
     titles, IRC nicks, Matrix display names, Telegram `username` (vs
     `id`), Discord `username#discrim` or global name, Slack
     `name`/`real_name`, Mattermost `username`, LINE
     `displayName`, Synology nickname, Zalo `displayName`.
3. **Is the runtime mutable path gated by
   `dangerouslyAllowNameMatching`?** Read the surrounding control
   flow. If the mutable comparison only runs when
   `dangerouslyAllowNameMatching === true`, that's break-glass — out
   of scope for the runtime layer (operator opted in).
4. **Is there an identity-binding step that mutates authorization
   state?** Apply the four-element fingerprint from the Layer-2
   section: configured-allowlist read → directory/search call →
   mutable-field match → write into runtime-readable state. The trigger
   doesn't have to be startup — also check periodic timers, auth-refresh
   hooks, lazy/first-message resolvers, pairing handlers,
   roster-mutation event handlers, and config-load/doctor hooks. If the
   binding step is not wrapped in
   `isDangerousNameMatchingEnabled(account.config)` (or equivalent at
   the *binding* step, not just at the runtime gate downstream), that
   is a Layer-2 break — even if the runtime gate itself is clean.
5. **DM vs group, and the parallel groups block.** Channels with both
   a `groupAllowFrom` resolution block and a `groups` config-key
   resolution block frequently gate one and forget the other (zalouser
   had two adjacent blocks; both needed the gate). Audit each block
   independently. Same pattern at runtime: DM path resolves to ID,
   group path silently falls back to a mutable group title.
6. **Numeric short-circuit is not a fix.** A pattern like
   `if (/^\d+$/.test(entry)) { additions.push(entry); continue; }`
   followed by a name lookup is still broken — the non-numeric branch
   is the vulnerable one. The presence of the numeric short-circuit
   only means the bug is reachable for non-numeric entries (which is
   the documented config form).
7. **Allowlist-entry normalization.** Look at how `allowFrom` entries
   are matched at runtime — if the code lower-cases, trims, strips a
   prefix, or accepts both an ID *and* a name as valid entry forms,
   that's a soft form of name matching. Flag it.
8. **Documented config form.** Before reporting a Layer-1 finding,
   confirm the entry form the code accepts is one operators are
   *documented* to write. Read `config-schema.ts` (or equivalent),
   the channel's README/AGENTS.md, and any example configs. If the
   documented allowFrom shape is "the bare account ID" and the bug only
   fires for an undocumented composite form (e.g. `nick!user@host` on
   IRC, `name#discrim` on Discord) that an operator following the
   docs would not write, the finding is heuristic — record it as
   **unclear** and ask the human to confirm operator intent, do not
   call it broken. The Layer-2 startup-resolution bug class does not
   need this gate because the operator's config is being silently
   *rewritten* — they never see the resolved entry.
9. **Field mutability check.** For each mutable-field finding, confirm
   the field is changeable by the attacker themselves (not just by an
   admin). Slack `profile.display_name`: any workspace member, no
   approval. AAD `displayName`: user-editable in most tenants but
   admins can lock it (note this in the verdict). Matrix `display_name`:
   any user via `/setDisplayName`. If the field requires
   admin/operator action to change, downgrade the verdict — that's a
   chained finding and likely fails the Acceptance Gate below.

## Verdict criteria

- **Broken** — there is a code path where, with no
  `dangerouslyAllowNameMatching` opt-in, an attacker who can rename
  themselves (or rename a group) to an allowlisted value passes the
  gate. This includes:
  - Layer 1: runtime comparison reads a mutable field outside the flag.
  - Layer 2: startup resolution rewrites `account.config.allowFrom`
    (or sibling) using a mutable-field index outside the flag, even if
    the runtime comparison itself is clean.
  Cite file:line for the comparison/resolution call AND the field
  extraction. Note which layer.
- **Risky** — name matching is gated by the flag, but the gate is
  checked at the wrong layer (e.g. flag read once at startup; mutable
  lookup table built unconditionally), the mutable form is
  *additionally* matched as a fallback on the safe path, or only one of
  two parallel blocks (users vs groups) is gated.
- **Safe** — every comparison is against an immutable provider ID, and
  any startup resolution that touches the allowlist is wrapped in the
  flag. Mutable comparisons are absent or strictly behind the flag at
  every layer.
- **Unclear** — the trace got too deep or the identity field is a
  normalized handle that *might* be immutable on this provider; flag
  for human review with the specific question.

## Acceptance Gate — does this finding write up as a GHSA?

OpenClaw's published security policy rejects several finding shapes.
Apply this gate *before* calling something broken — if the chain
depends on any of these, downgrade to risky or unclear:

- **Trusted-operator local feature.** The operator running the gateway
  is trusted; bugs that only fire when a malicious operator
  misconfigures their own host are out of scope. Layer-1/Layer-2
  allowlist bypasses only count when an operator following the
  documented config gets bypassed by a *third party* (a workspace peer,
  a chat-room peer).
- **Multi-tenant gateway.** Findings that require multiple distrustful
  operators sharing a single gateway/host/config are out of scope.
- **Adversarial operator.** If exploitation requires the operator to
  write an undocumented or obviously-unsafe config form, it's
  heuristic.
- **`dangerously*` opt-in already enabled.** If the operator has
  opted in to name matching, mutable-field reads are by design.
- **Parity/heuristic finding.** "Channel X has a flag check that
  channel Y doesn't" is not a finding unless you can show concrete
  exploitation through the documented surface.
- **Supplemental-context visibility / prompt injection.** The agent
  reading attacker text is not allowlist bypass.

The published Slack and zalouser writeups pass this gate cleanly
because: (i) the config is what the docs tell operators to write,
(ii) any non-admin workspace member can perform the renaming,
(iii) no special workspace settings are required, (iv) the bind
persists across an operator-driven restart, (v) the only operator-
facing signal is a verbose log line they don't normally diff.
Reproduce that shape in every Layer-2 report.

## Validated references — example shapes

Use these as calibration, not as a checklist. Each one is a different
*surface* showing the same fingerprint — the agent should generalize
from them, not narrow to them.

- **GHSA-8c59-hr4w-qg69 (zalouser, patched).** Mobile-IM provider,
  friend-list directory. Boot pass resolves non-numeric entries via
  local name index, merges into `account.config.allowFrom`.
  Demonstrates the canonical `mergeAllowlist`-after-name-index shape
  and the parallel-blocks gotcha (DM and groups gated independently).
- **GHSA-mj5r-hh7j-4gxf (telegram, patched).** Numeric-ID provider.
  Demonstrates the config-load surface — non-numeric entries surfaced
  through `openclaw doctor`. Shows the fix can also live at
  config-load if the binding is rejected there.
- **GHSA-c29c-2q9c-pc86 (slack, validated 2026-05-04).** Workspace-IM
  provider, server-side member lookup. Resolution at
  `extensions/slack/src/monitor/provider.ts:389-410` calls
  `resolveSlackUserAllowlist` (`extensions/slack/src/resolve-users.ts:120-123`)
  matching `user.name` / `user.displayName` / `user.realName`.
  Per-channel users block at lines 418-443 is a separately-fixed
  parallel block. PoC shape: vanilla bot install, operator writes
  `allowFrom: ["@displayname"]`, attacker is any workspace peer who
  edits their own `profile.display_name`, takes effect on next
  gateway restart, observable signal is the `summarizeMapping` log
  line. Fix: `if (resolveToken && isDangerousNameMatchingEnabled(slackCfg))`.
- **MS Teams (`extensions/msteams/src/monitor.ts:104-198`) — same
  shape, server-side search.** Microsoft Graph `$search "displayName:..."`.
  Notable because the search is *server-side* — no client-side name
  index exists; the bug fingerprint still applies because the *server*
  does the mutable match and returns the stable GUID. Three parallel
  blocks (`allowFrom`, `groupAllowFrom`, `teamsConfig`) all
  ungated.
- **Matrix (`extensions/matrix/src/matrix/monitor/config.ts:192-217`)
  — same shape, no flag wired at all.** Homeserver
  `/user_directory/search`. The extension has zero references to
  `dangerouslyAllowNameMatching` — there is no opt-in path; this is a
  wholly missing security control rather than a missed gate. Same bug
  class.

**Generalize from these:** the directory call can be (a) a local index
built from a roster fetch, (b) a server-side search where the provider
returns matches, or (c) a username-resolution endpoint. The persistence
target can be (a) `account.config.allowFrom`, (b) a context object
the runtime gate reads, (c) a per-route nested config map, or (d) a
cache. The trigger can be (a) startup, (b) a timer, (c) an auth
refresh, (d) a roster event, (e) first-message lazy resolution. The
flag check is missing in *one* of the layered code paths even when
other paths in the same file are gated. Look for the *shape*, not the
syntax.

## Channels to prioritize

Known-broken (validated, expect or have GHSAs): `slack`, `msteams`,
`matrix`. Audit these first to ground-truth your understanding of the
Layer-2 shape, then sweep the rest.

Untouched / least-scrutinized at time of writing: `line`, `nostr`,
`tlon`, `twitch`, `nextcloud-talk`, `qqbot`, plus the WeChat
surface (look under `tencent/` if no `wechat/` dir exists). Then
sweep `discord`, `googlechat`, `synology-chat`, `irc`,
`mattermost`, `feishu` — they support
`dangerouslyAllowNameMatching` so the bug shape is "name matching
leaks out from behind the flag." `zalouser` and `telegram` are
patched but useful as fix references.

Any extension that imports `mergeAllowlist` or `summarizeMapping`
from `plugin-sdk/allow-from` is doing startup resolution and must be
checked.

## Report format

Group findings by verdict, then by channel. Each finding's
`title` / `summary` / `details` / `poc` / `impact` fields
should reflect the shape below. In `details`, include the structured
metadata as a labeled block:

```
Layer:    <runtime / startup / refresh / lazy / event / pairing / config-load / both>
Gate:     <file:line of the allowlist comparison>          # for runtime findings
Bind:     <file:line of the mutable->stable resolution call> # for layer-2 findings
Persist:  <file:line where the resolved ID is written into authorization state>
Field:    <the mutable field, e.g. friend.displayName, profile.display_name, AAD displayName>
Source:   <where the field comes from — inbound payload, or which provider directory/search API>
Trigger:  <what causes the binding step to run — startup, timer (cite interval), token refresh, pairing handler, first message, roster event>
Flag:     <gated by dangerouslyAllowNameMatching at the binding step? yes / no / partial / not-wired>
Paths:    <DM / group / per-channel-users / per-team-channel / both>
Config:   <the documented operator-config form that triggers the bug, e.g. allowFrom: ["@displayname"]>
Attacker: <who performs the rename — workspace peer, room peer, group member, AAD user; what privilege they need; whether admin approval is involved>
Trigger2: <what makes the bind take effect — restart, timer fire, first-message-since-rename, etc.>
Signal:   <observable signal in operator logs/UI that this happened — usually summarizeMapping line>
Acceptance: <does this pass the GHSA Acceptance Gate? yes / chained / heuristic — and which gate clauses if not>
```

Prefer five solid findings over thirty maybes — every broken verdict
needs a concrete attacker action, a cited line, and an explicit
Acceptance verdict.
