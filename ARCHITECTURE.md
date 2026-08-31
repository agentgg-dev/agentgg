# ARCHITECTURE

One-page reference for what's wired and how. User-facing docs are in [README.md](./README.md); start there if you're using agentgg rather than working on it.

## Scan pipeline

`agentgg scan` runs as a pipeline, orchestrated by [`scan.ts`](packages/cli/src/commands/scan.ts). The first two phases each write a durable artifact under `state/`, so the steps are inspectable (and, later, distributable):

1. **Recon** — one tool-enabled survey of the repo via the built-in recon agent ([`src/agents/recon.md`](packages/cli/src/agents/recon.md), loaded by [`recon-agent.ts`](packages/cli/src/recon-agent.ts)). Produces a concise `ReconReport` → `state/recon.json`. Cached by `reconHash` (source identity + `fingerprint` tags); `--re-recon` forces a refresh, `--no-recon` skips it entirely. The brief is injected into precondition prompt checks and into every agent's detection prompt.
2. **Precondition** — for each selected agent, decide queued vs skipped ([`precondition.ts`](packages/cli/src/precondition.ts)). The decisions (with reasons) are written to `state/plan.json` **before any agent runs**. Reused like recon: when a `plan.json` already matches the recon brief and covers the `-t` selection, the for-loop is skipped and its decisions are lifted from disk (`--re-recon` re-evaluates; `--no-recon` bypasses gating and queues every `-t` agent).
3. **Run** — each queued agent runs over its `where` file set, in batches.
4. **Validate** (`--scope` for rules), **Score**, and **Dedup** — second-pass passes over the findings. All three run by default; disable individually with `--no-validate` / `--no-score` / `--no-dedup`.
5. **Report** — per-finding `findings/*.md` + `summary.md`. Skippable with `--no-summary` (state still persists); regenerate later with `agentgg summary`. `--serve` (opt-in) boots the viewer once the report is written.

Each phase is also a standalone command over the same `--output` dir, sharing the artifacts above: **`agentgg recon`** (phases 1–2 only, no detection), **`agentgg revalidate`** (phase 4 validate), **`agentgg score`** (phase 4 score), **`agentgg summary`** (phase 5). `recon` writes `recon.json` + `plan.json` that a later `scan` reuses — the durable plan→run hand-off.

## Create pipeline

`agentgg create` ([`commands/create.ts`](packages/cli/src/commands/create.ts) → [`create.ts`](packages/cli/src/create.ts)) is a standalone, single-shot flow that takes a past security report and emits a new agent `.md` shaped for the codebase the report came from. No `state/` dir, no resume, no recon brief — just one tool-enabled LLM session per report.

1. **Resolve reports** — [`report-loader.ts`](packages/cli/src/report-loader.ts) turns `--report` (a `.md`/`.txt` file, a directory of them, or a `.txt` list of paths) into a `LoadedReport[]`. A `.txt` is auto-detected as a list iff every non-blank, non-comment line resolves to an existing path.
2. **Distill** — for each report, call `detector.createAgent` (see Detector contract). The built-in instructions live in [`src/agents/create.md`](packages/cli/src/agents/create.md), loaded by [`create-agent.ts`](packages/cli/src/create-agent.ts) the same way recon loads its prompt. The wrapper in [`detect.ts`](packages/cli/src/detect.ts) (`buildCreateAgentPrompt`) appends the report verbatim plus the scope rules. The model returns an `AgentSpec` (the LLM-authored subset of `Agent`: slug, name, description, noiseTier, references, precondition, where, prompt body), schema-constrained by Zod at the protocol layer.
3. **Render + lint** — [`agent-spec.ts`](packages/cli/src/agent-spec.ts) renders the spec to the standard agent `.md` shape (YAML frontmatter + body), then round-trips it through `parseAgentMarkdown` from `@agentgg/core` to catch bad regex, malformed slug, or schema mismatch before write.
4. **Write** — filename is `<slug>-<shortHash>.md` where the hash is `sha256(codeRoot|reportPath|reportContent).slice(0, 8)`. Reruns on identical inputs overwrite in place; different reports never collide.

The generated agents land in `--output` only. Installing them (so `scan` picks them up) is an explicit follow-up: `agentgg agents add <output-dir>`.

## The unified agent

There is one agent shape — no `mode`. Every agent declares a `precondition`, a `where`, and a prompt body (the instructions), and is always tool-enabled (Read/Glob/Grep). At runtime:

- **Precondition** ([`precondition.ts`](packages/cli/src/precondition.ts)) — a `regex` block (file `extensions` / `files` / `directories` / content `patterns`) is pure filesystem work; a `prompt` is one cheap LLM call that sees the recon brief; both present = AND; neither = always run. Regex short-circuits before the LLM.
- **Where** ([`walker.ts`](packages/cli/src/walker.ts)) — when the agent declares `extensions` and/or `filePatterns`, the walker enumerates matching files (a bare directory/path matches everything under it) minus `excludePatterns`, then `preFilter` regexes narrow to files with a line hit (and surface those lines as anchors). An agent that declares neither has no file scope (`hasFileScope` returns false): the walker is skipped entirely, the whole repository is its scope, and it finds its own targets with Read/Glob/Grep at a higher turn budget (150 vs 50; see the CLI flags table below).
- **Run** — a scoped agent's candidates are chunked into batches of `where.maxFilesPerBatch` (default 5); each batch is one tool-enabled session (`detector.runAgent`). An agent with no file scope runs as a single session with no seeded files. Batches from every queued agent are flattened into a single scan-wide pool capped by `--concurrency`, so different agents' batches interleave (safe because per-file writes are namespaced by `agent.slug`). A session can read beyond its seeded files to confirm a finding. One agent per session; findings are stamped with the agent's slug.

Declare a scope whenever you can: a scoped agent reports how many candidate files it reviewed against a known total, while an agent with no file scope can't say what fraction of the repository it covered. No file scope is for a question with no syntax to anchor on, such as whether a control is missing everywhere rather than misused somewhere.

## Detector contract

Backend-agnostic ([`detect.ts`](packages/cli/src/detect.ts)). One `Detector` is held for the whole scan:

- `recon` — tool-enabled survey → `ReconResult`.
- `suggestExcludes` — `--auto-exclude` only; one no-tools call over the directory layout → folder globs to skip (`SuggestExcludesResult`).
- `checkPrecondition` — one-shot LLM relevance gate (no tools) → `{ relevant, reason }`.
- `runAgent` — tool-enabled investigation over a batch of seeded files → `Finding[]`.
- `validateFinding` / `validateFindingByScope` — second-pass classifier.
- `scoreFinding` — picks the 8 CVSS 3.1 base metrics.
- `createAgent` — `agentgg create` only; tool-enabled session that reads a past security report and explores the repo → `AgentSpec`. Optional on the interface so a backend can opt out; every shipped detector implements it.

### Dispatch engines

Three implementations in [`detectors/`](packages/cli/src/detectors/):

- **`ClaudeAgentDetector`** — wraps `@anthropic-ai/claude-agent-sdk` (spawns the `claude` CLI), SDK-enforced structured output. Handles both Anthropic auth types. `recon`/`runAgent` get `["Read","Glob","Grep"]`; precondition/validate/score get `tools: []`.
- **`VercelAgentDetector`** — Vercel AI SDK. Tool-using methods (`recon`, `runAgent`) use a hand-rolled multi-step `generateText` loop (Read/Glob/Grep as `tool()` defs, TPM-retry, JSON parsed from the final text with a `structuredModel` reformat fallback); no-tool methods use `generateObject`. The tool implementations are bounded to the scan root and honor the exclude set.
- **`MultiProviderDetector`** — `generateObject` with strict structured output, no tools. Its `recon`/`runAgent` are best-effort (work from prompt context only, no file browsing).

Provider → detector:
- **Anthropic** (API key + OAuth) → `ClaudeAgentDetector` for every method.
- **OpenAI / Bedrock / Vertex / OpenRouter** → `VercelAgentDetector` for every method.
- **Ollama** → a composite: tool-using calls (`recon`, `runAgent`) → `VercelAgentDetector` (best-effort JSON); no-tool calls (`checkPrecondition`, `validate`, `score`) → `MultiProviderDetector`.

Notes: Anthropic via the Vercel SDK was dropped (OAuth tokens get rate-limited; `mode: "json"` is rejected). Ollama splits because `structuredOutputs: true` (required for `generateObject`) conflicts with tool-calling. Vertex routes through `@ai-sdk/openai` against the Model Garden OpenAI-compatible endpoint with a `fetch` middleware stamping Google ADC tokens; GLM-5's non-standard `message.reasoning_content` is ignored by the JSON extractor. OpenRouter uses the same `@ai-sdk/openai` path against `openrouter.ai/api/v1`, with a `fetch` middleware that injects an OpenRouter provider-routing block (fp8 + tool-calling by default; tunable via `--openrouter-routing` / `OPENROUTER_*`). The reasoning/content split that Vertex handles above is, on OpenRouter, the individual host's job, and hosts get it wrong: one that returns the model's whole answer as `reasoning` leaves `message.content` empty, so `generateObject` throws `NoObjectGeneratedError` on a response the transport layer sees as successful. `OPENROUTER_IGNORE` exists to drop such a host, since no retry or fallback can detect it.

## Provider registry

Providers are standalone modules under [`providers/`](packages/cli/src/providers/). Adding one = a module + an entry in [`providers/index.ts`](packages/cli/src/providers/index.ts) + a `Provider` enum entry + a `UserConfig` block in [`core/types.ts`](packages/core/src/types.ts). No edits to `llm.ts` / `init.ts` / `config.ts` / `scan.ts`. Each `ProviderModule` carries `buildDetector`, `collectCredentials`, `acceptedFlags` (passing a flag the active provider doesn't accept is a hard error), `curatedModels`/`listModels`, and `formatForList`/`redact`.

## File selection & default excludes

The walker is a **pure enumerator** — it applies only the `excludePatterns` it's handed and carries no built-in policy. The shared default skip set (`node_modules`, `.git`, build dirs, lockfiles, binaries) lives as data in `DEFAULT_EXCLUDES` ([`walker.ts`](packages/cli/src/walker.ts)) and is merged in by `scan.ts`. It can be dropped globally (`--no-default-excludes`) or per-agent (`where.useDefaultExcludes: false`). CLI `--exclude` paths are always applied (treated as deleted) and, on the Vercel tool path, enforced at the tool layer so a tool read can't reach them. (The Claude Agent SDK's built-in tools aren't bounded, so there it's prompt-level only.)

Auto-exclude ([`smart-exclude.ts`](packages/cli/src/smart-exclude.ts)) is **on by default** (`--no-auto-exclude` disables it) and runs **before recon**: a no-tools LLM call classifies the directory layout and returns folders not worth scanning (tests, fixtures, docs, generated output, vendored deps). Those globs are folded into `excludePatterns` exactly like a CLI `--exclude`, so recon, the precondition census, and every agent inherit them (and they fold into the resume scope signature). It only removes folders. A pass failure is advisory — the scan continues with no auto-excludes.

## Persistence & resume

```
out/
├── summary.md
├── findings/...
└── state/
    ├── scan.json          ← root + timestamps
    ├── recon.json         ← ReconReport (phase 1)
    ├── plan.json          ← ScanPlan: queued/skipped decisions (phase 2)
    ├── usage.json         ← ScanUsage: LLM token usage (input / output / cached) for this invocation
    ├── runs/<id>.json     ← RunMeta per scan / recon / revalidate / score / summary
    ├── agents/<slug>.json ← AgentRun resume sidecar (one per agent)
    └── files/<path>.json  ← FileRecord per scanned source file
```

`usage.json` (`ScanUsage`) records how many tokens a run actually spent — input, output, and prompt-cached, plus a call count. The detector checkpoints it as the run proceeds (written incrementally, force-flushed on SIGTERM), so even an interrupted run leaves an accurate tally. It's purely an observability surface: the CLI records raw counts and doesn't price or bill anything (you run your own model) — whatever reads `usage.json` (a dashboard, a CI summary, your own accounting) decides what to do with the numbers. One file per invocation, written for every provider: the Vercel AI SDK path (`vertex` / `openai` / `bedrock` / `openrouter`), the Claude Agent SDK (Anthropic, from its `result` message's `usage`), and the structured-output path (Ollama).

Resume:
- **Recon + plan** — a `recon.json` whose `reconHash` matches is reused without re-surveying; a `plan.json` with the same `reconHash` that covers the current `-t` selection is reused without re-running the precondition for-loop (`scan.ts` reads `readScanPlan` and filters the selection to the plan's queued slugs). `--re-recon` forces both to recompute.
- **Per-agent** — an agent is skipped on re-run when its `AgentRun` sidecar matches the current scope (source identity + diff + excludePatterns + includePatterns + maxFileSizeKb + **reconHash**); prior findings are lifted from disk. An agent only writes its sidecar on full completion, so an interrupted agent re-runs in full.
- **Per-file** — within an agent, a `(file, agent)` pair is skipped when the `FileRecord` shows a prior `detect` with the same `contentHash` and agent slug.

`--rescan` bypasses resume. Changing scope (`--diff`, `--exclude`, `--only`, `--max-file-size`, source identity) or the recon brief (`--re-recon` / a stack change) invalidates the affected agents. Source identity is the absolute scan root unless `--source-id <id>` overrides it; the override is what lets a distributed runner (or a CI job with a moving checkout path) extract the same source to a different path each run and still resume. It is recorded verbatim as `scope.rootPath` on the sidecar and `rootPath` on `plan.json`, and is never resolved as a path. `--no-recon` uses a synthetic `reconHash` (`"no-recon"`) and queues every `-t` agent, so its runs resume independently of recon-bearing runs.

## Validator & scoring

Three Detector methods, so any provider participates without bespoke wiring:
- **`validateFinding`** — full classifier; re-reads source → `confirmed` / `false-positive` / `out-of-scope` / `uncertain` + reasoning. Used by `--validate` and `agentgg revalidate`.
- **`validateFindingByScope`** — cheap variant, no source read; only `out-of-scope` / `uncertain`. Triggered by an explicit `--scope <path>` combined with `--no-validate` (a pre-filter that stands in for the full validator when it's turned off).
- **`scoreFinding`** — picks the 8 CVSS 3.1 base metrics; vector string, base score, and severity bucket are computed deterministically in [`scoring.asCvssScore`](packages/cli/src/scoring.ts). Triggered by `--score` or `agentgg score`.

## CLI flags

| Flag | Applies to | Notes |
|---|---|---|
| `--max-turns <n>` | recon, agent runs, validator | When set, a uniform cap. Unset: agent batches use `where.maxTurnsPerBatch`, defaulting to 50 for a scoped agent and 150 for one with no file scope; recon 50, validator 50. |
| `--max-files-per-batch <n>` | agent runs | Candidate files per batch. Overrides `where.maxFilesPerBatch` (default 5). |
| `--concurrency <n>` | precondition gates, agent runs, validation, scoring | One scan-wide cap on in-flight LLM sessions. Phase 3 flattens every `(agent, batch)` pair into a single pool; validation and scoring fan out one finding per session through the same `runConcurrent` worker pool. Default 5. |
| `--re-recon` | recon + plan | Re-run recon **and** re-evaluate the precondition plan instead of reusing the cached brief/plan. |
| `--no-recon` | recon + precondition | Skip the survey and the gating loop; run every `-t` agent unconditionally with no injected brief. |
| `--no-summary` | report | Skip rendering `summary.md` + `findings/*.md`. Also accepted by `revalidate` / `score`. State still persists; render later with `agentgg summary`. |
| `--effort` / `--thinking` | provider-dependent | Reasoning knobs. `--effort` → Claude SDK effort (Anthropic) or `reasoning_effort` (OpenAI **reasoning models only** — a non-reasoning model returns HTTP 400); `--thinking` is Anthropic-only. No-op on providers that don't map them. |
| `--diff <commit>` | agent runs | Each agent's candidate list is intersected with the touched files; the commit patch is injected as a focus hint. Accepts `<ref>`, `a..b`, `a...b`. |
| `--exclude` / `--only` / `--max-file-size` / `--no-default-excludes` | file selection | Walk filters. `--exclude` = deleted; `--only` restricts; `--no-default-excludes` drops the built-in skip set. |
| `--auto-exclude` / `--no-auto-exclude` | file selection (pre-recon) | LLM pass that picks non-runtime folders to skip, folded in like `--exclude`. **On by default**; `--no-auto-exclude` disables. Logged (reasons under `--verbose`). |
| `--validate` / `--no-validate` / `--revalidate-all` / `--scope` | post-detection | Validation passes (see above). **On by default**; `--no-validate` for a detection-only run. |
| `--score` / `--no-score` / `--rescore` | post-detection | CVSS scoring pass. **On by default**; `--no-score` to skip. |
| `--dedup` / `--no-dedup` / `--delete-duplicates` | post-detection | De-duplication pass, clustering same-root-cause findings per file. **On by default**; `--no-dedup` to skip. |
| `--serve [port]` | after report | Boot the local web UI when the scan finishes. Opt-in (default port 3737). |

## Frontmatter vs CLI precedence

**CLI flag wins → frontmatter → hardcoded default.** Batch size and per-batch turns:

```
batchSize        = opts.maxFilesPerBatch ?? agent.where.maxFilesPerBatch (default 5)
maxTurnsPerBatch = opts.maxTurns         ?? agent.where.maxTurnsPerBatch ?? (50 scoped / 150 no file scope)
```

## Tool restriction

`ClaudeAgentDetector` passes `tools: ["Read","Glob","Grep"]` for `recon`/`runAgent` and `tools: []` for the precondition gate / validator / scorer. The SDK option `tools` controls what's in the model's context (not `allowedTools`, which only governs auto-approval and is a no-op under `bypassPermissions`).

`VercelAgentDetector` declares the same three tools via `tool()` definitions and runs them in a multi-step `generateText` loop. The implementations are bounded to the scan root and skip excluded paths.

## Packages

- [`packages/core/`](packages/core/) — types (`Agent`, `Precondition`, `Where`, `ReconReport`, `ScanPlan`, `Finding`, `FileRecord`, `AgentRun`, `UserConfig`, `CvssScore`), CVSS math, `fingerprint`, persistence helpers (`writeFileRecord` / `readAgentRun` / `writeReconReport` / `writeScanPlan` / …), agent loader, path resolution.
- [`packages/cli/`](packages/cli/) — commander wiring, detectors, providers, recon, precondition, walker, validator, scoring, reporters, the built-in `recon` and `create` agents ([`src/agents/`](packages/cli/src/agents/)), the `AgentSpec` schema + renderer ([`src/agent-spec.ts`](packages/cli/src/agent-spec.ts)) used by `agentgg create`, viewer bootstrap.
- [`packages/viewer/`](packages/viewer/) — Next.js app served by `agentgg view` / `agentgg scan --serve`.
