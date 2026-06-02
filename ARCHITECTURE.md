# ARCHITECTURE

One-page reference for what's wired and how. User-facing docs are in [README.md](./README.md); start there if you're using agentgg rather than working on it.

## Scan pipeline

`agentgg scan` runs as a pipeline, orchestrated by [`scan.ts`](packages/cli/src/commands/scan.ts). The first two phases each write a durable artifact under `state/`, so the steps are inspectable (and, later, distributable):

1. **Recon** — one tool-enabled survey of the repo via the built-in recon agent ([`src/agents/recon.md`](packages/cli/src/agents/recon.md), loaded by [`recon-agent.ts`](packages/cli/src/recon-agent.ts)). Produces a concise `ReconReport` → `state/recon.json`. Cached by `reconHash` (root + `fingerprint` tags); `--re-recon` forces a refresh, `--no-recon` skips it entirely. The brief is injected into precondition prompt checks and into every agent's detection prompt.
2. **Precondition** — for each selected agent, decide queued vs skipped ([`precondition.ts`](packages/cli/src/precondition.ts)). The decisions (with reasons) are written to `state/plan.json` **before any agent runs**. Reused like recon: when a `plan.json` already matches the recon brief and covers the `-t` selection, the for-loop is skipped and its decisions are lifted from disk (`--re-recon` re-evaluates; `--no-recon` bypasses gating and queues every `-t` agent).
3. **Run** — each queued agent runs over its `where` file set, in batches.
4. **Validate** (`--validate` / `--scope`) and **Score** (`--score`) — second-pass passes over the findings.
5. **Report** — per-finding `findings/*.md` + `summary.md`. Skippable with `--no-summary` (state still persists); regenerate later with `agentgg summary`.

Each phase is also a standalone command over the same `--output` dir, sharing the artifacts above: **`agentgg recon`** (phases 1–2 only, no detection), **`agentgg revalidate`** (phase 4 validate), **`agentgg score`** (phase 4 score), **`agentgg summary`** (phase 5). `recon` writes `recon.json` + `plan.json` that a later `scan` reuses — the durable plan→run hand-off.

## The unified agent

There is one agent shape — no `mode`. Every agent declares a `precondition`, a `where`, and a prompt body (the instructions), and is always tool-enabled (Read/Glob/Grep). At runtime:

- **Precondition** ([`precondition.ts`](packages/cli/src/precondition.ts)) — a `regex` block (file `extensions` / `files` / `directories` / content `patterns`) is pure filesystem work; a `prompt` is one cheap LLM call that sees the recon brief; both present = AND; neither = always run. Regex short-circuits before the LLM.
- **Where** ([`walker.ts`](packages/cli/src/walker.ts)) — the walker enumerates files by `extensions` + `filePatterns` (a bare directory/path matches everything under it) minus `excludePatterns`, then `preFilter` regexes narrow to files with a line hit (and surface those lines as anchors). Empty `where` = all files.
- **Run** — candidates are chunked into batches of `where.maxFilesPerBatch` (default 5); each batch is one tool-enabled session (`detector.runAgent`), run concurrently (`--concurrency`). A session can read beyond its seeded files to confirm a finding. One agent per session; findings are stamped with the agent's slug.

## Detector contract

Backend-agnostic ([`detect.ts`](packages/cli/src/detect.ts)). One `Detector` is held for the whole scan:

- `recon` — tool-enabled survey → `ReconResult`.
- `checkPrecondition` — one-shot LLM relevance gate (no tools) → `{ relevant, reason }`.
- `runAgent` — tool-enabled investigation over a batch of seeded files → `Finding[]`.
- `validateFinding` / `validateFindingByScope` — second-pass classifier.
- `scoreFinding` — picks the 8 CVSS 3.1 base metrics.

### Dispatch engines

Three implementations in [`detectors/`](packages/cli/src/detectors/):

- **`ClaudeAgentDetector`** — wraps `@anthropic-ai/claude-agent-sdk` (spawns the `claude` CLI), SDK-enforced structured output. Handles both Anthropic auth types. `recon`/`runAgent` get `["Read","Glob","Grep"]`; precondition/validate/score get `tools: []`.
- **`VercelAgentDetector`** — Vercel AI SDK. Tool-using methods (`recon`, `runAgent`) use a hand-rolled multi-step `generateText` loop (Read/Glob/Grep as `tool()` defs, TPM-retry, JSON parsed from the final text with a `structuredModel` reformat fallback); no-tool methods use `generateObject`. The tool implementations are bounded to the scan root and honor the exclude set.
- **`MultiProviderDetector`** — `generateObject` with strict structured output, no tools. Its `recon`/`runAgent` are best-effort (work from prompt context only, no file browsing).

Provider → detector:
- **Anthropic** (API key + OAuth) → `ClaudeAgentDetector` for every method.
- **OpenAI / Bedrock / Vertex** → `VercelAgentDetector` for every method.
- **Ollama** → a composite: tool-using calls (`recon`, `runAgent`) → `VercelAgentDetector` (best-effort JSON); no-tool calls (`checkPrecondition`, `validate`, `score`) → `MultiProviderDetector`.

Notes: Anthropic via the Vercel SDK was dropped (OAuth tokens get rate-limited; `mode: "json"` is rejected). Ollama splits because `structuredOutputs: true` (required for `generateObject`) conflicts with tool-calling. Vertex routes through `@ai-sdk/openai` against the Model Garden OpenAI-compatible endpoint with a `fetch` middleware stamping Google ADC tokens; GLM-5's non-standard `message.reasoning_content` is ignored by the JSON extractor.

## Provider registry

Providers are standalone modules under [`providers/`](packages/cli/src/providers/). Adding one = a module + an entry in [`providers/index.ts`](packages/cli/src/providers/index.ts) + a `Provider` enum entry + a `UserConfig` block in [`core/types.ts`](packages/core/src/types.ts). No edits to `llm.ts` / `init.ts` / `config.ts` / `scan.ts`. Each `ProviderModule` carries `buildDetector`, `collectCredentials`, `acceptedFlags` (passing a flag the active provider doesn't accept is a hard error), `curatedModels`/`listModels`, and `formatForList`/`redact`.

## File selection & default excludes

The walker is a **pure enumerator** — it applies only the `excludePatterns` it's handed and carries no built-in policy. The shared default skip set (`node_modules`, `.git`, build dirs, lockfiles, binaries) lives as data in `DEFAULT_EXCLUDES` ([`walker.ts`](packages/cli/src/walker.ts)) and is merged in by `scan.ts`. It can be dropped globally (`--no-default-excludes`) or per-agent (`where.useDefaultExcludes: false`). CLI `--exclude` paths are always applied (treated as deleted) and, on the Vercel tool path, enforced at the tool layer so a tool read can't reach them. (The Claude Agent SDK's built-in tools aren't bounded, so there it's prompt-level only.)

## Persistence & resume

```
out/
├── summary.md
├── findings/...
└── state/
    ├── scan.json          ← root + timestamps
    ├── recon.json         ← ReconReport (phase 1)
    ├── plan.json          ← ScanPlan: queued/skipped decisions (phase 2)
    ├── runs/<id>.json     ← RunMeta per scan / recon / revalidate / score / summary
    ├── agents/<slug>.json ← AgentRun resume sidecar (one per agent)
    └── files/<path>.json  ← FileRecord per scanned source file
```

Resume:
- **Recon + plan** — a `recon.json` whose `reconHash` matches is reused without re-surveying; a `plan.json` with the same `reconHash` that covers the current `-t` selection is reused without re-running the precondition for-loop (`scan.ts` reads `readScanPlan` and filters the selection to the plan's queued slugs). `--re-recon` forces both to recompute.
- **Per-agent** — an agent is skipped on re-run when its `AgentRun` sidecar matches the current scope (root + diff + excludePatterns + includePatterns + maxFileSizeKb + **reconHash**); prior findings are lifted from disk. An agent only writes its sidecar on full completion, so an interrupted agent re-runs in full.
- **Per-file** — within an agent, a `(file, agent)` pair is skipped when the `FileRecord` shows a prior `detect` with the same `contentHash` and agent slug.

`--rescan` bypasses resume. Changing scope (`--diff`, `--exclude`, `--only`, `--max-file-size`, root) or the recon brief (`--re-recon` / a stack change) invalidates the affected agents. `--no-recon` uses a synthetic `reconHash` (`"no-recon"`) and queues every `-t` agent, so its runs resume independently of recon-bearing runs.

## Validator & scoring

Three Detector methods, so any provider participates without bespoke wiring:
- **`validateFinding`** — full classifier; re-reads source → `confirmed` / `false-positive` / `out-of-scope` / `uncertain` + reasoning. Used by `--validate` and `agentgg revalidate`.
- **`validateFindingByScope`** — cheap variant, no source read; only `out-of-scope` / `uncertain`. Triggered by `--scope` without `--validate` (a pre-filter before the full validator).
- **`scoreFinding`** — picks the 8 CVSS 3.1 base metrics; vector string, base score, and severity bucket are computed deterministically in [`scoring.asCvssScore`](packages/cli/src/scoring.ts). Triggered by `--score` or `agentgg score`.

## CLI flags

| Flag | Applies to | Notes |
|---|---|---|
| `--max-turns <n>` | recon, agent runs, validator | When set, a uniform cap. Unset: agent batches use `where.maxTurnsPerBatch` (default 30), recon 30, validator 30. |
| `--max-files-per-batch <n>` | agent runs | Candidate files per batch. Overrides `where.maxFilesPerBatch` (default 5). |
| `--concurrency <n>` | agent runs, precondition gates | Parallel sessions in flight. Default 5. |
| `--re-recon` | recon + plan | Re-run recon **and** re-evaluate the precondition plan instead of reusing the cached brief/plan. |
| `--no-recon` | recon + precondition | Skip the survey and the gating loop; run every `-t` agent unconditionally with no injected brief. |
| `--no-summary` | report | Skip rendering `summary.md` + `findings/*.md`. Also accepted by `revalidate` / `score`. State still persists; render later with `agentgg summary`. |
| `--effort` / `--thinking` | provider-dependent | Reasoning knobs mapped to provider-native options where supported. |
| `--diff <commit>` | agent runs | Each agent's candidate list is intersected with the touched files; the commit patch is injected as a focus hint. Accepts `<ref>`, `a..b`, `a...b`. |
| `--exclude` / `--only` / `--max-file-size` / `--no-default-excludes` | file selection | Walk filters. `--exclude` = deleted; `--only` restricts; `--no-default-excludes` drops the built-in skip set. |
| `--validate` / `--revalidate-all` / `--scope` | post-detection | Validation passes (see above). |
| `--score` / `--rescore` | post-detection | CVSS scoring pass. |

## Frontmatter vs CLI precedence

**CLI flag wins → frontmatter → hardcoded default.** Batch size and per-batch turns:

```
batchSize        = opts.maxFilesPerBatch ?? agent.where.maxFilesPerBatch (default 5)
maxTurnsPerBatch = opts.maxTurns         ?? agent.where.maxTurnsPerBatch (default 30)
```

## Tool restriction

`ClaudeAgentDetector` passes `tools: ["Read","Glob","Grep"]` for `recon`/`runAgent` and `tools: []` for the precondition gate / validator / scorer. The SDK option `tools` controls what's in the model's context (not `allowedTools`, which only governs auto-approval and is a no-op under `bypassPermissions`).

`VercelAgentDetector` declares the same three tools via `tool()` definitions and runs them in a multi-step `generateText` loop. The implementations are bounded to the scan root and skip excluded paths.

## Packages

- [`packages/core/`](packages/core/) — types (`Agent`, `Precondition`, `Where`, `ReconReport`, `ScanPlan`, `Finding`, `FileRecord`, `AgentRun`, `UserConfig`, `CvssScore`), CVSS math, `fingerprint`, persistence helpers (`writeFileRecord` / `readAgentRun` / `writeReconReport` / `writeScanPlan` / …), agent loader, path resolution.
- [`packages/cli/`](packages/cli/) — commander wiring, detectors, providers, recon, precondition, walker, validator, scoring, reporters, the built-in recon agent ([`src/agents/`](packages/cli/src/agents/)), viewer bootstrap.
- [`packages/viewer/`](packages/viewer/) — Next.js app served by `agentgg view` / `agentgg scan --serve`.
