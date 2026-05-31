# ARCHITECTURE

One-page reference for what's wired and how. User-facing docs are in [README.md](./README.md); start there if you're using agentgg rather than working on it.

## Three execution modes

Every agent declares one `mode` in its frontmatter. The CLI dispatches based on that field.

| Mode | What it does | Tools | Cost |
|---|---|---|---|
| `file` | One LLM call per (agent, matching file). File content is in the prompt. | None | Lowest |
| `walker` | Walker enumerates files matching `filePatterns`. Each agent's `preFilter` regexes narrow to candidates with line hits. Hits are **pooled across agents by file** — a file flagged by N walker agents is investigated once in a session carrying every agent's brief; findings are attributed back per-agent via `agentSlug`. | Read, Glob, Grep | Medium |
| `hunt` | One tool-enabled session per agent over the whole repo. Model discovers its own files. | Read, Glob, Grep | Highest |

Hunt agents run first (heaviest), then walker, then file. All three share the same `Detector` contract (see [`detect.ts`](packages/cli/src/detect.ts)).

## Provider registry

Providers live as standalone modules under [`packages/cli/src/providers/`](packages/cli/src/providers/). Adding a provider = one new module file + one entry in [`providers/index.ts`](packages/cli/src/providers/index.ts) + a `Provider` enum entry + a `UserConfig` block in [`core/types.ts`](packages/core/src/types.ts). No edits to `llm.ts` / `init.ts` / `config.ts` / `scan.ts` required.

Each `ProviderModule` carries:
- `buildDetector(config, options)` — constructs the `Detector` for a scan run from CLI flags + saved config + env.
- `collectCredentials(args)` — wizard step; returns a `UserConfig` fragment.
- `acceptedFlags` — which generic flags (`--api-key`, `--oauth-token`, `--base-url`, `--region`) are meaningful. Passing a flag the active provider doesn't accept is a hard error, not a silent ignore.
- `curatedModels` / `listModels` — init-wizard model picker.
- `formatForList` / `redact` — used by `agentgg config`.

## Provider matrix

| Provider | File mode | Walker mode | Hunt mode | Validate / Score |
|---|---|---|---|---|
| Anthropic (API key) | Claude Agent SDK | Claude Agent SDK | Claude Agent SDK | Claude Agent SDK |
| Anthropic (OAuth, `sk-ant-oat…`) | Claude Agent SDK | Claude Agent SDK | Claude Agent SDK | Claude Agent SDK |
| OpenAI | Vercel AI SDK (tool detector) | Vercel AI SDK (tool detector) | Vercel AI SDK (tool detector) | Vercel AI SDK (tool detector) |
| Ollama | Vercel AI SDK (generateObject) | Vercel AI SDK (tool detector) | Vercel AI SDK (tool detector) | Vercel AI SDK (generateObject) |
| AWS Bedrock | Vercel AI SDK (tool detector) | Vercel AI SDK (tool detector) | Vercel AI SDK (tool detector) | Vercel AI SDK (tool detector) |
| Google Vertex AI (GLM-5 MaaS) | Vercel AI SDK (tool detector) | Vercel AI SDK (tool detector) | Vercel AI SDK (tool detector) | Vercel AI SDK (tool detector) |

Anthropic via the Vercel SDK was dropped: OAuth tokens hitting the API directly get rate-limited, and `mode: "json"` is rejected for structured output. Both Anthropic auth types route through `claude-agent-sdk` for every Detector method.

Ollama splits because `structuredOutputs: true` (required for `generateObject`) conflicts with tool-calling on Ollama — the model emits example JSON verbatim instead of reasoning about tool results.

## Dispatch engines

Three concrete `Detector` implementations, all in [`detectors/`](packages/cli/src/detectors/):

- **`ClaudeAgentDetector`** ([`detectors/claude-agent.ts`](packages/cli/src/detectors/claude-agent.ts)) — wraps `@anthropic-ai/claude-agent-sdk`. Spawns the `claude` CLI as a child process. Handles every Detector method for both Anthropic auth types.
- **`VercelAgentDetector`** ([`detectors/vercel-agent.ts`](packages/cli/src/detectors/vercel-agent.ts)) — Vercel AI SDK with a hand-rolled tool loop (`Read`/`Glob`/`Grep` as `tool()` definitions, multi-step `generateText` with TPM-retry). Backs OpenAI / Bedrock / Ollama / Vertex hunt + walker, plus OpenAI / Bedrock / Vertex file + validator. Maps `effort` → `providerOptions.openai.reasoningEffort` and `thinking` → `providerOptions.anthropic.thinking` where each provider supports it. Vertex routes through `@ai-sdk/openai` against the Vertex Model Garden OpenAI-compatible endpoint, with a `fetch` middleware that stamps Google ADC access tokens; GLM-5's `message.reasoning_content` field is non-standard and ignored by the JSON extractor.
- **`MultiProviderDetector`** ([`detectors/multi-provider.ts`](packages/cli/src/detectors/multi-provider.ts)) — Vercel AI SDK's `generateObject` with strict structured-output schema. Used by Ollama for file mode / validate / score (where tool-calling and `structuredOutputs:true` collide). Throws on `hunt` / `investigate`.

The orchestrator ([`scan.ts`](packages/cli/src/commands/scan.ts)) holds one `Detector` for the whole scan and calls `detectFile` / `investigate` / `hunt` / `validateFinding` / `validateFindingByScope` / `scoreFinding` depending on what each agent and phase needs.

## Persistence model

`agentgg scan -o ./out` writes everything under `./out/`:

```
out/
├── summary.md            ← human report
├── findings/...          ← one .md per finding (GHSA-shaped)
└── state/
    ├── scan.json         ← root path + timestamps
    ├── runs/<id>.json    ← one per scan / revalidate / score
    ├── files/<path>.json ← FileRecord per scanned source file
    └── agents/<slug>.json← AgentRun sidecar for walker/hunt resume
```

State drives resume. On re-scan:
- **File mode** skips a `(file, agent)` pair when the `FileRecord` shows a prior `detect` ran with the same `contentHash` and the same agent slug.
- **Walker mode** does the same per-(file, agent) check, lifting prior findings into the report without queuing an LLM call.
- **Hunt mode** skips the whole agent when an `AgentRun` sidecar matches the current scope (root + diff + excludePatterns + includePatterns + maxFileSizeKb).

`--rescan` bypasses all three. Changing scope (`--diff`, `--exclude`, `--only`, `--max-file-size`, or the scanned root) invalidates resume for the affected agents.

## Validator and scoring

Both run as separate Detector methods, so any provider participates without bespoke wiring.

- **`validateFinding`** — full second-pass classifier. Re-reads the source file and returns `confirmed` / `false-positive` / `out-of-scope` / `uncertain` + reasoning. Used by `--validate` and `agentgg revalidate`.
- **`validateFindingByScope`** — cheap variant that skips re-reading source. Sees only the finding metadata + a scope document; can only return `out-of-scope` or `uncertain`. Triggered when `--scope` is passed without `--validate`, and by `agentgg revalidate --scope-validate`. Used as a pre-filter to drop scope-disqualified findings before paying the full validator cost.
- **`scoreFinding`** — picks the 8 CVSS 3.1 base metrics. Vector string, numeric base score, and severity bucket are computed deterministically in [`scoring.asCvssScore`](packages/cli/src/scoring.ts). Triggered by `--score` during scan, or `agentgg score` standalone.

## CLI flags by mode

| Flag | Applies to | Notes |
|---|---|---|
| `--max-turns <n>` | file, walker, hunt, validator | Max tool-use turns per LLM session. When set, overrides every per-mode default. When unset, each context uses: file=5, walker=30, hunt=150, validator=30. |
| `--max-files-per-batch <n>` | walker | Candidate files packed into one investigation batch. Default 5. |
| `--concurrency <n>` | walker, hunt, file | Parallel sessions in flight. Default 5. |
| `--effort <level>` | Anthropic (OAuth + API key), OpenAI, Bedrock | Reasoning effort. `low`/`medium`/`high`/`max`. Anthropic via Claude Agent SDK: all four work. OpenAI / Bedrock via Vercel SDK: `max` maps to `high`. Ollama / Vertex: honest no-op. |
| `--thinking <mode>` | Anthropic (OAuth + API key), Bedrock (Anthropic-family models) | `off` / `adaptive` / `enabled`. Anthropic OAuth: all three. Anthropic API key / Bedrock via Vercel SDK: `adaptive` maps to `enabled`. OpenAI / Ollama / Vertex: no equivalent — GLM-5 has its own thinking mode that is always on. |
| `--diff <commit>` | walker, file, hunt | Walker/file: candidate list is intersected with the changed-file set. Hunt: agent still runs whole-repo but receives `git show <commit>` (message + patch) in the prompt as a focus hint; tools stay unrestricted. Accepts `<ref>`, `a..b`, or `a...b`. |
| `--exclude <pattern>`, `--only <pattern>`, `--max-file-size <kb>` | walker, file (enumeration) | File-selection filters applied during walker enumeration. Hunt agents see them embedded in their prompt (not enforced by tools). |
| `--score`, `--rescore` | post-detection | Runs the CVSS scoring pass after detection / validation. `--rescore` re-scores findings that already carry a score. |
| `--validate`, `--revalidate-all` | post-detection | Runs the source-reading validator. `--revalidate-all` re-classifies findings that already have a verdict. |
| `--scope <path>` | validator | Scope doc threaded into validator prompt verbatim. Without `--scope`, the validator does not return `out-of-scope`. With `--scope` and without `--validate`, triggers scope-only validation (cheap pre-filter). |

## Frontmatter vs CLI precedence

**CLI flag wins. Frontmatter is the fallback. Hardcoded default is the last resort.**

For walker's `maxFilesPerBatch` / per-batch turn budget ([`scan.ts`](packages/cli/src/commands/scan.ts) — search `declaredBatchSize` / `declaredMaxTurns`):

```
batchSize        = opts.maxFilesPerBatch ?? max(walker agents' maxFilesPerBatch ?? 5)
maxTurnsPerBatch = opts.maxTurns         ?? max(walker agents' maxTurnsPerBatch ?? 30)
```

When CLI flags are omitted and multiple walker agents disagree, the runtime takes the **largest** declared value so no agent gets undercut. `--max-turns` is the single unified turn-cap flag; the per-agent frontmatter still uses `maxTurnsPerBatch` because it's a walker-specific knob.

## Tool restriction

`ClaudeAgentDetector` passes `tools: []` to the SDK for file mode and the validator, and `tools: ["Read", "Glob", "Grep"]` for hunt / walker. The SDK option `tools` controls what's in the model's context (not `allowedTools`, which only governs auto-approval prompts and is a no-op under `bypassPermissions`). File mode and validator have no tools available; walker and hunt are scoped to exactly Read / Glob / Grep.

`VercelAgentDetector` declares the same three tools via `tool()` definitions and runs them in a multi-step `generateText` loop. The tool implementations are bounded to the scan root.

## Packages

- [`packages/core/`](packages/core/) — types (`Agent`, `Finding`, `FileRecord`, `AgentRun`, `UserConfig`, `CvssScore`), CVSS computation, persistence helpers (`writeFileRecord` / `readAgentRun` / etc), agent loader, path resolution.
- [`packages/cli/`](packages/cli/) — commander wiring, detectors, providers, walker, validator, scoring, reporters, viewer-server bootstrap.
- [`packages/viewer/`](packages/viewer/) — Next.js app served by `agentgg view` / `agentgg scan --serve`.

