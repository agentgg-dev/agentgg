# ARCHITECTURE

One-page reference for what's wired and how. User-facing docs are in [README.md](./README.md); start there if you're using agentgg rather than working on it.

## Three execution modes

Every agent declares one `mode` in its frontmatter. The CLI dispatches based on that field.

| Mode | What it does | Tools | Cost |
|---|---|---|---|
| `file` | One LLM call per (agent, matching file). File content is in the prompt. | None (`tools: []` in the SDK call — actually enforced as of the bypassPermissions/allowedTools fix) | Lowest |
| `walker` | Walker enumerates files matching `filePatterns`, agent's `preFilter` regexes narrow to candidates with line hits, batched candidates get one tool-enabled session each. | Read, Glob, Grep | Medium |
| `hunt` | One tool-enabled session per agent over the whole repo. Model discovers its own files. | Read, Glob, Grep | Highest |

All three modes use the same `runStructured` helper in [`packages/cli/src/detectors/claude-agent.ts`](packages/cli/src/detectors/claude-agent.ts) for Claude Agent SDK invocations and the same `generateObject` call in [`packages/cli/src/detectors/multi-provider.ts`](packages/cli/src/detectors/multi-provider.ts) for the Vercel AI SDK path. The three modes are different prompt + parameter combinations, not different engines.

## Provider matrix

| Provider | File mode | Walker mode | Hunt mode |
|---|---|---|---|
| Anthropic API key | Vercel AI SDK | Claude Agent SDK | Claude Agent SDK |
| Anthropic OAuth | Claude Agent SDK | Claude Agent SDK | Claude Agent SDK |
| OpenAI | Vercel AI SDK | **not implemented** | **not implemented** |
| Ollama | Vercel AI SDK | **not implemented** | **not implemented** |

Walker and hunt on OpenAI/Ollama is an implementation gap (the Vercel detector throws), not an SDK capability ceiling. The Vercel AI SDK supports tool use across providers; agentgg just hasn't wired the multi-step tool loop yet.

## CLI flags by mode

| Flag | Applies to | Notes |
|---|---|---|
| `--max-turns <n>` | file, walker, hunt, validator | Max tool-use turns per LLM session. When set, overrides every per-mode default in this run. When unset, each context uses: file=5, walker=30, hunt=150, validator=30. |
| `--max-files-per-batch <n>` | walker | Candidate files packed into one investigation batch. Default 5. |
| `--effort <level>` | Anthropic (OAuth + API key), OpenAI | Reasoning effort. `low`/`medium`/`high`/`max`. Anthropic OAuth (Claude Agent SDK): all four work. OpenAI (Vercel SDK): `max` maps to `high` (`reasoningEffort` tops out at high). Anthropic API key via Vercel SDK: no equivalent (provider doesn't expose effort). Ollama: no equivalent. |
| `--thinking <mode>` | Anthropic (OAuth + API key) | Thinking mode. `off`/`adaptive`/`enabled`. Anthropic OAuth: all three work. Anthropic API key via Vercel SDK: `adaptive` maps to `enabled` (provider only exposes enabled/disabled). OpenAI / Ollama: no equivalent. |
| `--concurrency <n>` | walker, hunt | Parallel sessions in flight. |
| `--diff <commit>` | walker, file | Restrict to files changed between commit and HEAD. Hunt agents are skipped. |
| `--exclude <pattern>`, `--only <pattern>`, `--max-file-size <kb>` | walker, file (walker enumeration) | File-selection filters applied during enumeration. Hunt agents see them embedded in their prompt (not enforced). |

## Frontmatter vs CLI precedence

**CLI flag wins. Frontmatter is the fallback. Hardcoded default is the last resort.**

Concretely, for walker's `maxFilesPerBatch` / per-batch turn budget ([`scan.ts:387-399`](packages/cli/src/commands/scan.ts#L387-L399)):

```
batchSize       = opts.maxFilesPerBatch ?? max(walker agents' maxFilesPerBatch ?? 5)
maxTurnsPerBatch = opts.maxTurns        ?? max(walker agents' maxTurnsPerBatch ?? 30)
```

When CLI flags are omitted and multiple walker agents disagree, the runtime takes the **largest** declared value (so no agent gets undercut). `--max-turns` is the single unified flag; the agent frontmatter still uses `maxTurnsPerBatch` because it's a walker-specific knob.

## Dispatch engines

- **Claude Agent SDK path** ([`detectors/claude-agent.ts`](packages/cli/src/detectors/claude-agent.ts)): handles every mode. Used for Anthropic OAuth (all modes), Anthropic API key (walker/hunt), and validator calls when Anthropic creds exist.
- **Vercel AI SDK path** ([`detectors/multi-provider.ts`](packages/cli/src/detectors/multi-provider.ts)): file mode + validator only. Throws on walker/hunt. Used for OpenAI, Ollama, Anthropic API key (file mode).
- **Hybrid detector** ([`llm.ts:114-134`](packages/cli/src/llm.ts#L114-L134)): for Anthropic API key, routes file mode through the cheaper Vercel SDK and walker/hunt through the Claude Agent SDK. Same credential, two backends.

## Tool restriction (post-fix)

`runStructured` in `claude-agent.ts` now passes `tools: []` or `tools: ["Read", "Glob", "Grep"]` to the SDK. The SDK option `tools` controls what's in the model's context; `allowedTools` (which agentgg used to pass) only controls auto-approval prompts and was a no-op under `bypassPermissions`. File mode and validator now genuinely have no tools available; walker and hunt are scoped to exactly Read/Glob/Grep.

## Known debt (not yet addressed)

See the open list in conversation memory. Highlights:

- Walker/hunt on OpenAI/Ollama (Vercel detector port).
- `excludePatterns` enforcement asymmetry: walker filters hard, hunt embeds in prompt.
- No persistent state model (every scan starts cold).
- file mode is structurally a constrained walker; could collapse if the cost profile is preserved.
