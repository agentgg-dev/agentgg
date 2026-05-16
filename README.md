# agentgg

AI-powered SAST CLI with modular, community-installable agents — **Nuclei templates for AI-driven code review.**

> ⚠️ **Early development.** Detect / validate / resume / status / revalidate are
> all working end-to-end against Anthropic (API key + OAuth), OpenAI, and Ollama.
> Severity scoring, notifiers, and an official agents repo are next.

## Install

```bash
npm install -g agentgg
```

From source:

```bash
git clone https://github.com/agentgg/agentgg
cd agentgg
npm install --legacy-peer-deps
npm run build
npm link --workspace agentgg   # makes `agentgg` available globally
```

## Quick start

```bash
agentgg init                                # one-time: pick a provider, paste a key
agentgg scan ./src --validate -o ./out      # scan, validate findings, write a report
agentgg status ./out                        # what got found / validated / when
```

Findings land in `./out/`:

```
out/
├── summary.md            ← human report
├── findings/...          ← one .md per finding (GHSA-shaped)
└── state/                ← what `status` and `revalidate` read
    ├── scan.json         ← root path + timestamps
    ├── runs/<id>.json    ← one per scan / revalidate
    └── files/<path>.json ← FileRecord per scanned source file
```

The `state/` directory is what makes resume, status, and revalidate work. Re-running `scan` with the same `-o` skips files that haven't changed. Different `-o` = fresh scan.

## How agents work

Every agent is a self-contained markdown file with YAML frontmatter:

```markdown
---
slug: sql-injection
name: SQL Injection
description: String-concatenated SQL queries.
mode: file                  # or "hunt"
noiseTier: normal
filePatterns:
  - "**/*.{ts,js,py,rb,go}"
references:
  - CWE-89
---

You are reviewing source code for SQL injection. Look for queries
built by string concatenation, template interpolation, or unescaped
substitution. ...
```

The same schema applies whether the agent lives in:

- **Built-in** ([`packages/agents/agents/`](packages/agents/agents/)) — ship with the npm package
- **User-installed** (`~/.agentgg/agents/custom/`) — `agentgg agents add ./my-agent.md`
- **Per-scan** — pass a `.md` file, directory, or `.txt` list to `-t/--template`

## Three execution modes

Each agent declares its own `mode`. The framework dispatches accordingly.

**`mode: file`** — one LLM call per (agent, matching file). No tools. Cheap, predictable:

- `sql-injection`, `command-injection`, `hardcoded-secrets`, …

**`mode: walker`** — anchored agentic investigation. The walker enumerates files matching the agent's `filePatterns`, the agent's `preFilter` regexes narrow to "candidates" with line hits, then each batch of candidates gets one tool-enabled session. Same shape as deepsec's scan→process pipeline collapsed into one pass:

- `openclaw-audit-allowlist-identity-walker` — anchored allowlist-bypass investigation

**`mode: hunt`** — one tool-enabled session per agent across the whole repo. The agent uses Read/Glob/Grep to discover its own files. Good for cross-file logic and CVE-pattern hunts:

- `missing-access-control` — IDOR / auth-middleware coverage across handlers
- `openclaw-audit-allowlist-identity-hunter` — project-specific mutable-identity allowlist bypass

All three modes run side-by-side in one scan. Hunt agents run first (heaviest), then walker, then file agents.

## Providers

`agentgg init` writes credentials to `~/.agentgg/config.json`. Scan state is per-output-dir and has nothing to do with this file.

| Provider | Credential | File mode | Walker mode | Hunt mode |
|---|---|---|---|---|
| **Anthropic** | API key (`sk-ant-api...`) | Vercel AI SDK | Claude Agent SDK | Claude Agent SDK |
| **Anthropic** | OAuth (`sk-ant-oat...`, Claude Pro/Max) | Claude Agent SDK | Claude Agent SDK | Claude Agent SDK |
| **OpenAI** | API key | Vercel AI SDK | Vercel AI SDK | Vercel AI SDK |
| **Ollama** | local URL | Vercel AI SDK | Vercel AI SDK | Vercel AI SDK |

All four provider paths support all three agent modes. Hunt and walker use the Vercel AI SDK's `generateText` with Read/Glob/Grep tools for OpenAI and Ollama; Anthropic routes those modes through the Claude Agent SDK. Model quality matters most for hunt and walker — Claude is the most reliable at multi-step tool use and structured output; OpenAI and Ollama models work but may produce occasional hallucinated paths or incomplete investigations.

---

## Examples

### Pick which agents to run

Run the default agent set (`~/.agentgg/agentgg-agents/default/`):

```bash
agentgg scan ./src -o ./out
```

A single slug:

```bash
agentgg scan ./src -t sql-injection -o ./out
```

Multiple slugs, comma-separated within one `-t`:

```bash
agentgg scan ./src -t sql-injection,hardcoded-secrets,command-injection -o ./out
```

Whitespace-separated (quote it for the shell):

```bash
agentgg scan ./src -t "sql-injection hardcoded-secrets command-injection" -o ./out
```

A custom `.md` agent on disk:

```bash
agentgg scan ./src -t ./my-agents/path-traversal.md -o ./out
```

A whole directory of custom agents:

```bash
agentgg scan ./src -t ./my-agents/ -o ./out
```

A `.txt` list file (one slug or path per line, `#` for comments, blank lines OK):

```bash
agentgg scan ./src -t ./agents.txt -o ./out
```

Mix everything in one invocation:

```bash
agentgg scan ./src -t "sql-injection,./my-agents/path-traversal.md,./agents.txt" -o ./out
```

`-t` can also be repeated — every form composes.

### Add validation

The validation phase is a second-pass LLM call per finding that re-reads the source and classifies as `confirmed` / `false-positive` / `out-of-scope` / `uncertain`. Off by default — opt in:

```bash
agentgg scan ./src -t sql-injection --validate -o ./out
```

Each finding gets a `validation` section in its markdown file and a verdict count in `summary.md`.

### Use a scope file to mark out-of-scope findings

Pass any text file the validator should consult as scope context (a `SECURITY.md`-style doc, your own notes, etc.). Without `--scope`, the `out-of-scope` verdict is withheld — the model would just be guessing.

```bash
agentgg scan ./src --validate --scope ./SECURITY.md -o ./out
```

A missing scope file fails fast with no LLM call:

```bash
agentgg scan ./src --validate --scope ./typo.md -o ./out
# → scan failed: --scope: cannot read /path/to/typo.md: ENOENT
```

### Re-run only the validation phase

Detect once, validate later (or with a different model / scope):

```bash
agentgg scan ./src -t sql-injection -o ./out         # detect only
agentgg revalidate ./out                              # validate everything pending
agentgg revalidate ./out --scope ./SECURITY.md       # re-classify with scope
agentgg revalidate ./out --force                     # re-classify everything
```

### Resume after Ctrl+C

Cancel a scan mid-run and re-run the same command — already-analyzed files print `cached`, the rest get fresh LLM calls. The interrupted run on disk is marked `phase: error` so you can find it in `agentgg status`.

```bash
agentgg scan ./src -t sql-injection,hardcoded-secrets --validate -o ./out
# Ctrl+C partway through
# → "Interrupted. Partial state persisted; re-run the same command to resume."

agentgg scan ./src -t sql-injection,hardcoded-secrets --validate -o ./out
# → "server.js: cached (3 finding(s) from disk)"
# → "1 file(s) reused from prior run (pass --rescan to force)."
```

Force a fresh run instead:

```bash
agentgg scan ./src -t sql-injection -o ./out --rescan          # re-analyze every file
agentgg scan ./src -t sql-injection --validate --revalidate-all -o ./out
```

### Scan only what changed in a PR

`--diff <commit>` intersects the walker output with `git diff --name-only <commit>` HEAD. Hunt agents are skipped (they're whole-repo by design).

```bash
agentgg scan ./src -t sql-injection --diff main -o ./out
agentgg scan ./src --diff origin/main -o ./out
```

### Inspect scan state

```bash
agentgg status ./out                  # human-readable
agentgg status ./out --json           # machine-readable
```

Output includes: scanned root, file counts (analyzed / validated / pending), total findings, verdict breakdown, and recent runs.

```bash
agentgg status ./out
# Scan state: /path/to/out
#   Root:           /path/to/src
#   Files tracked:  37
#
# Status
#   analyzed:   30
#   validated:  30
#   pending:    7
#
# Findings
#   total:      12
#   validated:  12/12
#   verdicts:   confirmed=8, false-positive=4
#
# Recent runs (3 total)
#   20260514001435-4e8b5e55  scan       done  88.2s files: 37 findings: 12
#   ...
```

Pointing at a directory that was never scanned returns a friendly message, not a crash:

```bash
agentgg status ./never-scanned
# No scan state at /path/to/never-scanned
#   Run `agentgg scan <path> -o ./never-scanned` first.
```

### Limit what gets scanned

Override the default glob exclusions / restrict to specific paths:

```bash
agentgg scan ./src --exclude "**/migrations/**" --exclude "vendor/**" -o ./out
agentgg scan ./src --only "src/api/**/*.ts" --only "src/handlers/**/*.ts" -o ./out
agentgg scan ./src --max-file-size 200 -o ./out      # skip files larger than 200 KB
```

The walker auto-skips lockfiles, minified bundles, binary assets, `node_modules`, `dist`, `.git`, and the scan-results directory regardless of flags.

### Speed it up (or down)

`--concurrency` controls parallel files-per-agent. Default 5.

```bash
agentgg scan ./src --concurrency 10 -o ./out    # faster on large repos
agentgg scan ./src --concurrency 1  -o ./out    # sequential, easier to follow
```

### Use a one-off API key without saving it

```bash
agentgg scan ./src --provider anthropic --api-key sk-ant-... -o ./out
agentgg scan ./src --provider anthropic --oauth-token sk-ant-oat-... -o ./out
agentgg scan ./src --provider ollama --base-url http://localhost:11434 -o ./out
```

### Manage agents

```bash
agentgg agents list                                  # table of built-ins + custom
agentgg agents list --json                           # machine-readable
agentgg agents info sql-injection                    # show prompt + frontmatter
agentgg agents add ./my-agent.md                     # install into ~/.agentgg/agents/custom/
agentgg agents add ./agents-dir/                     # install every .md in a dir
agentgg agents remove my-agent                       # uninstall by slug
```

### Inspect saved config

```bash
agentgg config                # masks secrets
agentgg config --json         # raw, also masked
```

---

## Report format

Each finding is a markdown file under `./out/findings/`, GHSA-shaped:

```
# <title>

**Agent:** `sql-injection`
**Vuln class:** `sql-injection`
**File:** `src/login.ts`
**Lines:** 12–14
**Confidence:** 90%
**Severity:** _pending (scoring phase not yet run)_
**Validation:** `confirmed`

### Summary
One sentence stating the issue + impact.

### Details
Full analysis with code excerpts.

### PoC
Concrete reproduction (HTTP request, payload, command).

### Impact
Vulnerability class, who's affected, what an attacker gets.

### Validation
**Verdict:** `confirmed`

Short reasoning citing the unsafe code element.

### References
- CWE-89
```

`summary.md` aggregates: counts per agent, validation verdict breakdown, links to each finding.

## Commands

| Command | Status |
|---|---|
| `agentgg init` | ✅ Anthropic API key + OAuth, OpenAI, Ollama; merges new providers |
| `agentgg scan <path>` | ✅ file + hunt mode, `--template`, `--diff`, `--validate`, `--scope`, resume |
| `agentgg status [output-dir]` | ✅ reads `<output>/state/`, human or `--json` |
| `agentgg revalidate [output-dir]` | ✅ re-runs validation against persisted findings |
| `agentgg agents list` | ✅ table or `--json`; built-ins + user-installed |
| `agentgg agents info <slug>` | ✅ |
| `agentgg agents add <file-or-dir>` | ✅ installs into `~/.agentgg/agents/custom/` |
| `agentgg agents remove <slug>` | ✅ |
| `agentgg agents update` | ⏳ stub (needs official agents repo) |
| `agentgg config` | ✅ secrets masked |

Run `agentgg <command> --help` for the full flag list on any subcommand.

## Scan flag reference

```
-t, --template <value>          slug, .md path, directory, or .txt list file;
                                comma- or whitespace-separated; repeatable
-o, --output <path>             output directory (default ./scan-results/)
--validate                      run a second-pass validation phase per finding
--scope <path>                  scope file the validator consults (enables `out-of-scope`)
--rescan                        re-analyze files even if a prior run covered them
--revalidate-all                re-validate findings that already have a verdict
--diff <commit>                 scan only files changed since <commit> (skips hunt agents)
--concurrency <n>               parallel files per agent (default 5)
--exclude <pattern>             glob to exclude (repeatable; additive)
--only <pattern>                restrict scan to matching globs (repeatable)
--max-file-size <kb>            skip files larger than this (default 500)
--provider <name>               anthropic | openai | ollama (overrides config default)
--api-key <key>                 one-shot API key (not persisted)
--oauth-token <token>           one-shot Anthropic OAuth token (not persisted)
--base-url <url>                one-shot Ollama base URL (not persisted)
-v, --verbose                   verbose output
```

## Project layout

```
agentgg/
├── packages/
│   ├── core/                  Zod schemas, persistence layer, paths, agent loader
│   ├── cli/                   commander CLI, walker, detectors, reporter, validator
│   └── agents/
│       └── agents/            built-in markdown agents
├── docs/                      documentation
├── samples/                   example projects
├── product-overview.md        full product vision
└── ...
```

## License

agentgg is licensed under the GNU Lesser General Public License v2.1 or later. See [LICENSE](./LICENSE) for the full text.
