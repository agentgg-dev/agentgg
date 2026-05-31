<p align="center">
  <img src="https://raw.githubusercontent.com/agentgg-dev/agentgg-agents/main/static/logo.png" alt="agentgg" width="240" />
</p>

# agentgg

**Agentic SAST. White box. CI ready.**

`agentgg` is an agentic SAST scanner. Its agents reason about your code. They follow imports, check the call graph, and confirm findings before flagging, instead of pattern-matching the way traditional SAST does. 200+ official agents and rule templates cover security vulnerabilities, coding anti-patterns, and codebase recon; the catalog auto-downloads on first scan from [agentgg-dev/agentgg-agents](https://github.com/agentgg-dev/agentgg-agents). Run on your full repo or on a git diff for PR reviews. Each agent runs in one of four modes: **file**, **walker**, **hunt** (all LLM-driven), or **rule** (regex only, no LLM cost). agentgg fingerprints the project on each scan and skips agents whose tech declaration doesn't match the stack. PHP agents never run on Go-only repos. Interrupted scans resume on re-run: only new or changed files hit the LLM again.

**[agentgg.dev](https://agentgg.dev)** · [Agents catalog](https://github.com/agentgg-dev/agentgg-agents) · [Report a bug](https://github.com/agentgg-dev/agentgg/issues/new/choose) · [Report a security issue](https://github.com/agentgg-dev/agentgg/security)

> **agentgg is in beta.** Things will move and edges will be rough. Bug reports and feedback are very welcome. [Open an issue](https://github.com/agentgg-dev/agentgg/issues/new/choose).

<p align="center">
  <img src="https://raw.githubusercontent.com/agentgg-dev/agentgg/main/static/agentgg-view.png" alt="agentgg viewer UI showing scan findings" width="780" />
</p>

## Table of Contents

- [Install](#install)
- [Quick start](#quick-start)
- [How agents work](#how-agents-work)
- [Four execution modes](#four-execution-modes)
- [Tech gating](#tech-gating)
- [Providers](#providers)
- [Examples](#examples)
- [GitHub Actions](#github-actions)
- [Report format](#report-format)
- [Commands](#commands)
- [Scan flag reference](#scan-flag-reference)
- [License](#license)

## Install

```bash
npm install -g agentgg
```

From source:

```bash
git clone https://github.com/agentgg-dev/agentgg
cd agentgg
pnpm install
pnpm --filter agentgg build:bundle
pnpm --filter agentgg link --global
```

Requires Node.js 20+ and pnpm 9+. See [CONTRIBUTING.md](https://github.com/agentgg-dev/agentgg/blob/main/CONTRIBUTING.md) for the dev workflow.

## Quick start

```bash
agentgg init                                                       # one-time: pick a provider, paste a key
agentgg scan ./src --validate -o ./out                             # scan everything, validate findings
agentgg scan ./src --diff origin/main...HEAD --validate -o ./out   # PR-style: scan only what changed
agentgg status ./out                                               # what got found / validated / when
agentgg view ./out                                                 # browse findings in a local web UI
agentgg scan ./src --serve -o ./out                                # scan, then boot the UI when done
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

- **Official catalog** (`~/.agentgg/agentgg-agents/`): downloaded on first scan from [agentgg-dev/agentgg-agents](https://github.com/agentgg-dev/agentgg-agents); refresh with `agentgg agents update`
- **User-installed** (`~/.agentgg/agents/custom/`): `agentgg agents add ./my-agent.md`
- **Per-scan**: pass a `.md` file, directory, or `.txt` list to `-t/--template`

## Four execution modes

Each agent declares its own `mode`. The framework dispatches accordingly.

**`mode: rule`**: regex only. No LLM, no cost. The rule's `preFilter` patterns run against files matching `filePatterns` and produce candidate hits attached to those files. Hits flow into walker pool sessions, hunt prompts, and file prompts as scanner context, so other agents use them as anchors without rediscovering what's already known. Tech-gated by convention (e.g. only fires on Laravel repos):

- `php-laravel-route`, `py-django-view`, `go-gin-route`, `jvm-spring-controller`, … (75+ framework entry-point finders)

**`mode: file`**: one LLM call per (agent, matching file). No tools. Cheap, predictable:

- `sql-injection`, `command-injection`, `hardcoded-secrets`, …

**`mode: walker`**: anchored agentic investigation. The walker enumerates files matching the agent's `filePatterns`, the agent's `preFilter` regexes narrow to "candidates" with line hits, then each batch of candidates gets one tool-enabled session:

- `openclaw-audit-allowlist-identity-walker`: anchored allowlist-bypass investigation

**`mode: hunt`**: one tool-enabled session per agent across the whole repo. The agent uses Read/Glob/Grep to discover its own files. Good for cross-file logic and CVE-pattern hunts:

- `missing-access-control`: IDOR / auth-middleware coverage across handlers
- `openclaw-audit-allowlist-identity-hunter`: project-specific mutable-identity allowlist bypass

All four modes run side-by-side in one scan. Rules run first (no LLM), then hunt agents (heaviest), then walker, then file agents.

## Tech gating

agentgg fingerprints the project on each scan (`package.json` deps, `composer.json`, `go.mod`, `Gemfile`, `pyproject.toml`, `Cargo.toml`, `.csproj`, etc.) and produces a set of tech tags (`nextjs`, `laravel`, `django`, `go`, `spring`, …). Agents and rules with a `tech:` field only run when at least one of their declared tags is present.

A scan against a Go-only repo silently skips PHP/Python/Ruby/.NET agents; a Laravel scan silently skips Django/Rails/Spring agents. Generic agents (no `tech:` field) always run.

```bash
agentgg scan ./src -v -o ./out         # `-v` lists what was gated out and why
agentgg scan ./src --no-gate -o ./out  # force every selected agent to run regardless
```

`--no-gate` is the escape hatch for debugging a new agent on a repo where the fingerprinter doesn't yet recognize the stack.

## Providers

`agentgg init` writes credentials to `~/.agentgg/config.json`. Scan state is per-output-dir and unrelated to this file.

| Provider | Credential |
|---|---|
| **Anthropic** | API key (`sk-ant-api...`) or OAuth (`sk-ant-oat...`, Claude Pro/Max) |
| **OpenAI** | API key |
| **Ollama** | local URL |
| **AWS Bedrock** | AWS credentials (env / `~/.aws/credentials` / IAM role) |
| **Google Vertex AI (Model Garden)** | Google ADC (`gcloud auth application-default login` / `GOOGLE_APPLICATION_CREDENTIALS` / GCE/Cloud Run service account) + GCP project ID |

All providers support all three agent modes. Hunt and walker are multi-step and tool-using, so finding quality scales with model quality.

### AWS Bedrock

`agentgg init --provider bedrock --region us-east-1` walks you through setup. agentgg picks up your existing AWS credentials. Anything that works with the AWS CLI (env vars, `aws configure`, SSO, IAM role) works here.

Two things to know:

- **Inference profiles are required for newer Claude models.** Default uses a US profile (`us.anthropic.*`); EU/APAC use `eu.*` / `apac.*`. Override at init time.
- **Bedrock has no free tier.** Set a CloudWatch billing alarm before scanning large repos.

### Google Vertex AI (Model Garden)

`agentgg init --provider vertex --project my-gcp-project` walks you through setup. agentgg uses Google's [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials) — anything that works with `gcloud` (`gcloud auth application-default login`, `GOOGLE_APPLICATION_CREDENTIALS`, GCE/Cloud Run service account) works here. No API key.

Default model is `zai-org/glm-5-maas` (GLM-5 managed, OpenAI-compatible). Pricing and quota are governed by Vertex AI Model Garden, not agentgg.

Three things to know:

- **Enable Vertex AI** on the target GCP project before first scan (`gcloud services enable aiplatform.googleapis.com`) and grant the calling identity `roles/aiplatform.user`.
- **The MaaS endpoint runs in the `global` region pool only.** Code-under-scan transits a multi-region pool — if data residency matters, use a different provider.
- **GLM-5 defaults to thinking mode.** Responses include a `message.reasoning_content` field on top of the standard OpenAI shape; with very small `--max-turns` budgets you may see truncated answers.

---

## Examples

### Pick which agents to run

Run the default agent set (`~/.agentgg/agentgg-agents/base/`):

```bash
agentgg scan ./src -o ./out
```

Every scan makes LLM calls; cost scales with files × agents × phases. The biggest levers are scoping the scan (`--diff`, `--only`, `--exclude`, `--max-file-size`) and picking which agents run (`-t`). Ollama runs locally for free. `--concurrency` controls parallelism, not total cost.

A single slug:

```bash
agentgg scan ./src -t sql-injection -o ./out
```

Multiple slugs, comma-separated within one `-t`:

```bash
agentgg scan ./src -t sql-injection,hardcoded-secrets,command-injection -o ./out
```

A custom `.md` agent on disk:

```bash
agentgg scan ./src -t ./my-agents/path-traversal.md -o ./out
```

A `.txt` list file (one slug or path per line):

```bash
agentgg scan ./src -t ./agents.txt -o ./out
```

### Add validation

The validation phase is a second-pass LLM call per finding that re-reads the source and classifies as `confirmed` / `false-positive` / `out-of-scope` / `uncertain`. Off by default. Opt in:

```bash
agentgg scan ./src -t sql-injection --validate -o ./out
```

Each finding gets a `validation` section in its markdown file and a verdict count in `summary.md`.

### Use a scope file to mark out-of-scope findings

Pass any text file the validator should consult as scope context (your security policy, an audit-scope doc, internal notes, etc.). Without `--scope`, the `out-of-scope` verdict is withheld. The model would just be guessing.

```bash
agentgg scan ./src --validate --scope ./scope.md -o ./out
```

### Score findings

Add `--score` during scan, or run `agentgg score ./out` afterward, to attach a CVSS 3.1 severity to each finding.

```bash
agentgg scan ./src --validate --score -o ./out
```

### Re-run only the validation phase

Detect once, validate later (or with a different model / scope):

```bash
agentgg scan ./src -t sql-injection -o ./out         # detect only
agentgg revalidate ./out                              # validate everything pending
agentgg revalidate ./out --scope ./scope.md          # re-classify with scope
agentgg revalidate ./out --force                     # re-classify everything
```

### Force a fresh run

Resume is automatic. To bypass the cache:

```bash
agentgg scan ./src -t sql-injection -o ./out --rescan          # re-analyze every file
agentgg scan ./src -t sql-injection --validate --revalidate-all -o ./out
```

### Scan only what changed

`--diff <commit>` scopes the scan to a specific change set. It accepts whatever git accepts (a bare ref or a range), and the dots determine the semantic:

| Form | What it means | Use when |
|---|---|---|
| `--diff <commit>` | That commit's own changes (parent → commit) | Reviewing a single commit |
| `--diff a..b` | Tip-to-tip diff between two refs | You want the literal difference, even if `a` has advanced |
| `--diff a...b` | Merge-base of `a` and `b` → `b` | Reviewing a PR (matches GitHub's "Files changed" tab) |

How agents behave under `--diff`:

- **file- and walker-mode agents**: candidate file lists are intersected with the changed-file set, so unchanged files cost zero LLM calls.
- **hunt-mode agents**: still run whole-repo, but the commit message + patch is injected into the prompt as a focus hint. Tools stay unrestricted so the hunter can chase callers and imports outward for context.

```bash
# Review just the latest commit
agentgg scan ./src --diff HEAD -o ./out

# PR review against main (three dots, recommended)
git fetch origin main
agentgg scan ./src --diff origin/main...HEAD -o ./out

# Reviewing someone else's PR
git fetch origin pull/123/head:pr-123
git checkout pr-123
agentgg scan ./src --diff origin/main...HEAD -o ./out

# Combine with a template
agentgg scan ./src -t sql-injection --diff origin/main...HEAD -o ./out
```

The `--diff` value is part of each agent's resume scope. Changing it (or rebasing so the merge base moves) invalidates resume and re-runs the agent.

Patches larger than 64 MB (typically vendored-code or generated-file commits) are rejected for hunt agents. Narrow the scan or review them manually.

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

### Limit what gets scanned

Override the default glob exclusions / restrict to specific paths:

```bash
agentgg scan ./src --exclude "**/migrations/**" --exclude "vendor/**" -o ./out
agentgg scan ./src --only "src/api/**/*.ts" --only "src/handlers/**/*.ts" -o ./out
agentgg scan ./src --max-file-size 200 -o ./out      # skip files larger than 200 KB
```

The walker auto-skips lockfiles, minified bundles, binary assets, `node_modules`, `dist`, `.git`, and the scan-results directory regardless of flags.

### Use a one-off credential or model without saving it

Useful for CI runs where credentials come from secrets, not a saved config.

```bash
agentgg scan ./src \
  --provider anthropic \
  --api-key $ANTHROPIC_API_KEY \
  --model claude-opus-4-7 \
  -o ./out
```

`--api-key`, `--oauth-token`, `--base-url`, `--region`, `--project`, and `--model` all work as one-shot overrides. Each is scoped to its provider; passing one that doesn't apply (e.g. `--region` with `--provider openai`) is a hard error, not a silent ignore.

### Manage agents

```bash
agentgg agents list                                  # table of built-ins + custom
agentgg agents list --json                           # machine-readable
agentgg agents info sql-injection                    # show prompt + frontmatter
agentgg agents add ./my-agent.md                     # install into ~/.agentgg/agents/custom/
agentgg agents add ./agents-dir/                     # install every .md in a dir
agentgg agents remove my-agent                       # uninstall by slug
agentgg agents lint                                  # lint installed official tree
agentgg agents lint ./agentgg-agents                 # lint an arbitrary tree (pre-commit-friendly)
```

---

## GitHub Actions

Run agentgg on every pull request, scoped to the diff:

```yaml
# .github/workflows/agentgg.yml
name: agentgg PR review
on:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # required so --diff can compute the merge base
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm install -g agentgg
      - run: |
          agentgg scan . \
            --diff ${{ github.event.pull_request.base.sha }}...${{ github.sha }} \
            --validate \
            -o ./scan-results
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: agentgg-findings
          path: ./scan-results
```

Store your provider credential as a repo secret (`Settings → Secrets and variables → Actions`). The example uses Anthropic. Swap `ANTHROPIC_API_KEY` for `OPENAI_API_KEY` (and add `--provider openai`) for OpenAI, follow the AWS Bedrock section for Bedrock, or use [google-github-actions/auth](https://github.com/google-github-actions/auth) with `--provider vertex --project <id>` for Vertex AI.

Findings land in the `agentgg-findings` workflow artifact for download. To block merges on confirmed findings, parse `./scan-results/summary.md` (or the per-finding files in `findings/`) and `exit 1` from a follow-up step.

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
**Severity:** High (CVSS 7.5)
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

| Command | What it does |
|---|---|
| `agentgg init` | One-time setup wizard. Pick a provider (Anthropic / OpenAI / Ollama / Bedrock / Vertex) and paste credentials. Re-run to merge in another provider without overwriting the first. |
| `agentgg scan <path>` | Run a security scan. Fingerprints the project, dispatches rule / file / walker / hunt agents per each agent's `mode`, and writes findings + state to `--output`. Supports `--diff` for PR review, `--validate` for second-pass classification, `--scope` for SECURITY.md-style rules. Resumes by default. |
| `agentgg status [output-dir]` | Print a summary of a scan's output dir: file counts (analyzed / validated / pending), finding counts, validation verdicts, recent runs. Pass `--json` for machine-readable. |
| `agentgg revalidate [output-dir]` | Re-run the validation phase against findings already on disk. Skips detection entirely. Use to validate with a different model, scope, or after editing the validator prompt. |
| `agentgg score [output-dir]` | Standalone CVSS 3.1 scoring pass over persisted findings. The agent picks the 8 base metrics; the score and severity bucket are computed deterministically. |
| `agentgg view [output-dir]` | Boot the bundled Next.js viewer on a local port to browse findings in a web UI. |
| `agentgg agents list` | List installed agents (official + user-installed). Pass `--json` for machine-readable. |
| `agentgg agents info <slug>` | Print an agent's full frontmatter + prompt body. |
| `agentgg agents add <file-or-dir>` | Install an agent (or every `.md` in a directory) into `~/.agentgg/agents/custom/`. |
| `agentgg agents remove <slug>` | Uninstall a custom agent by slug. |
| `agentgg agents update` | Download / refresh the official catalog at `~/.agentgg/agentgg-agents/` from the [agentgg-agents](https://github.com/agentgg-dev/agentgg-agents) repo. |
| `agentgg agents lint [path]` | Check slug uniqueness, filename-matches-slug, schema validity, and regex compilation for an agent tree. Pre-commit-friendly. |
| `agentgg config` | Print the current saved config. Secrets are masked. |

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
--diff <commit>                 scope scan to a commit or range; file/walker agents only see touched files, hunt agents receive the patch as a focus hint (accepts `<ref>`, `a..b`, or `a...b`)
--no-gate                       disable the tech gate; force every selected agent to run regardless of the project fingerprint (default: agents with a `tech:` field skip when no detected tag matches)
--concurrency <n>               parallel files per agent (default 5)
--exclude <pattern>             glob to exclude (repeatable; additive)
--only <pattern>                restrict scan to matching globs (repeatable)
--max-file-size <kb>            skip files larger than this (default 500)
--provider <name>               anthropic | openai | ollama | bedrock | vertex (overrides config default)
--api-key <key>                 one-shot API key for anthropic / openai (not persisted)
--oauth-token <token>           one-shot Anthropic OAuth token (not persisted)
--base-url <url>                one-shot Ollama base URL (not persisted)
--region <name>                 one-shot AWS region for Bedrock (not persisted)
--project <id>                  one-shot GCP project ID for Vertex AI (not persisted)
-v, --verbose                   verbose output
```

## License

agentgg is licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) for the full text and [NOTICE](./NOTICE) for attribution.
