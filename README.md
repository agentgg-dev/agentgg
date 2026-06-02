<p align="center">
  <img src="https://raw.githubusercontent.com/agentgg-dev/agentgg-agents/main/static/logo.png" alt="agentgg" width="240" />
</p>

# agentgg

**Agentic SAST. White box. CI ready.**

`agentgg` is an agentic SAST scanner. Its agents reason about your code — they follow imports, check the call graph, and confirm findings before flagging, instead of pattern-matching the way traditional SAST does. The catalog auto-downloads on first scan from [agentgg-dev/agentgg-agents](https://github.com/agentgg-dev/agentgg-agents). Run on your full repo or on a git diff for PR reviews. There's **one kind of agent**: a tool-enabled investigation (Read/Glob/Grep) that declares **where** to look (file types, paths, content regex) and an optional **precondition** that decides whether it's even worth running on this repo. Every scan opens with a fast **recon** pass that briefs the agents on what the project is. Interrupted scans resume on re-run: completed agents are skipped, only new or changed work hits the LLM again.

**[agentgg.dev](https://agentgg.dev)** · [Agents catalog](https://github.com/agentgg-dev/agentgg-agents) · [Report a bug](https://github.com/agentgg-dev/agentgg/issues/new/choose) · [Report a security issue](https://github.com/agentgg-dev/agentgg/security)

> **agentgg is in beta.** Things will move and edges will be rough. Bug reports and feedback are very welcome. [Open an issue](https://github.com/agentgg-dev/agentgg/issues/new/choose).

<p align="center">
  <img src="https://raw.githubusercontent.com/agentgg-dev/agentgg/main/static/agentgg-view.png" alt="agentgg viewer UI showing scan findings" width="780" />
</p>

## Table of Contents

- [Install](#install)
- [Quick start](#quick-start)
- [How a scan runs](#how-a-scan-runs)
- [Agent templates](#agent-templates)
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
cd packages/cli && pnpm link --global   # exposes the `agentgg` command (run `pnpm setup` once if it has no global bin dir)
```

The global command is a link to `packages/cli`, so a later `pnpm --filter agentgg build` is picked up automatically — no re-link needed.

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
    ├── recon.json        ← the recon brief (phase 1)
    ├── plan.json         ← which agents queued / skipped + why (phase 2)
    ├── runs/<id>.json    ← one per scan / recon / revalidate / score / summary
    ├── agents/<slug>.json← per-agent resume sidecar
    └── files/<path>.json ← FileRecord per scanned source file
```

The `state/` directory is what makes resume, status, and revalidate work. Re-running `scan` with the same `-o` skips files that haven't changed. Different `-o` = fresh scan.

## How a scan runs

A scan is three phases, and each writes a durable artifact under `state/` so the steps are inspectable (and, later, distributable):

1. **Recon** — a fast, tool-enabled survey runs once and writes a concise project brief to `state/recon.json`: what the project is, languages, frameworks, auth model, integrations. The brief is fed into the next phases so agents start oriented. Cached across runs; force a refresh with `--re-recon`.
2. **Preconditions** — every selected agent is checked to decide whether it's worth running on *this* repo, and the queued/skipped decisions (with reasons) are written to `state/plan.json` **before any agent runs**.
3. **Run → validate → score → report** — each queued agent runs over its file set in batches; then the optional validation and scoring passes classify and rate the findings; finally `summary.md` + `findings/*.md` are rendered.

Interrupted scans resume: a completed agent is skipped on re-run (its findings lifted from disk); only new or changed work hits the LLM. Changing scope (`--diff`, `--exclude`, …) or the recon brief invalidates and re-runs the affected agents.

**Recon and the plan are reused, not just resumed.** When a `state/recon.json` already covers the project (same root + stack fingerprint), the survey is skipped; and when a matching `state/plan.json` already covers your `-t` selection, the precondition loop is skipped too — the scan just runs the agents the plan already queued. `--re-recon` forces both to be recomputed.

**The phases can also run on their own**, each operating on the same `--output` dir:

- `agentgg recon <path> -o <dir>` runs phases 1–2 only (writes `recon.json` + `plan.json`, no detection) — a cheap preview of what a scan would run, and a durable plan→run hand-off.
- `agentgg revalidate <dir>` / `agentgg score <dir>` / `agentgg summary <dir>` run the validate / score / report steps on already-persisted findings.

And the two phases can be skipped inline on a `scan`:

- `--no-recon` skips the survey **and** the precondition loop, running every `-t` agent unconditionally with no project brief.
- `--no-summary` skips the report render (findings still persist to `state/files/*`); render later with `agentgg summary`. `revalidate` and `score` accept `--no-summary` too, so you can defer the report to a single explicit render at the end.

## Agent templates

Every agent is one kind of thing — a markdown file (YAML frontmatter + prompt body) with three parts: a **precondition**, a **where**, and the **instructions**. There are no execution modes.

```markdown
---
slug: sql-injection
name: SQL Injection
description: SQL built from untrusted input instead of parameterized queries.
noiseTier: normal
precondition:                      # 1. should this agent run on THIS repo?
  regex:
    patterns:
      - regex: "\\.(query|execute)\\s*\\("
        in: ["**/*.{ts,js,py,go,php}"]
  # prompt: "Run only if this project talks to a SQL database."   # optional LLM gate
where:                             # 2. which files to run on
  extensions: [ts, js, py, go, php]
  excludePatterns: ["**/*.{test,spec}.*"]
  preFilter:                       # narrow to files containing a match (regex)
    - { regex: "\\.(query|execute)\\s*\\(", label: "raw SQL call" }
references: [CWE-89]
---

You are reviewing source for SQL injection. ...   # 3. the instructions
```

**Precondition** (optional) decides whether the agent is queued. `regex` is a cheap, no-LLM filesystem check — file `extensions`, sentinel `files`, `directories`, or content `patterns`. `prompt` is a one-shot LLM check that sees the recon brief. Both present = AND; omit it = always run. (This replaces the old per-stack tech gate: a PHP agent simply preconditions on `.php` existing, so it skips a Go-only repo on its own.)

**Where** is the file set the agent runs on. Use plain `extensions` (nuclei-style — `ts`, `php`), plus optional `filePatterns`/`excludePatterns` for complex include/exclude rules (globs, or a bare directory/file path — a directory matches everything under it), and a `preFilter` regex that narrows to files containing a match (and hands the model those lines as anchors). Empty `where` = all files. The matching files are reviewed in batches of `maxFilesPerBatch` (default 5).

**Instructions** are the prompt body. Every agent is tool-enabled (Read/Glob/Grep), so although it's seeded with specific files, it can follow imports and chase callers into other files to confirm a finding.

Templates live in the **official catalog** (`~/.agentgg/agentgg-agents/`; refresh with `agentgg agents update`), are **user-installed** (`agentgg agents add ./my-agent.md`), or passed **per-scan** via `-t` — a slug, a `.md` file, a directory of `.md` files, or a `.txt` list.

## Providers

`agentgg init` writes credentials to `~/.agentgg/config.json`. Scan state is per-output-dir and unrelated to this file.

| Provider | Credential |
|---|---|
| **Anthropic** | API key (`sk-ant-api...`) or OAuth (`sk-ant-oat...`, Claude Pro/Max) |
| **OpenAI** | API key |
| **Ollama** | local URL |
| **AWS Bedrock** | AWS credentials (env / `~/.aws/credentials` / IAM role) |
| **Google Vertex AI (Model Garden)** | Google ADC (`gcloud auth application-default login` / `GOOGLE_APPLICATION_CREDENTIALS` / GCE/Cloud Run service account) + GCP project ID |

Every agent is multi-step and tool-using (Read/Glob/Grep), so finding quality scales with model quality.

### AWS Bedrock

`agentgg init --provider bedrock --region us-east-1` walks you through setup. agentgg picks up your existing AWS credentials. Anything that works with the AWS CLI (env vars, `aws configure`, SSO, IAM role) works here.

Two things to know:

- **Inference profiles are required for newer Claude models.** Default uses a US profile (`us.anthropic.*`); EU/APAC use `eu.*` / `apac.*`. Override at init time.
- **Bedrock has no free tier.** Set a CloudWatch billing alarm before scanning large repos.

### Google Vertex AI (Model Garden)

`agentgg init --provider vertex --project my-gcp-project` walks you through setup. agentgg uses Google's [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials) — anything that works with `gcloud` (`gcloud auth application-default login`, `GOOGLE_APPLICATION_CREDENTIALS`, GCE/Cloud Run service account) works here. No API key.

Default model is `zai-org/glm-5-maas` (GLM-5 managed, OpenAI-compatible). The `init` picker also surfaces Llama 4 Scout and Maverick; pass `--model <id>` to use any other Model Garden MaaS model reachable through the OpenAI-compatible endpoint. Pricing and quota are governed by Vertex AI Model Garden, not agentgg.

Things to know:

- **Enable the specific Model Garden publisher model** in your GCP project before first scan (each one is gated separately) and grant the calling identity `roles/aiplatform.user`. `aiplatform.googleapis.com` itself must be enabled too: `gcloud services enable aiplatform.googleapis.com`.
- **Pass `--region <name>` matching the model.** Each Vertex MaaS model is published to a specific region pool (check the model's Model Garden page in the GCP console). Defaults to `global`. The `init` wizard suggests the right region per curated model.

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

### Plan first, then run

Run recon + precondition planning on its own to preview what a scan would execute. The brief and plan are written to `--output`, and a follow-up `scan` reuses both — no second survey, no second precondition pass:

```bash
agentgg recon ./src -t base -o ./out     # phase 1–2 only: writes recon.json + plan.json
agentgg scan  ./src -t base -o ./out     # reuses the brief + plan, runs the queued agents
```

To skip recon and gating entirely and run exactly the agents you pass (no project brief, no precondition filtering):

```bash
agentgg scan ./src -t sql-injection --no-recon -o ./out
```

### Defer the report to the end

Each of `scan` / `revalidate` / `score` re-renders `summary.md` when it finishes. Pass `--no-summary` to skip those intermediate renders and produce the report once, explicitly, at the end:

```bash
agentgg scan       ./src -t base -o ./out --no-summary
agentgg revalidate ./out --no-summary
agentgg score      ./out --no-summary
agentgg summary    ./out                   # render summary.md + findings/*.md once
```

Findings persist to `state/files/*` regardless, so `agentgg summary` can rebuild the report at any time.

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

- Each agent's candidate file list is **intersected with the changed-file set**, so unchanged files cost zero LLM calls.
- The commit message + patch is **injected into the agent's prompt as a focus hint**. Tools stay unrestricted, so the agent can chase callers and imports outward for context.

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

Patches larger than 64 MB (typically vendored-code or generated-file commits) are rejected. Narrow the scan or review them manually.

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

By default the scan skips a built-in exclude set — lockfiles, minified bundles, binary assets, `node_modules`, `dist`, `.git`, and the scan-results directory. Pass `--no-default-excludes` to scan everything, or set `where.useDefaultExcludes: false` on a single agent. CLI `--exclude` paths are always treated as deleted (invisible to every agent).

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
| `agentgg recon <path>` | Run only phases 1–2 — the recon survey + precondition planning — writing `recon.json` + `plan.json` to `--output`. No detection. A cheap preview of what a scan would run; a later `scan` on the same `--output` reuses the brief and plan. |
| `agentgg scan <path>` | Run a security scan: recon → precondition gating → run queued agents → validate → score → report, writing findings + state to `--output`. Supports `--diff` for PR review, `--validate` for second-pass classification, `--scope` for SECURITY.md-style rules, `--no-recon` to run every `-t` agent without gating, and `--no-summary` to defer the report. Reuses a cached recon brief + plan; resumes by default. |
| `agentgg status [output-dir]` | Print a summary of a scan's output dir: file counts (analyzed / validated / pending), finding counts, validation verdicts, recent runs. Pass `--json` for machine-readable. |
| `agentgg revalidate [output-dir]` | Re-run the validation phase against findings already on disk. Skips detection entirely. Use to validate with a different model, scope, or after editing the validator prompt. `--no-summary` defers the report render. |
| `agentgg score [output-dir]` | Standalone CVSS 3.1 scoring pass over persisted findings. The agent picks the 8 base metrics; the score and severity bucket are computed deterministically. `--no-summary` defers the report render. |
| `agentgg summary [output-dir]` | Render `summary.md` + `findings/*.md` from persisted findings. No LLM, no detection. Pairs with `scan/revalidate/score --no-summary` to render the report once, at the end. |
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
--diff <commit>                 scope scan to a commit or range; each agent's candidate files are intersected with the touched files and the patch is injected as a focus hint (accepts `<ref>`, `a..b`, or `a...b`)
--re-recon                      re-run the recon pass + precondition plan instead of reusing the cached brief/plan
--no-recon                      skip the recon survey AND precondition gating; run every -t agent unconditionally
--no-summary                    skip writing the markdown report (summary.md + findings/*.md); state still persists
--max-files-per-batch <n>       candidate files per agent batch (overrides the agent's where.maxFilesPerBatch)
--concurrency <n>               max LLM sessions in flight across the whole scan — agent batches, validation, and scoring all draw from one pool (default 5)
--exclude <pattern>             path/glob to exclude — treated as deleted (repeatable; additive)
--only <pattern>                restrict scan to matching globs (repeatable)
--max-file-size <kb>            skip files larger than this (default 500)
--no-default-excludes           don't apply the built-in excludes (node_modules, .git, lockfiles, binaries)
--provider <name>               anthropic | openai | ollama | bedrock | vertex (overrides config default)
--api-key <key>                 one-shot API key for anthropic / openai (not persisted)
--oauth-token <token>           one-shot Anthropic OAuth token (not persisted)
--base-url <url>                one-shot Ollama base URL (not persisted)
--region <name>                 one-shot region: AWS region (Bedrock) or Vertex publisher region pool (e.g. global, us-central1)
--project <id>                  one-shot GCP project ID for Vertex AI (not persisted)
-v, --verbose                   verbose output
```

## License

agentgg is licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) for the full text and [NOTICE](./NOTICE) for attribution.
