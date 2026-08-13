<p align="center">
  <img src="https://raw.githubusercontent.com/agentgg-dev/agentgg-agents/main/static/logo.png" alt="agentgg" width="240" />
</p>

# agentgg

**Agentic SAST. White box. CI ready.**

`agentgg` is an agentic SAST scanner. Its agents reason about your code — they follow imports, check the call graph, and confirm findings before flagging, instead of pattern-matching the way traditional SAST does. The catalog auto-downloads on first scan from [agentgg-dev/agentgg-agents](https://github.com/agentgg-dev/agentgg-agents). Run on your full repo or on a git diff for PR reviews. Each agent is a tool-enabled investigation (Read/Glob/Grep) that declares **where** to look (file types, paths, content regex) and an optional **precondition** that decides whether it's even worth running on this repo. Every scan opens with a fast **recon** pass that briefs the agents on what the project is. Interrupted scans resume on re-run: completed agents are skipped, only new or changed work hits the LLM again. Past incidents become new detectors via `agentgg create`, which distills a security report into a reusable repo-shaped agent.

**[agentgg.dev](https://agentgg.dev)** · [Platform](https://app.agentgg.dev) · [Agents catalog](https://github.com/agentgg-dev/agentgg-agents) · [Report a bug](https://github.com/agentgg-dev/agentgg/issues/new/choose) · [Report a security issue](https://github.com/agentgg-dev/agentgg/security)

> **agentgg is in beta.** Things will move and edges will be rough. Bug reports and feedback are very welcome. [Open an issue](https://github.com/agentgg-dev/agentgg/issues/new/choose).

<p align="center">
  <img src="https://raw.githubusercontent.com/agentgg-dev/agentgg/main/static/agentgg-view.png" alt="agentgg viewer UI showing scan findings" width="780" />
</p>

## Table of Contents

- [Install](#install)
- [Quick start](#quick-start)
- [How a scan runs](#how-a-scan-runs)
- [Execution model: ordering, batching, and concurrency](#execution-model-ordering-batching-and-concurrency)
- [Agent templates](#agent-templates)
- [Authoring agents from past reports](#authoring-agents-from-past-reports)
- [Providers](#providers)
- [Examples](#examples)
- [GitHub Actions](#github-actions)
- [Report format](#report-format)
- [Commands](#commands)
- [Scan flag reference](#scan-flag-reference)
- [License](#license)

## Install

> Don't want to run it locally? [app.agentgg.dev](https://app.agentgg.dev) runs the same scanner as a hosted service: upload a repo, no install, no provider key of your own.

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
agentgg scan ./src -o ./out                                        # scan everything (validate/score/dedup on by default)
agentgg scan ./src --diff origin/main...HEAD -o ./out              # PR-style: scan only what changed
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
3. **Run → validate → score → dedup → report** — each queued agent runs over its file set in batches; then the optional validation, scoring, and de-duplication passes classify, rate, and cluster findings; finally `summary.md` + `findings/*.md` are rendered. Dedup is the last gather step: it groups same-root-cause findings per source file across agents and folds them under one primary so the report collapses them.

Interrupted scans resume: a completed agent is skipped on re-run (its findings lifted from disk); only new or changed work hits the LLM. Changing scope (`--diff`, `--exclude`, …) or the recon brief invalidates and re-runs the affected agents.

**Recon and the plan are reused, not just resumed.** When a `state/recon.json` already covers the project (same source identity + stack fingerprint), the survey is skipped; and when a matching `state/plan.json` already covers your `-t` selection, the precondition loop is skipped too — the scan just runs the agents the plan already queued. `--re-recon` forces both to be recomputed.

**Source identity defaults to the absolute scan root.** That is what keeps two projects sharing one `-o` directory from serving each other's cached findings. It also means resume silently stops applying whenever the path moves — a CI checkout under a fresh workspace dir, a container mount, a renamed folder — and the scan re-pays for detection over unchanged code. Pass the same `--source-id <id>` on every run to pin the identity to a label of your choosing instead. Reusing one id across genuinely different codebases will serve the wrong cached findings, so keep it one id per codebase.

**The phases can also run on their own**, each operating on the same `--output` dir:

- `agentgg recon <path> -o <dir>` runs phases 1–2 only (writes `recon.json` + `plan.json`, no detection) — a cheap preview of what a scan would run, and a durable plan→run hand-off.
- `agentgg revalidate <dir>` / `agentgg score <dir>` / `agentgg dedup <dir>` / `agentgg summary <dir>` run the validate / score / dedup / report steps on already-persisted findings.

And the two phases can be skipped inline on a `scan`:

- `--no-recon` skips the survey **and** the precondition loop, running every `-t` agent unconditionally with no project brief.
- `--no-summary` skips the report render (findings still persist to `state/files/*`); render later with `agentgg summary`. `revalidate` and `score` accept `--no-summary` too, so you can defer the report to a single explicit render at the end.

## Execution model: ordering, batching, and concurrency

The section above is the *what*. This one is the *how*: what runs in parallel, how work is batched, and where the barriers are. The short version:

- **Phases are strictly sequential.** Each phase fully drains before the next begins. Parallelism lives *inside* a phase, never across phase boundaries.
- **One concurrency primitive.** Every parallel phase uses the same bounded worker pool (`runConcurrent`): a shared cursor hands out work to at most `--concurrency` workers (**default 5**). It is fail-fast: the first fatal error (e.g. a bad credential) stops new dispatch, lets in-flight calls drain, then rethrows. Draining first is deliberate, so a `process.exit` never races a still-shutting-down agent subprocess.
- **One knob for all parallelism.** `--concurrency` bounds *in-flight LLM sessions* in every parallel phase (precondition prompt gates, agent batches, validation, scoring, dedup). Because phases don't overlap, it is not additive: at most `--concurrency` sessions are ever in flight at once. It bounds parallelism, not total cost.

### The pipeline, phase by phase

```
preamble ─▶ recon ─▶ preconditions ─▶ AGENTS ─▶ validate ─▶ score ─▶ dedup ─▶ report
 (git,      (1 LLM   (regex census,   (batch    (pool over  (pool    (pool     (no LLM)
  auto-      survey)  then gate pool)  pool)     findings)   over     over
  exclude)                                                   findings) file-groups)
        └──────────────── each ── is a barrier: the next phase waits ────────────────┘
```

**0. Preamble** (no LLM, except auto-exclude). Load the agent catalog, fingerprint the stack, and, under `--diff`, shell out to git once to compute the changed-file set and the patch text. If `--auto-exclude` is on (default), one LLM pass over the directory layout picks non-runtime folders to skip; it runs *before* recon so every later phase inherits the excludes.

**1. Recon** (1 LLM session). A single tool-enabled survey of the repo (up to `--max-turns`, default 50) writes the project brief. It is advisory: if it fails or times out, the scan continues with a minimal brief. Cached by `reconHash`, so an unchanged project skips it. Barrier: the brief feeds phases 2–4.

**2. Preconditions** (mixed). Decides which agents are queued.
- *Regex census*: the tree is walked **once**, and each agent's `regex` precondition is tested against that shared file list. Pure filesystem, no LLM. Runs first and short-circuits: an agent that declares both `regex` and `prompt` and fails the regex is skipped without an LLM call.
- *Prompt gates*: agents that declare an LLM `prompt` (and passed regex) are evaluated **concurrently** in a pool at `--concurrency`. Barrier: the entire queued set is decided, and `plan.json` written, before any agent runs. A cached plan covering your `-t` selection is reused instead of re-running the gates.

**3. Agents.** The core, split into a cheap sequential setup and a parallel drain.
- *3a. Enqueue* (sequential, no LLM). For each queued agent, in order: resolve `where` → walk + `preFilter` to candidate files, intersect with the `--diff` set, apply the `--max-files-per-agent` cap (default 300), drop already-analyzed files via per-file resume, then split the remainder into **batches of `maxFilesPerBatch` (default 5)**. Every `(agent, batch)` pair is pushed onto **one shared queue**. An agent whose prior run still matches scope is lifted from disk and skipped entirely here. `--max-batches` (default 250) then truncates the queue.
- *3b. Drain* (concurrent). One bounded pool runs over **every `(agent, batch)` pair across all agents** at `--concurrency`. This is the key design point: batches from *different* agents interleave in the same pool, so agents are **not** run one-at-a-time. Each batch is one tool-enabled LLM session (up to the agent's `maxTurnsPerBatch`, default 50) that reviews its files and follows imports/callers outward. A fast agent's batches and a slow agent's batches overlap instead of blocking each other.

  ```
  batch pool (--concurrency = 5)
    worker1: [sqli/batch1] [xss/batch2] [secrets/batch1] ...
    worker2: [sqli/batch2] [ssrf/batch1] [sqli/batch3]   ...
    worker3: [xss/batch1]  [secrets/batch2] ...
    ...                    (batches from all agents, one queue)
  ```

**4. Validate** (concurrent, on by default). After **all** batches settle, a pool over the findings at `--concurrency`. Each finding is one LLM session that re-reads the source from the working tree and traces the exploit chain across files, classifying `confirmed` / `false-positive` / `out-of-scope` / `uncertain`. Findings already carrying a verdict are skipped (resume); `--revalidate-all` forces re-classification.

**5. Score** (concurrent, on by default). After validation, a pool over the scorable findings at `--concurrency` picks CVSS 3.1 base metrics per finding. Skips findings the validator disqualified (`false-positive` / `out-of-scope`) and anything already scored.

**6. Dedup** (concurrent, on by default). Runs **last**. Unlike the per-finding phases, it first needs every finding for a file co-located, so it groups shippable findings **by source file across all agents** (a barrier), then deduplicates each file-group **concurrently** at `--concurrency`. One LLM session per file that has 2+ findings; same-root-cause findings get folded under one primary.

**7. Report** (no LLM). Render `summary.md` + `findings/*.md`. Skipped by `--no-summary`.

### What this means in practice

- The only phase where many agents work at once is 3b. Everything before it (walk, prefilter, resume, batching) is cheap sequential setup with no LLM calls, and everything after it (validate/score/dedup) is per-finding fan-out, not per-agent.
- Raising `--concurrency` speeds up phases 2–6 by running more sessions at once. It does not change how many sessions run in total, only how many run in parallel, so it trades wall-clock for peak API load, not for cost.
- Resume is orthogonal to all of this: completed agents and already-validated/scored findings are lifted from disk *before* each pool is built, so a re-run only pools the work that actually changed.

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

## Authoring agents from past reports

`agentgg create` turns a past security report (an internal post-mortem, a GHSA, a CVE write-up) into a reusable agent shaped for **this** codebase. A tool-enabled LLM session reads the report, explores the repo to confirm how the issue manifested in code, and emits an agent that catches the same anti-pattern if it recurs. The goal is not to re-find the exact past bug — that's already fixed — but to catch a future re-introduction by a different author in a different file.

```bash
agentgg create -c ./src -r ./incidents/2024-q3-sqli.md -o ./generated-agents
```

`--report` accepts the same shapes `-t` accepts: a single `.md` / `.txt` file, a directory of them, or a `.txt` list of paths. Each report becomes one agent file, named `<slug>-<hash>.md` (the hash is derived from the code root + report path + report contents, so reruns are idempotent and never collide across reports).

```bash
# Distill a directory of incident reports in one pass
agentgg create -c ./src -r ./incidents/ -o ./generated-agents

# Use a one-off model and provider without saving credentials
agentgg create -c ./src -r ./incidents/2024-q3-sqli.md -o ./out \
  --provider anthropic --api-key $ANTHROPIC_API_KEY
```

The generated agents drop into `--output` only — they are not auto-installed. Inspect them, then install with `agentgg agents add ./generated-agents` and they show up in `agentgg agents list` and in every subsequent scan.

## Providers

`agentgg init` writes credentials to `~/.agentgg/config.json`. Scan state is per-output-dir and unrelated to this file.

| Provider | Credential |
|---|---|
| **Anthropic** | API key (`sk-ant-api...`) or OAuth (`sk-ant-oat...`, Claude Pro/Max) |
| **OpenAI** | API key |
| **Ollama** | local URL |
| **AWS Bedrock** | AWS credentials (env / `~/.aws/credentials` / IAM role) |
| **Google Vertex AI (Model Garden)** | Google ADC (`gcloud auth application-default login` / `GOOGLE_APPLICATION_CREDENTIALS` / GCE/Cloud Run service account) + GCP project ID |
| **OpenRouter** | API key (`sk-or-v1...`) |

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

### OpenRouter

`agentgg init --provider openrouter` prompts for your API key (`sk-or-v1...`, from [openrouter.ai/settings/keys](https://openrouter.ai/settings/keys)). Default model is `z-ai/glm-5.2`; pass `--model <slug>` for any other OpenRouter model (route suffixes like `:nitro` work).

OpenRouter routes each request to one of several hosts serving the model. Tune that routing with env vars (`OPENROUTER_QUANTIZATIONS`, `OPENROUTER_PROVIDER_ORDER`, `OPENROUTER_SORT`, `OPENROUTER_IGNORE`, `OPENROUTER_MAX_PRICE_*`, `OPENROUTER_ZDR`) or, per run, with `--openrouter-routing` — inline JSON or a path to a `.json` file holding an [OpenRouter provider block](https://openrouter.ai/docs/features/provider-routing). `scan`, `recon`, and `dedup` all accept it. Defaults pin fp8 and require tool-calling support; an invalid routing block or unknown model aborts the run.

Hosts serving the same model are not interchangeable. A host that returns the answer in the `reasoning` channel and leaves content empty fails every structured call while reporting success, surfacing as `No object generated: the model did not return a response`, and nothing retries or re-routes around it. Exclude that host with `OPENROUTER_IGNORE` (a CSV of provider slugs) or an `ignore` array in `--openrouter-routing`. A base slug (`baseten`) drops all of that provider's endpoints, a full slug (`baseten/fast`) just one.

---

## Examples

### Pick which agents to run

Run the default agent set (`~/.agentgg/agentgg-agents/base/`):

```bash
agentgg scan ./src -o ./out
```

Every scan makes LLM calls; cost scales with files × agents × phases. The biggest levers are scoping the scan (`--diff`, `--only`, `--exclude`, `--auto-exclude`, `--max-file-size`, `--max-files-per-agent`, `--max-batches`) and picking which agents run (`-t`). Ollama runs locally for free. `--concurrency` controls parallelism, not total cost.

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

### Validation

The validation phase is a second-pass LLM call per finding that re-reads the source and classifies as `confirmed` / `false-positive` / `out-of-scope` / `uncertain`. **On by default.** Turn it off for a detection-only run:

```bash
agentgg scan ./src -t sql-injection --no-validate -o ./out
```

Each finding gets a `validation` section in its markdown file and a verdict count in `summary.md`.

### Scope: filter findings by trust boundary

During validation, findings are checked against a **scope document** — the trust-boundary rules that decide whether a defect is actually exploitable. A built-in default scope applies automatically, so `out-of-scope` is a real verdict out of the box:

```bash
agentgg scan ./src -o ./out                          # validation + built-in default scope, both on by default
```

Override it with your own policy (any text file: a security policy, an audit-scope doc, internal notes), or turn scope filtering off entirely:

```bash
agentgg scan ./src --scope ./scope.md -o ./out       # your scope instead of the default
agentgg scan ./src --no-scope -o ./out               # no scope filtering at all
```

Scope only matters where validation runs. Because validation is on by default, the default scope applies to a plain `scan` and to any `revalidate` (which always validates). A detection-only run (`--no-validate`) never consults it.

### Scoring

The CVSS 3.1 scoring phase attaches a severity to each finding. **On by default** during scan; turn it off with `--no-score`, or run `agentgg score ./out` afterward.

```bash
agentgg scan ./src -o ./out                          # scoring on by default
agentgg scan ./src --no-score -o ./out               # skip scoring
```

### Re-run only the validation phase

Detect once, validate later (or with a different model / scope):

```bash
agentgg scan ./src -t sql-injection -o ./out         # detect only
agentgg revalidate ./out                              # validate pending (uses the default scope)
agentgg revalidate ./out --scope ./scope.md          # re-classify with your scope
agentgg revalidate ./out --no-scope                  # re-classify with no scope filtering
agentgg revalidate ./out --force                     # re-classify everything (already-validated too)
```

### Plan first, then run

Run recon + precondition planning on its own to preview what a scan would execute. The brief and plan are written to `--output`, and a follow-up `scan` reuses both — no second survey, no second precondition pass:

```bash
agentgg recon ./src -t base -o ./out     # phase 1–2 only: writes recon.json + plan.json
agentgg scan  ./src -t base -o ./out     # reuses the brief + plan, runs the queued agents
```

`recon` runs the same default `--auto-exclude` pass as `scan` (and records the chosen globs in `plan.json`), so the preview faithfully reflects what the scan would skip. Pass `--no-auto-exclude` to plan the whole tree.

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
agentgg scan ./src --max-file-size 200 -o ./out          # skip files larger than 200 KB (default 500)
agentgg scan ./src --max-files-per-agent 30 -o ./out     # each agent reviews at most 30 files (default 300)
agentgg scan ./src --max-batches 50 -o ./out             # run at most 50 agent batches this scan (default 250)
agentgg scan ./src --no-max-files-per-agent --no-max-batches --no-max-file-size -o ./out   # disable every cap (fully uncapped)
```

By default the scan skips a built-in exclude set — lockfiles, minified bundles, binary assets, `node_modules`, `dist`, `.git`, and the scan-results directory. Pass `--no-default-excludes` to scan everything, or set `where.useDefaultExcludes: false` on a single agent. CLI `--exclude` paths are always treated as deleted (invisible to every agent).

Auto-exclude (**on by default**; disable with `--no-auto-exclude`) lets the model pick additional non-runtime folders — tests, fixtures, docs, generated output, vendored dependencies — to skip before the scan starts. It runs one cheap pass over the directory layout ahead of recon, so recon and every agent inherit the result. Its picks are always logged (with a reason per folder under `--verbose`) and combine with any manual `--exclude` paths; it only ever removes folders, never adds them back.

`--max-files-per-agent` is a per-agent ceiling (**default 300**): when an agent's `where` resolves to more candidate files than the cap, it reviews the first `<n>` (in the walker's deterministic scan order) and drops the rest, rather than being skipped. A guardrail so one over-broad agent can't blow up cost or time on a large repo. Pass `--no-max-files-per-agent` to disable the cap. Different from `--max-files-per-batch`, which only sets how many files pack into a single LLM session.

`--max-batches` is a whole-scan ceiling on the number of agent batches (**default 250**). Once every `(agent, batch)` pair is enqueued, the pool is truncated to `<n>` (in enqueue order) and the rest are dropped before any LLM call runs. Agents whose batches are dropped write no completion sidecar, so a later scan picks them up where this one stopped — a way to spread a large scan across several runs or cap the spend of a single run. Pass `--no-max-batches` to disable the cap. Different from `--concurrency`, which bounds how many batches run in parallel, not how many run at all.

`--max-file-size` (**default 500 KB**) skips files larger than the limit before any agent sees them. Pass `--no-max-file-size` to scan files of any size.

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
| `agentgg scan <path>` | Run a security scan: recon → precondition gating → run queued agents → validate → score → report, writing findings + state to `--output`. Supports `--diff` for PR review, `--validate` for second-pass classification (which applies a built-in trust-boundary scope by default — override with `--scope`, disable with `--no-scope`), `--no-recon` to run every `-t` agent without gating, and `--no-summary` to defer the report. Reuses a cached recon brief + plan; resumes by default. |
| `agentgg status [output-dir]` | Print a summary of a scan's output dir: file counts (analyzed / validated / pending), finding counts, validation verdicts, recent runs. Pass `--json` for machine-readable. |
| `agentgg revalidate [output-dir]` | Re-run the validation phase against findings already on disk. Skips detection entirely. Use to validate with a different model, scope, or after editing the validator prompt. `--no-summary` defers the report render. |
| `agentgg score [output-dir]` | Standalone CVSS 3.1 scoring pass over persisted findings. The agent picks the 8 base metrics; the score and severity bucket are computed deterministically. `--no-summary` defers the report render. |
| `agentgg dedup [output-dir]` | De-duplicate findings on disk: group same-root-cause findings per source file across agents, fold them under one primary, and mark the rest with a `dedup` field so the report collapses them. Pass `--delete-duplicates` to physically remove marked duplicates; `--no-summary` defers the report render. |
| `agentgg create` | Distill a past security report (`.md`/`.txt`, a directory of them, or a `.txt` list) into a reusable agent `.md` shaped for the codebase the report came from. Standalone: no `state/` dir, no scan resume. Takes `-c <code-path>`, `-r <report-path>`, `-o <output-dir>`. Each report yields one `<slug>-<hash>.md`; install with `agentgg agents add`. |
| `agentgg summary [output-dir]` | Render `summary.md` + `findings/*.md` from persisted findings. No LLM, no detection. Pairs with `scan/revalidate/score/dedup --no-summary` to render the report once, at the end. |
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
--source-id <id>                stable identity for the scanned source; resume state in -o is reused only when it matches (default: the absolute scan root — set it when the path changes between runs, e.g. CI checkouts or container mounts)
--validate / --no-validate      second-pass validation phase per finding (on by default; --no-validate for a detection-only run)
--score / --no-score            CVSS 3.1 scoring phase (on by default; --no-score to skip)
--scope <path>                  scope doc the validator consults for trust-boundary rules; overrides the built-in default (enables `out-of-scope`)
--no-scope                      disable the built-in default scope (skip trust-boundary filtering during validation)
--rescan                        re-analyze files even if a prior run covered them
--revalidate-all                re-validate findings that already have a verdict
--diff <commit>                 scope scan to a commit or range; each agent's candidate files are intersected with the touched files and the patch is injected as a focus hint (accepts `<ref>`, `a..b`, or `a...b`)
--re-recon                      re-run the recon pass + precondition plan instead of reusing the cached brief/plan
--no-recon                      skip the recon survey AND precondition gating; run every -t agent unconditionally
--no-summary                    skip writing the markdown report (summary.md + findings/*.md); state still persists
--max-files-per-batch <n>       candidate files per agent batch (overrides the agent's where.maxFilesPerBatch)
--max-files-per-agent <n>       cap the candidate files each agent reviews — keep the first <n> in scan order, drop the rest (guardrail against an over-broad agent; default 300, --no-max-files-per-agent disables)
--no-max-files-per-agent        disable the per-agent candidate-file cap (review every file)
--max-batches <n>               cap the total agent batches run this scan — keep the first <n> in enqueue order, drop the rest (dropped agents re-run next scan; default 250, --no-max-batches disables)
--no-max-batches                disable the whole-scan agent-batch cap (run every batch)
--concurrency <n>               max LLM sessions in flight across the whole scan — agent batches, validation, and scoring all draw from one pool (default 5)
--dedup / --no-dedup            final de-duplication pass that clusters same-root-cause findings per source file (on by default; --no-dedup to skip)
--delete-duplicates             with dedup, physically remove duplicate findings instead of just marking them
--exclude <pattern>             path/glob to exclude — treated as deleted (repeatable; additive)
--only <pattern>                restrict scan to matching globs (repeatable)
--max-file-size <kb>            skip files larger than this (default 500; --no-max-file-size disables)
--no-max-file-size              don't skip large files (scan files of any size)
--no-default-excludes           don't apply the built-in excludes (node_modules, .git, lockfiles, binaries)
--auto-exclude / --no-auto-exclude  model picks non-runtime folders (tests, docs, generated, vendored) to skip up front (on by default; logged; --no-auto-exclude to disable)
--serve [port]                  boot the local web UI when the scan finishes (opt-in; default port 3737)
--provider <name>               anthropic | openai | ollama | bedrock | vertex (overrides config default)
--api-key <key>                 one-shot API key for anthropic / openai (not persisted)
--oauth-token <token>           one-shot Anthropic OAuth token (not persisted)
--base-url <url>                one-shot Ollama base URL (not persisted)
--region <name>                 one-shot region: AWS region (Bedrock) or Vertex publisher region pool (e.g. global, us-central1)
--project <id>                  one-shot GCP project ID for Vertex AI (not persisted)
--effort <level>                reasoning effort for tool-using calls: low | medium | high | max (default: no override). Anthropic maps it to the Claude SDK effort; OpenAI maps it to reasoning_effort, which only its reasoning models accept (a non-reasoning model rejects it with an HTTP 400). No effect on Bedrock, Vertex, or Ollama.
--thinking <mode>               thinking mode: off | adaptive | enabled (default: no override). Anthropic-only; other providers ignore it.
-v, --verbose                   verbose output
```

## License

agentgg is licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) for the full text and [NOTICE](./NOTICE) for attribution.
