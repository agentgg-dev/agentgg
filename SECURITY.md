# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/agentgg-dev/agentgg/security) of this repo
2. Click **Report a vulnerability**
3. Fill in the form. We receive it privately.

If GitHub's reporting form is unavailable, email **Contact@agentgg.dev** instead.

## Scope

This repo contains the `agentgg` CLI, a Node.js tool that orchestrates LLM scans over user code. Several distinct kinds of security issues exist; only some are issues in this repo.

**In scope, please report:**

- Code execution or arbitrary-file-write issues in the CLI (e.g. path traversal in `--output`, command injection in `--diff` parsing, prototype pollution in config loading).
- Credential mishandling such as secrets logged to disk in plaintext, leaked in error messages, or sent to the wrong provider.
- Tool sandbox escapes. Hunt and walker modes give the model `Read` / `Glob` / `Grep` tools scoped to the scanned root; any way to break out and access files outside that root is a vulnerability.
- Supply chain integrity, including tampering with npm releases, GitHub tags, or release workflows.

**Out of scope, not security issues here:**

- An agent missing a vulnerability it should have caught, or producing false positives. That is an agent quality bug. Report to [agentgg-agents](https://github.com/agentgg-dev/agentgg-agents/issues).
- A weaponized agent prompt that tries to manipulate the model. That belongs to [agentgg-agents](https://github.com/agentgg-dev/agentgg-agents/security).
- Vulnerabilities in code being scanned **by** agentgg. That is the user's own codebase; report to that project.

## Response timeline

- **Acknowledgement** within 3 business days.
- **Initial assessment** within 7 business days.
- **Fix or mitigation** target depends on severity; we aim for 30 days for high-severity issues.
- **Public disclosure** coordinated with you once a fix is published.

## Disclosure

We support coordinated disclosure. We credit you in release notes and the GitHub Security Advisory unless you prefer to remain anonymous.
