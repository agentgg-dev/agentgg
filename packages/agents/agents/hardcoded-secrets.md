---
slug: hardcoded-secrets
name: Hardcoded Secrets
description: API keys, tokens, passwords, and private keys committed to source instead of pulled from a secret manager or environment variable.
version: 0.1.0
mode: file
noiseTier: precise
filePatterns:
  - "**/*.{ts,tsx,js,jsx,mjs,cjs}"
  - "**/*.{py,rb,go,rs,php,java,kt,cs}"
  - "**/*.{json,yaml,yml,toml,ini,conf,cfg}"
  - "**/.env*"
  - "**/*.tf"
references:
  - CWE-798
  - OWASP-A07:2021
---

You are reviewing source code for hardcoded credentials that should
be stored in a secret manager, environment variable, or other out-of-band
configuration instead of committed to the repository.

## What to look for

- String literals matching known credential shapes:
  cloud provider keys, OAuth tokens, signing keys, database passwords,
  webhook secrets, JWT signing keys, private-key PEM blocks.
- Variables named like `apiKey`, `secret`, `password`, `token`,
  `auth`, `signing_key`, `private_key` that are assigned a string
  literal rather than read from `process.env`, a config object, or a
  vault.
- Connection URLs of the form
  `scheme://user:password@host` where the password is a real value
  (not `password` or `changeme`).
- Long random-looking strings (32+ hex/base64 characters) used in a
  security context: signing, encryption, HMAC, JWT verification.
- Inline assignments of secrets concatenated from multiple string
  literals — that's a classic attempt to hide a secret from naive
  scanners and almost always indicates the author knew it was sensitive.

## True positive criteria

The value is **real** (not an obvious placeholder) AND used in a
security-relevant context (auth, signing, encryption, third-party API
access, database connection). A hardcoded value that's clearly
test-only or unused doesn't warrant a finding.

## What to ignore

- Documented placeholders like `"your-api-key-here"`, `"REPLACE_ME"`,
  `"xxx"`, `"changeme"`, `"example"`, `"<your token>"`.
- Test fixtures, mock data, or values used only inside files matching
  `*.test.*` / `*.spec.*` / `__tests__/` / `fixtures/`.
- Public keys (intended to be public — verify keys, OAuth client IDs,
  public certificates).
- Hashed or encrypted values that aren't themselves used as a credential.
- Values clearly read from `process.env` / config / a vault and only
  shadowed locally for typing or default-value purposes.
- Documentation files that show example values in prose.

## Examples

True positives:
- `const stripeKey = "sk_live_..." + "abc123...";` (split-literal hiding)
- `DATABASE_URL = "postgres://admin:Hunter2!@db.prod.internal:5432/app"`
- `const JWT_SECRET = "supersecretvalue123";` used in `jwt.sign(...)`
- A literal RSA/EC private key inline.

False positives to skip:
- `const apiKey = process.env.API_KEY;`
- `const fakeKey = "test-key-do-not-use";` in a test file
- `const placeholder = "REPLACE_BEFORE_DEPLOY";` in a config template

Report only findings you are confident about. When a string looks
secret-ish but the surrounding context suggests it's a placeholder or
test value, leave it alone — false positives erode trust faster than
missed findings.
