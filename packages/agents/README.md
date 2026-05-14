# @agentgg/agents

Built-in agent set shipped with agentgg.

> ⚠️ Empty for now. The v0.1 launch will ship ~10–15 high-signal agents
> here — see `product-overview.md` §7 for the planned list. The agent
> file format spec is the blocking dependency; see `docs/agent-format.md`
> (TODO) once written.

## Layout (planned)

```
packages/agents/
├── manifest.json            # pack metadata (name, version, agent list)
├── secrets-hardcoded.md
├── sql-injection.md
├── command-injection.md
├── ssrf.md
├── insecure-deserialization.md
├── path-traversal.md
├── weak-crypto.md
├── missing-authn-authz.md
├── xss-templating.md
├── idor.md
├── open-redirect.md
└── sensitive-data-in-logs.md
```

## Conventions

- One agent per file. Filename = slug + `.md`.
- YAML frontmatter validated against the `Agent` schema in
  `@agentgg/core`.
- Body is the prompt template.
