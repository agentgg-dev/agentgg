# Contributing

Thanks for considering a contribution to agentgg.

## Repo layout

```
agentgg/
├── packages/
│   ├── core/        Types, Zod schemas, plugin contracts (FileRecord, Agent,
│   │                ScopeConfig, AgentggPlugin, defineConfig)
│   ├── cli/         Commander-based CLI: init, scan, agents, config
│   └── agents/      Built-in markdown agents (curated, ships in npm package)
├── docs/            User and contributor documentation
├── samples/         Example projects + agentgg.config.ts samples
└── product-overview.md   Product vision (read this first)
```

## Dev workflow

```bash
pnpm install
pnpm build           # tsc across all packages
pnpm test            # vitest, all packages
pnpm agentgg ...     # run the CLI from source via tsx
pnpm lint            # biome check
pnpm lint:fix        # biome check --write
```

Requires Node.js 20+ and pnpm 9+.

## Code style

Biome handles lint + format — no ESLint, no Prettier. Run `pnpm lint:fix`
before opening a PR. Configuration lives in `biome.json` at the repo
root; package-level overrides are discouraged.

TypeScript strict mode is on. Prefer Zod schemas as the source of truth
for any shape that crosses a boundary (config files, plugin output,
agent frontmatter) and infer the TS type from the schema.

## Adding agents to the official registry

The built-in agents shipped inside this repo (`packages/agents/`) are
intentionally a small, ruthlessly curated set — the v0.1 launch ships
~10–15. Community contributions to the broader catalog happen in a
**separate repo**:

> `agentgg-agents` (link: TBD — repo not yet created)

That repo is the source of `~/.agentgg/agents/official/` (synced via
`agentgg agents update`). Submit new agents there, not here.

The agent file format spec is in `docs/agent-format.md` (TODO — see
`product-overview.md` §4.1 and §10.4).

## Issues & discussion

- **Bugs**: open a GitHub issue with a minimal repro.
- **Feature requests**: open a discussion first. The product is small
  on purpose; we say no a lot.
- **Security**: do **not** open a public issue. See `SECURITY.md`
  (TODO — write this) for the disclosure process.

## License

Contributions are accepted under the project's license (see `LICENSE`
and the License section in `README.md`). By submitting a pull request
you certify that you have the right to license your contribution to
the project.
