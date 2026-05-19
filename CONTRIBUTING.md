# Contributing

Thanks for considering a contribution to agentgg.

## Repo layout

```
agentgg/
└── packages/
    ├── core/        Types, Zod schemas (FileRecord, Agent, ScopeConfig)
    ├── cli/         Commander-based CLI: init, scan, agents, config, view
    └── viewer/      Next.js viewer bundled into the CLI dist
```

## Dev workflow

Requires Node.js 20+ and pnpm 9+.

### First-time setup

```bash
git clone https://github.com/agentgg-dev/agentgg.git
cd agentgg
pnpm install
```

That's the entire setup. No build step is required — the dev runner uses
`tsx` against TypeScript source.

### Run the CLI while you iterate

```bash
pnpm agentgg <command>            # e.g. pnpm agentgg scan ./some-repo
```

`pnpm agentgg` is wired up in [`package.json`](./package.json) as
`tsx packages/cli/src/cli.ts`. Edit source, re-run — no rebuild step.
This is the loop most contributors will live in.

### Working on the viewer

The viewer is a Next.js app in `packages/viewer/`. When you run
`pnpm agentgg view <results-dir>` from a source checkout, the CLI
spawns the viewer in two modes depending on what's on disk:

- **Source dev mode** (the default in a fresh clone): runs `next dev`
  against `packages/viewer/`. First page load takes a few seconds
  (Next compiles on demand), but viewer source edits hot-reload.
- **Source prod mode**: runs `next start` if `packages/viewer/.next/`
  has a build (e.g. you ran `pnpm --filter @agentgg/viewer build`).

So the everyday viewer workflow is:

```bash
pnpm agentgg view ./scan-results       # boots `next dev`, hot-reloads on edits
```

Force dev mode regardless of whether a build exists:

```bash
pnpm agentgg view ./scan-results --dev
```

`Ctrl+C` stops the viewer. The default port is 3737, walking forward
to the next free one if taken.

### Run tests and lint before opening a PR

```bash
pnpm lint           # biome check
pnpm lint:fix       # auto-fix what biome can
pnpm test           # vitest across all packages
pnpm build          # tsc --build across the workspace (type-check + emit per-file dist)
```

`pnpm build` is required for `pnpm test` to pass — vitest imports
`@agentgg/core` through the package's `main: ./dist/index.js` entry,
so the core's dist must exist. CI runs the same `lint → build → test`
sequence on PRs.

### Make `agentgg` globally available against your local checkout (optional)

If you'd rather type `agentgg ...` than `pnpm agentgg ...`, link the
package globally:

```bash
pnpm --filter agentgg build       # build the bundled dist/cli.js first
pnpm --filter agentgg link --global
agentgg --version                 # resolves to packages/cli/dist/cli.js
```

Re-run `pnpm --filter agentgg build` after every source change. To undo:
`pnpm --filter agentgg unlink --global`.

### Reproduce the npm tarball locally (rare)

You normally don't need this — CI builds the tarball on tag push. But
if you're debugging the publish flow, this is the exact pipeline:

```bash
pnpm --filter agentgg build:bundle          # esbuild + Next.js standalone
cd packages/cli
npm pack                                    # produces agentgg-X.Y.Z.tgz
npm install -g ./agentgg-X.Y.Z.tgz          # simulates `npm install -g agentgg`
```

`build:bundle` runs `scripts/bundle-cli.mjs` (inlines `@agentgg/core`
via esbuild) then `scripts/bundle-viewer.mjs` (Next.js standalone build
copied into `dist/viewer/`). The `prepack` hook on the `agentgg` package
fires the same command automatically during `npm pack` / `npm publish`.

## Code style

Biome handles lint + format. Run `pnpm lint:fix`
before opening a PR.

TypeScript strict mode is on. Prefer Zod schemas as the source of truth
for any shape that crosses a boundary (config files, agent frontmatter)
and infer the TS type from the schema.

## Adding agents

Agents live in a **separate repo**: [agentgg-dev/agentgg-agents](https://github.com/agentgg-dev/agentgg-agents).
That repo is the source of `~/.agentgg/agentgg-agents/` (synced on
first scan and via `agentgg agents update`). Submit new agents there,
not here.

## Issues & discussion

- **Bugs**: open a GitHub issue with a minimal repro.
- **Feature requests**: open a discussion first.
- **Security**: do **not** open a public issue. See `SECURITY.md` for
  the disclosure process.

## License

Contributions are accepted under the project's license (see `LICENSE`
and the License section in `README.md`). By submitting a pull request
you certify that you have the right to license your contribution to
the project.
