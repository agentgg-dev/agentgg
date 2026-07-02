#!/usr/bin/env node
/*
 * bundle-cli.mjs
 *
 * Bundles src/cli.ts (and the entire CLI source tree it imports) into a
 * single dist/cli.js. @agentgg/core is inlined into the bundle — it's a
 * `private` workspace package, never published to npm, so the published
 * agentgg tarball can't depend on it externally. Every other runtime
 * dependency (commander, ai, zod, @ai-sdk/*, @anthropic-ai/*, etc.)
 * stays external and is resolved at install time from the user's
 * node_modules via npm's normal dependency tree.
 *
 * Run via `pnpm build:bundle` (which also bundles the viewer). Fires
 * automatically during `pnpm pack` / `pnpm publish` via the `prepack`
 * hook in cli/package.json.
 */

import { chmodSync, cpSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliRoot = resolve(__dirname, "..");
const entry = resolve(cliRoot, "src", "cli.ts");
const outfile = resolve(cliRoot, "dist", "cli.js");

const pkg = JSON.parse(readFileSync(resolve(cliRoot, "package.json"), "utf8"));

// Everything in `dependencies` and `peerDependencies` stays external —
// npm will install them next to the CLI. Built-in `node:*` modules are
// always external. @agentgg/core is deliberately NOT in this list so
// esbuild inlines it.
const external = [
  ...Object.keys(pkg.dependencies ?? {}),
  ...Object.keys(pkg.peerDependencies ?? {}),
];

function log(msg) {
  console.log(`[bundle-cli] ${msg}`);
}

log(`Bundling ${entry} → ${outfile}`);
log(`External: ${external.join(", ") || "(none)"}`);

await build({
  entryPoints: [entry],
  outfile,
  bundle: true,
  platform: "node",
  target: "node20",
  format: "esm",
  // The shebang in src/cli.ts is preserved by esbuild automatically;
  // adding it as a banner would produce a duplicate and a syntax error.
  // Some externals are CommonJS; esbuild emits `import` for them by
  // default, which Node handles via interop. No banner shim required.
  external,
  sourcemap: true,
  // Keep stack traces and error messages legible — this is a dev tool,
  // not a browser bundle. Bytes don't matter.
  minify: false,
  legalComments: "inline",
  logLevel: "info",
});

// Built-in agent files (recon.md, etc.) are read at runtime relative to
// the bundle via import.meta.url, so they must be copied next to it.
// esbuild only bundles JS — these markdown assets need an explicit copy.
const agentsSrc = resolve(cliRoot, "src", "agents");
const agentsDest = resolve(cliRoot, "dist", "agents");
try {
  cpSync(agentsSrc, agentsDest, { recursive: true });
  log(`Copied built-in agents → ${agentsDest}`);
} catch (err) {
  log(`WARNING: failed to copy built-in agents: ${err.message}`);
}

// The bundled default scope doc (src/scope/default-scope.md) is read at
// runtime relative to the bundle via import.meta.url — same explicit-copy
// requirement as the agent markdown above.
const scopeSrc = resolve(cliRoot, "src", "scope");
const scopeDest = resolve(cliRoot, "dist", "scope");
try {
  cpSync(scopeSrc, scopeDest, { recursive: true });
  log(`Copied default scope → ${scopeDest}`);
} catch (err) {
  log(`WARNING: failed to copy default scope: ${err.message}`);
}

// chmod +x is a no-op on Windows but matters on macOS/Linux installs.
try {
  chmodSync(outfile, 0o755);
} catch {
  // best-effort
}

log("Done.");
