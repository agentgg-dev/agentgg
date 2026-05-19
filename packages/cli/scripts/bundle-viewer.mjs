#!/usr/bin/env node
/*
 * bundle-viewer.mjs
 *
 * Builds the @agentgg/viewer Next.js app in standalone mode and copies
 * the resulting self-contained server into `packages/cli/dist/viewer/`.
 * That directory ships inside the `agentgg` npm tarball (via the
 * `files: ["dist", ...]` field in package.json), so an npm-install user
 * gets the viewer without ever installing Next.js, React, or this
 * workspace into their own dep tree.
 *
 * Layout produced (mirrors Next.js standalone convention):
 *
 *   packages/cli/dist/viewer/
 *     packages/viewer/
 *       server.js              <- entry. node-spawnable. reads PORT + HOSTNAME.
 *       .next/                 <- server build chunks
 *         static/              <- static assets (copied in by this script)
 *       package.json
 *       node_modules/          <- workspace symlinks, replaced with real files
 *     node_modules/            <- traced production deps (next, react, ...)
 *     package.json             <- root package.json snapshot
 *
 * Run via `pnpm build:bundle` (or from the root: `pnpm --filter agentgg
 * build:bundle`). Also fires automatically during `pnpm publish` via the
 * `prepublishOnly` script in cli/package.json.
 */

import { execSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliRoot = resolve(__dirname, "..");
const monorepoRoot = resolve(cliRoot, "..", "..");
const viewerRoot = resolve(monorepoRoot, "packages", "viewer");
const bundleDest = resolve(cliRoot, "dist", "viewer");

function log(msg) {
  console.log(`[bundle-viewer] ${msg}`);
}

if (!existsSync(viewerRoot)) {
  console.error(
    `[bundle-viewer] viewer package not found at ${viewerRoot}. ` +
      `Are you running this outside the agentgg monorepo?`,
  );
  process.exit(1);
}

log(`Building viewer at ${viewerRoot}…`);
// `pnpm exec` only resolves binaries from the local workspace install.
// Failing loud here beats silently pulling a random version off the
// npm registry.
//
// `--webpack` because Next.js 16's Turbopack standalone tracer is buggy:
// it ships @swc/helpers/package.json without the actual cjs/esm files,
// so the bundled server crashes at startup with MODULE_NOT_FOUND for
// @swc/helpers/cjs/_interop_require_default.cjs. The webpack build
// traces deps correctly. Revisit when Turbopack standalone stabilizes.
execSync("pnpm exec next build --webpack", {
  cwd: viewerRoot,
  stdio: "inherit",
  env: { ...process.env, NEXT_TELEMETRY_DISABLED: "1" },
});

const standaloneSrc = resolve(viewerRoot, ".next", "standalone");
const staticSrc = resolve(viewerRoot, ".next", "static");

if (!existsSync(standaloneSrc)) {
  console.error(
    `[bundle-viewer] expected standalone output at ${standaloneSrc} after build, but it doesn't exist. ` +
      `Check that next.config.js has \`output: 'standalone'\`.`,
  );
  process.exit(1);
}

log(`Wiping previous bundle at ${bundleDest}…`);
if (existsSync(bundleDest)) rmSync(bundleDest, { recursive: true, force: true });
mkdirSync(bundleDest, { recursive: true });

log(`Copying standalone server (${standaloneSrc} → ${bundleDest})…`);
// `dereference: true` is critical here. Next.js standalone in pnpm
// workspaces leaves junctions at node_modules/<pkg> and inside .pnpm
// that point at the build machine's pnpm store. Without dereferencing,
// those junctions get copied as-is and break on the consumer machine
// when the tarball is extracted to a different absolute path.
cpSync(standaloneSrc, bundleDest, { recursive: true, dereference: true });

// Next.js standalone deliberately omits .next/static — they're meant
// to be served from a CDN in production. Since we're shipping a
// self-contained local server, copy them in alongside the server build.
const staticDest = resolve(bundleDest, "packages", "viewer", ".next", "static");
if (existsSync(staticSrc)) {
  log(`Copying static assets (${staticSrc} → ${staticDest})…`);
  cpSync(staticSrc, staticDest, { recursive: true });
} else {
  log("No .next/static to copy (no client-side assets in this build).");
}

// `public/` is optional for the viewer today but copy it if it ever
// gains content (favicons, og images, etc.).
const publicSrc = resolve(viewerRoot, "public");
const publicDest = resolve(bundleDest, "packages", "viewer", "public");
if (existsSync(publicSrc)) {
  log(`Copying public assets (${publicSrc} → ${publicDest})…`);
  cpSync(publicSrc, publicDest, { recursive: true });
}

const entry = resolve(bundleDest, "packages", "viewer", "server.js");
if (!existsSync(entry)) {
  console.error(
    `[bundle-viewer] expected entry at ${entry} after copy, but it doesn't exist. ` +
      `Next.js may have changed its standalone layout.`,
  );
  process.exit(1);
}

// Next.js's standalone tracer in pnpm workspaces emits a content-addressed
// node_modules/.pnpm/<pkg>@<ver>/node_modules/<pkg>/ layout, plus a few
// junctions at node_modules/<pkg> pointing back into the SOURCE pnpm
// store on the build machine. When that bundle gets copied (here) and
// then extracted into an npm global install on another machine, those
// junctions point at paths that don't exist, and Node's CJS resolver
// can't find any of next's transitive deps (@next/env, @swc/helpers,
// styled-jsx, react, react-dom, postcss, …) because they only live
// under .pnpm/ — a directory the standard resolver doesn't traverse.
//
// Flatten the bundle: for every <pkg> sitting at
// node_modules/.pnpm/<pkg>@<ver>/node_modules/<pkg>/, ensure a real
// copy also lives at node_modules/<pkg>/ (both at the outer level and
// inside packages/viewer/node_modules/). Use cpSync with
// `dereference: true` so any remaining junctions resolve to real files.
//
// This is workaround code. Revisit when Next.js standalone produces
// a self-contained tree under pnpm without leaning on symlinks.
function flattenPnpmStore(outerNodeModules, hoistTargets) {
  const store = resolve(outerNodeModules, ".pnpm");
  if (!existsSync(store)) return;
  const entries = readdirSync(store, { withFileTypes: true });
  let copied = 0;
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    // pnpm stores look like `<pkg>@<ver>` for unscoped, `<scope>+<name>@<ver>`
    // for scoped (the `/` in the package name is encoded as `+`).
    const pkgRoot = resolve(store, entry.name, "node_modules");
    if (!existsSync(pkgRoot)) continue;
    const scopes = readdirSync(pkgRoot, { withFileTypes: true });
    for (const item of scopes) {
      if (!item.isDirectory()) continue;
      // Scoped packages: `@scope/<name>` — descend one more level.
      if (item.name.startsWith("@")) {
        const scopeDir = resolve(pkgRoot, item.name);
        for (const named of readdirSync(scopeDir, { withFileTypes: true })) {
          if (!named.isDirectory()) continue;
          const src = resolve(scopeDir, named.name);
          const rel = `${item.name}/${named.name}`;
          for (const target of hoistTargets) {
            const dst = resolve(target, rel);
            if (existsSync(dst)) continue;
            mkdirSync(dirname(dst), { recursive: true });
            cpSync(src, dst, { recursive: true, dereference: true });
            copied++;
          }
        }
        continue;
      }
      const src = resolve(pkgRoot, item.name);
      for (const target of hoistTargets) {
        const dst = resolve(target, item.name);
        if (existsSync(dst)) continue;
        mkdirSync(dirname(dst), { recursive: true });
        cpSync(src, dst, { recursive: true, dereference: true });
        copied++;
      }
    }
  }
  log(`Flattened ${copied} package copy(ies) out of .pnpm/ into hoisted node_modules.`);
}

const outerNm = resolve(bundleDest, "node_modules");
const innerNm = resolve(bundleDest, "packages", "viewer", "node_modules");
flattenPnpmStore(outerNm, [outerNm, innerNm]);

log(`Done. Entry: ${entry}`);
