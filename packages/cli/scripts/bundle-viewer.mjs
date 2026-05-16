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
 * Run via `npm run build:bundle` or transitively via `prepublishOnly`.
 */

import { execSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, rmSync } from "node:fs";
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
// `npx --no-install` so we only pick up the hoisted Next.js install.
// Failing loud here beats silently pulling a random version off the
// npm registry.
execSync("npx --no-install next build", {
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
cpSync(standaloneSrc, bundleDest, { recursive: true });

// Next.js standalone deliberately omits .next/static — they're meant
// to be served from a CDN in production. Since we're shipping a
// self-contained local server, copy them in alongside the server build.
const staticDest = resolve(
  bundleDest,
  "packages",
  "viewer",
  ".next",
  "static",
);
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

log(`Done. Entry: ${entry}`);
