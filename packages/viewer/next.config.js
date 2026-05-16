const path = require('node:path');

/** @type {import('next').NextConfig} */
// API routes need a real server — no static export here. Landing-page
// stays on `output: 'export'` for its CDN deploy; this app is meant
// to boot on localhost from the CLI.
const nextConfig = {
  reactStrictMode: true,
  // Emit a self-contained server at `.next/standalone/` with only the
  // node_modules the runtime actually touches. The CLI's bundle script
  // copies this into `packages/cli/dist/viewer/` at publish time so
  // npm-install users get the viewer without any extra dep on `next`.
  output: 'standalone',
  // Tracing root has to be the monorepo root, not packages/viewer/,
  // otherwise the standalone bundle won't include the workspace deps
  // (@agentgg/core, etc.) it imports.
  outputFileTracingRoot: path.join(__dirname, '..', '..'),
};

module.exports = nextConfig;
