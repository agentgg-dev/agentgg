#!/usr/bin/env node
// Copyright 2026 The agentgg Authors. SPDX-License-Identifier: Apache-2.0
//
// Copies README.md, LICENSE, and NOTICE from the monorepo root into
// packages/cli/ so they ship inside the published tarball. The CLI is
// the only published package; users browsing npmjs.com/package/agentgg
// see the same README and license terms as visitors to the GitHub repo.
//
// Runs as part of `pnpm publish` / `pnpm pack` via the `prepack` script.

import { copyFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_PKG = resolve(HERE, "..");
const REPO_ROOT = resolve(CLI_PKG, "..", "..");

const FILES = ["README.md", "LICENSE", "NOTICE"];

for (const f of FILES) {
  const src = resolve(REPO_ROOT, f);
  const dest = resolve(CLI_PKG, f);
  copyFileSync(src, dest);
  console.log(`[copy-root-docs] ${f} -> packages/cli/`);
}
