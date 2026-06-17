#!/usr/bin/env node
// Copyright 2026 The agentgg Authors. SPDX-License-Identifier: Apache-2.0

import { Command } from "commander";
import { registerAgentsCommand } from "./commands/agents.js";
import { registerConfigCommand } from "./commands/config.js";
import { registerCreateCommand } from "./commands/create.js";
import { registerDedupCommand } from "./commands/dedup.js";
import { registerInitCommand } from "./commands/init.js";
import { registerReconCommand } from "./commands/recon.js";
import { registerRevalidateCommand } from "./commands/revalidate.js";
import { registerScanCommand } from "./commands/scan.js";
import { registerScoreCommand } from "./commands/score.js";
import { registerStatusCommand } from "./commands/status.js";
import { registerSummaryCommand } from "./commands/summary.js";
import { registerViewCommand } from "./commands/view.js";
import { checkAndReportUpdates } from "./update-check.js";
import { VERSION } from "./version.js";

const program = new Command();

program
  .name("agentgg")
  .description("AI-powered SAST CLI with modular, community-installable agents")
  .version(VERSION, "-V, --version", "print the version")
  .helpOption("-h, --help", "show help");

registerInitCommand(program);
registerReconCommand(program);
registerScanCommand(program);
registerCreateCommand(program);
registerStatusCommand(program);
registerRevalidateCommand(program);
registerScoreCommand(program);
registerDedupCommand(program);
registerSummaryCommand(program);
registerViewCommand(program);
registerAgentsCommand(program);
registerConfigCommand(program);

checkAndReportUpdates(process.argv);

program.parseAsync(process.argv).catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
