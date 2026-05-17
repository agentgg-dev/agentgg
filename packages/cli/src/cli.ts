#!/usr/bin/env node
/*
 * agentgg — AI-powered SAST CLI with modular agents
 * Copyright (C) 2026  [LICENSOR_PLACEHOLDER]
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

import { Command } from "commander";
import { registerAgentsCommand } from "./commands/agents.js";
import { registerConfigCommand } from "./commands/config.js";
import { registerInitCommand } from "./commands/init.js";
import { registerRevalidateCommand } from "./commands/revalidate.js";
import { registerScanCommand } from "./commands/scan.js";
import { registerScoreCommand } from "./commands/score.js";
import { registerStatusCommand } from "./commands/status.js";
import { registerViewCommand } from "./commands/view.js";
import { VERSION } from "./version.js";

const program = new Command();

program
  .name("agentgg")
  .description("AI-powered SAST CLI with modular, community-installable agents")
  .version(VERSION, "-V, --version", "print the version")
  .helpOption("-h, --help", "show help");

registerInitCommand(program);
registerScanCommand(program);
registerStatusCommand(program);
registerRevalidateCommand(program);
registerScoreCommand(program);
registerViewCommand(program);
registerAgentsCommand(program);
registerConfigCommand(program);

program.parseAsync(process.argv).catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
