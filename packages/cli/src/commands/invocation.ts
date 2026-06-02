import type { RunMeta } from "@agentgg/core";

/**
 * Build the `RunMeta.invocation` record so a run on disk is
 * self-describing: the subcommand plus the raw args as typed (which
 * already carry the `-t` templates and every flag).
 */
export function buildInvocation(params: {
  command: string;
  argv?: string[];
}): NonNullable<RunMeta["invocation"]> {
  const argv = params.argv ?? process.argv.slice(2);
  return {
    command: params.command,
    argv: argv.join(" "),
  };
}
