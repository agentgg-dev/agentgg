import type { RunMeta } from "@agentgg/core";

/** Flags whose value is a credential. */
const SECRET_FLAGS = new Set(["--api-key", "--oauth-token"]);

/**
 * Drop the value of every credential flag. Unlike `agentgg config`, which
 * shows a prefix so you can tell two saved keys apart, this record ends up
 * in the output dir that users upload as a CI artifact, so it keeps nothing.
 */
function maskSecrets(argv: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const eq = arg.indexOf("=");
    if (eq > 0 && SECRET_FLAGS.has(arg.slice(0, eq))) {
      out.push(`${arg.slice(0, eq)}=***`);
      continue;
    }
    out.push(arg);
    if (SECRET_FLAGS.has(arg) && i + 1 < argv.length) {
      out.push("***");
      i++;
    }
  }
  return out;
}

/**
 * Build the `RunMeta.invocation` record so a run on disk is
 * self-describing: the subcommand plus the raw args as typed (which
 * already carry the `-t` templates and every flag), with credential
 * values masked.
 */
export function buildInvocation(params: {
  command: string;
  argv?: string[];
}): NonNullable<RunMeta["invocation"]> {
  const argv = params.argv ?? process.argv.slice(2);
  return {
    command: params.command,
    argv: maskSecrets(argv).join(" "),
  };
}
