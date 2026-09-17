import { readFileSync } from "node:fs";
export type TargetAuth = { username?: string; password?: string };

export function parseTargetAuth(opts: { targetCredentials?: string }): TargetAuth {
  const auth: TargetAuth = {};
  const cred = opts.targetCredentials;
  if (cred?.startsWith("@")) {
    const path = cred.slice(1);
    let j: { username?: string; password?: string };
    try {
      j = JSON.parse(readFileSync(path, "utf8"));
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      throw new Error(`could not read --target-credentials file ${path}: ${reason}`);
    }
    auth.username = j.username;
    auth.password = j.password;
  } else if (cred) {
    const i = cred.indexOf(":");
    auth.username = i >= 0 ? cred.slice(0, i) : cred;
    auth.password = i >= 0 ? cred.slice(i + 1) : undefined;
  }
  return auth;
}

export function redact(text: string, auth: TargetAuth): string {
  const secrets = [auth.password].filter(Boolean) as string[];
  secrets.sort((a, b) => b.length - a.length);
  let out = text;
  for (const s of secrets) out = out.split(s).join("***");
  return out;
}
