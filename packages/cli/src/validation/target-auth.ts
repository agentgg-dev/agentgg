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

/** Every encoding the password can survive in: raw, percent-encoded,
 *  form-encoded (space as `+`), JSON-escaped, and basic-auth base64. Longest
 *  first, so a shorter variant that is a substring of a longer one never
 *  leaves a partial match behind. */
export function credentialVariants(auth: TargetAuth): string[] {
  const pw = auth.password;
  if (!pw) return [];
  const set = new Set<string>([
    pw,
    encodeURIComponent(pw),
    new URLSearchParams({ x: pw }).toString().slice(2),
    JSON.stringify(pw).slice(1, -1),
  ]);
  if (auth.username !== undefined) {
    set.add(Buffer.from(`${auth.username}:${pw}`).toString("base64"));
  }
  return [...set].filter((s) => s.length > 0).sort((a, b) => b.length - a.length);
}

export function redact(text: string, auth: TargetAuth): string {
  let out = text;
  for (const s of credentialVariants(auth)) out = out.split(s).join("***");
  return out;
}

/** Byte-level redaction for evidence files (trace.zip entries) that may not be
 *  valid UTF-8. `latin1` maps bytes 1:1, so binary content (video, images)
 *  round-trips unchanged when no variant matches. */
export function redactBytes(buf: Buffer, auth: TargetAuth): Buffer {
  const variants = credentialVariants(auth);
  if (variants.length === 0) return buf;
  const text = buf.toString("latin1");
  let out = text;
  for (const s of variants) out = out.split(Buffer.from(s, "utf8").toString("latin1")).join("***");
  return out === text ? buf : Buffer.from(out, "latin1");
}

export function readTargetContext(raw: string | undefined): string | undefined {
  if (raw === undefined || !raw.startsWith("@")) return raw;
  const path = raw.slice(1);
  try {
    return readFileSync(path, "utf8");
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(`could not read --target-context file ${path}: ${reason}`);
  }
}
