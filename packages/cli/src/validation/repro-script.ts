import type { Sandbox } from "./sandbox.js";

export async function runReproScript(sandbox: Sandbox, script: string) {
  const path = "/srv/repro.spec.ts";
  await sandbox.writeFile(path, script);
  const { code } = await sandbox.exec(["npx", "playwright", "test", path, "--reporter=line"], {
    timeoutMs: 120_000,
  });
  return { path: "repro.spec.ts", executed: true, passed: code === 0 };
}
