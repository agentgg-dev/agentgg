// Cloud Run sidecar model, reproduced locally: the sandbox container joins a
// "main" container's network namespace (--network=container:<id>) instead of
// getting its own. Proves control-server auth and routing survive that.
// Docker-gated: run with `pnpm test:integration` (or filtered, see
// live-validation.integration.test.ts for the general instructions).
import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { DEFAULT_SANDBOX_IMAGE, dockerAvailable } from "../src/validation/sandbox.js";

// Best effort: a container may already be gone (--rm), and one failed removal
// must never skip the other.
function forceRemove(id: string): void {
  try {
    execFileSync("docker", ["rm", "-f", id]);
  } catch {}
}

describe("attached sandbox (sidecar model)", () => {
  it("serves MCP and control on the shared localhost", async () => {
    if (!(await dockerAvailable())) return;
    // `docker run` auto-pulls this if it's not already cached locally.
    const main = execFileSync("docker", ["run", "-d", "--rm", "node:22-slim", "sleep", "300"])
      .toString()
      .trim();
    let sandbox = "";
    try {
      sandbox = execFileSync("docker", [
        "run",
        "-d",
        "--rm",
        `--network=container:${main}`,
        "-e",
        "SANDBOX_CONTROL_TOKEN=tk",
        "-e",
        "ALLOWED_ORIGINS=http://example.com",
        DEFAULT_SANDBOX_IMAGE,
      ])
        .toString()
        .trim();
      const probe = `
        const h={Authorization:'Bearer tk'};
        const wait=async()=>{for(let i=0;i<60;i++){try{await fetch('http://127.0.0.1:8932/logs',{headers:h});return}catch{await new Promise(r=>setTimeout(r,500))}}throw new Error('no control')};
        await wait();
        const r=await fetch('http://127.0.0.1:8932/exec',{method:'POST',headers:{...h,'Content-Type':'application/json'},body:JSON.stringify({cmd:['ls','/srv']})});
        const j=await r.json(); if(!j.stdout.includes('sandbox-control.mjs')) throw new Error(JSON.stringify(j));
        const bad=await fetch('http://127.0.0.1:8932/logs'); if(bad.status!==401) throw new Error('no auth');
        console.log('ok');`;
      const out = execFileSync("docker", [
        "exec",
        main,
        "node",
        "--input-type=module",
        "-e",
        probe,
      ]).toString();
      expect(out.trim()).toBe("ok");
    } finally {
      if (sandbox) forceRemove(sandbox);
      forceRemove(main);
    }
  }, 120_000);
});
