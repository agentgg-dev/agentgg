// Gets Docker running before live validation starts: offers to install it when
// missing and to start it when stopped. Runs at command start, while the user is
// still at the terminal, and only prompts in an interactive terminal. Never
// throws: every failure comes back as a reason the caller prints.
import { execFile, spawn } from "node:child_process";
import { createWriteStream, existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { homedir, tmpdir, userInfo } from "node:os";
import { delimiter, join } from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { ReadableStream as WebReadableStream } from "node:stream/web";
import { promisify } from "node:util";
import { confirm } from "@inquirer/prompts";

const pexec = promisify(execFile);

export type DockerState = "running" | "stopped" | "missing" | "no-access";

export type DockerSetupResult = { ok: true } | { ok: false; reason: string };

export interface DockerSetupDeps {
  platform: NodeJS.Platform;
  interactive: boolean;
  canInstall: boolean;
  username: string;
  state(): Promise<DockerState>;
  confirm(message: string, defaultYes: boolean): Promise<boolean>;
  install(): Promise<void>;
  start(): Promise<void>;
  sleep(ms: number): Promise<void>;
  log(line: string): void;
}

const GET_DOCKER = "https://docs.docker.com/get-started/get-docker/";
const INSTALL_YOURSELF = `Install Docker (${GET_DOCKER}), then run the command again.`;
const NOT_INSTALLED = `Docker is not installed. ${INSTALL_YOURSELF}`;
const NOT_RUNNING =
  "Docker is installed but not running. Start Docker, then run the command again.";
// Docker Desktop's first start can include WSL or VM setup, so allow minutes.
const START_TIMEOUT_MS = 180_000;
const POLL_MS = 2_000;

export async function setUpDocker(
  deps: DockerSetupDeps = realDockerDeps(),
): Promise<DockerSetupResult> {
  let state = await deps.state();
  if (state === "running") return { ok: true };

  let installed = false;
  if (state === "missing") {
    if (!deps.canInstall) return fail(NOT_INSTALLED);
    if (!deps.interactive) {
      return fail(
        `Docker is not installed. ${INSTALL_YOURSELF} In an interactive terminal, agentgg offers to install it for you.`,
      );
    }
    const desktop = deps.platform !== "linux";
    deps.log("Live validation needs Docker, and Docker is not installed.");
    for (const line of desktop ? DESKTOP_NOTICE : ENGINE_NOTICE) deps.log(line);
    const question = desktop ? "Install Docker Desktop now?" : "Install Docker Engine now?";
    if (!(await deps.confirm(question, false))) return fail(NOT_INSTALLED);
    try {
      await deps.install();
    } catch (err) {
      return fail(`The Docker install failed: ${errorText(err)}. ${INSTALL_YOURSELF}`);
    }
    installed = true;
    state = await deps.state();
    if (state === "missing") {
      return fail(
        "Docker is installed, but agentgg cannot find the docker command yet. Open a new terminal, then run the command again.",
      );
    }
  }

  if (state === "no-access") return fail(noAccessReason(deps, installed));
  if (state === "running") return { ok: true };

  // A fresh install was already agreed to, so its start is not asked again.
  if (!installed) {
    if (!deps.interactive) return fail(NOT_RUNNING);
    if (!(await deps.confirm("Docker is installed but not running. Start it now?", true))) {
      return fail(NOT_RUNNING);
    }
  }
  try {
    await deps.start();
  } catch (err) {
    return fail(
      `Could not start Docker: ${errorText(err)}. Start Docker, then run the command again.`,
    );
  }
  deps.log("Waiting for Docker to start...");
  for (let waited = 0; waited < START_TIMEOUT_MS; waited += POLL_MS) {
    await deps.sleep(POLL_MS);
    state = await deps.state();
    if (state === "running") {
      deps.log("Docker is running.");
      return { ok: true };
    }
    if (state === "no-access") return fail(noAccessReason(deps, installed));
  }
  let reason =
    "Docker did not start within 3 minutes. Open Docker, wait until it runs, then run the command again.";
  if (installed && deps.platform === "win32") {
    reason += " If Docker Desktop or Windows asks for a restart or a WSL update, do that first.";
  }
  return fail(reason);
}

const DESKTOP_NOTICE = [
  "agentgg can install Docker Desktop for you. The install asks for administrator rights.",
  "Docker Desktop is free for personal use and small businesses. Larger companies need a paid subscription: https://www.docker.com/pricing/",
  "If you continue, you accept the Docker Subscription Service Agreement: https://www.docker.com/legal/docker-subscription-service-agreement/",
];

const ENGINE_NOTICE = [
  "agentgg can install Docker Engine with Docker's install script (https://get.docker.com).",
  "The install runs with sudo and adds your user to the docker group.",
];

function noAccessReason(deps: DockerSetupDeps, installed: boolean): string {
  if (deps.platform === "linux") {
    if (installed) {
      return "Docker is installed and running, and your user is now in the docker group. This takes effect after you log out and log in again. Then run the command again.";
    }
    return "Your user does not have permission to use Docker. Run `sudo usermod -aG docker $USER`, log out and log in again, then run the command again.";
  }
  if (deps.platform === "win32") {
    return `Your Windows user does not have permission to use Docker. In an administrator terminal, run \`net localgroup docker-users ${deps.username} /add\`. Then sign out, sign in again, and run the command again.`;
  }
  return "Your user does not have permission to use Docker. Check the Docker setup, then run the command again.";
}

function fail(reason: string): DockerSetupResult {
  return { ok: false, reason };
}

function errorText(err: unknown): string {
  return (err instanceof Error ? err.message : String(err)).replace(/\.$/, "");
}

/** Docker's official installer for this OS and CPU, or null when Docker publishes none. */
export function dockerDownloadUrl(platform: NodeJS.Platform, arch: string): string | null {
  if (platform === "linux") return "https://get.docker.com";
  const cpu = arch === "x64" ? "amd64" : arch === "arm64" ? "arm64" : null;
  if (!cpu) return null;
  if (platform === "win32") {
    return `https://desktop.docker.com/win/main/${cpu}/Docker%20Desktop%20Installer.exe`;
  }
  if (platform === "darwin") return `https://desktop.docker.com/mac/main/${cpu}/Docker.dmg`;
  return null;
}

export function realDockerDeps(): DockerSetupDeps {
  return {
    platform: process.platform,
    interactive: Boolean(process.stdin.isTTY && process.stdout.isTTY) && !process.env.CI,
    canInstall: dockerDownloadUrl(process.platform, process.arch) !== null,
    username: currentUser(),
    state: dockerState,
    confirm: (message, defaultYes) => confirm({ message, default: defaultYes }),
    install: installDocker,
    start: startDocker,
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    log: (line) => console.log(line),
  };
}

async function dockerState(): Promise<DockerState> {
  addDockerToPath();
  try {
    await pexec("docker", ["--version"], { timeout: 15_000 });
  } catch {
    return "missing";
  }
  try {
    await pexec("docker", ["version", "--format", "{{.Server.Version}}"], { timeout: 20_000 });
    return "running";
  } catch (err) {
    const text = `${(err as { stderr?: string }).stderr ?? ""} ${errorText(err)}`;
    return /permission denied|access is denied/i.test(text) ? "no-access" : "stopped";
  }
}

// A Docker installed after this terminal opened is not on its PATH yet. Appended,
// so a docker the user put on PATH still wins.
function addDockerToPath(): void {
  const dirs =
    process.platform === "win32"
      ? [join(programFiles(), "Docker", "Docker", "resources", "bin")]
      : process.platform === "darwin"
        ? ["/Applications/Docker.app/Contents/Resources/bin", join(homedir(), ".docker", "bin")]
        : [];
  const parts = (process.env.PATH ?? "").split(delimiter);
  const add = dirs.filter((d) => existsSync(d) && !parts.includes(d));
  if (add.length > 0) process.env.PATH = [...parts, ...add].join(delimiter);
}

async function installDocker(): Promise<void> {
  const url = dockerDownloadUrl(process.platform, process.arch);
  if (!url) throw new Error("Docker has no installer for this system");
  const dir = mkdtempSync(join(tmpdir(), "agentgg-docker-"));
  try {
    if (process.platform === "win32") await installWindows(url, dir);
    else if (process.platform === "darwin") await installMac(url, dir);
    else await installLinux(url, dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function installWindows(url: string, dir: string): Promise<void> {
  const exe = join(dir, "Docker Desktop Installer.exe");
  await download(url, exe, "Docker Desktop");
  const { stdout } = await powershell(
    `$s = Get-AuthenticodeSignature -LiteralPath ${psQuote(exe)}; "$($s.Status)|$($s.SignerCertificate.Subject)"`,
  );
  if (!/^Valid\|.*Docker,? Inc/i.test(stdout.trim())) {
    throw new Error(`the downloaded installer is not signed by Docker (${stdout.trim()})`);
  }
  console.log("Installing Docker Desktop. Accept the Windows administrator prompt.");
  // ErrorActionPreference: a declined UAC prompt must fail the script, not exit 0.
  await runPowershell(
    `$ErrorActionPreference = 'Stop'; $p = Start-Process -FilePath ${psQuote(exe)} -ArgumentList 'install','--quiet','--accept-license' -Verb RunAs -Wait -PassThru; exit $p.ExitCode`,
  );
}

async function installMac(url: string, dir: string): Promise<void> {
  const dmg = join(dir, "Docker.dmg");
  const mount = join(dir, "mount");
  await download(url, dmg, "Docker Desktop");
  mkdirSync(mount);
  await pexec("hdiutil", ["attach", "-nobrowse", "-readonly", "-mountpoint", mount, dmg]);
  try {
    const app = join(mount, "Docker.app");
    const check = await pexec("spctl", ["--assess", "--type", "execute", "-vv", app]).catch(
      (err: { stderr?: string }) => ({ stdout: "", stderr: `rejected ${err.stderr ?? ""}` }),
    );
    if (!/accepted/.test(check.stderr) || !/Docker,? Inc/i.test(check.stderr)) {
      throw new Error(`the downloaded app is not signed by Docker (${check.stderr.trim()})`);
    }
    console.log("Installing Docker Desktop. Enter your password if asked.");
    // --user does the privileged setup now, so the first start asks nothing more.
    await run([
      "sudo",
      join(app, "Contents", "MacOS", "install"),
      "--accept-license",
      `--user=${currentUser()}`,
    ]);
  } finally {
    await pexec("hdiutil", ["detach", mount]).catch(() => {});
  }
}

async function installLinux(url: string, dir: string): Promise<void> {
  const script = join(dir, "get-docker.sh");
  await download(url, script, "the Docker install script");
  console.log("Installing Docker Engine. Enter your password if asked.");
  await run(asRoot(["sh", script]));
  if (!isRoot()) await run(["sudo", "usermod", "-aG", "docker", currentUser()]);
}

async function startDocker(): Promise<void> {
  if (process.platform === "win32") {
    const exe = join(programFiles(), "Docker", "Docker", "Docker Desktop.exe");
    if (!existsSync(exe)) throw new Error(`Docker Desktop is not at ${exe}`);
    spawn(exe, [], { detached: true, stdio: "ignore" }).unref();
    return;
  }
  if (process.platform === "darwin") {
    try {
      await pexec("open", ["-a", "Docker"]);
    } catch {
      throw new Error("Docker Desktop is not in the Applications folder");
    }
    return;
  }
  // Docker Desktop for Linux runs as a user service; Docker Engine as a system one.
  const desktop = await pexec("systemctl", ["--user", "cat", "docker-desktop"]).then(
    () => true,
    () => false,
  );
  if (desktop) {
    await run(["systemctl", "--user", "start", "docker-desktop"]);
    return;
  }
  const systemd = existsSync("/run/systemd/system");
  await run(asRoot(systemd ? ["systemctl", "start", "docker"] : ["service", "docker", "start"]));
}

async function download(url: string, dest: string, label: string): Promise<void> {
  const res = await fetch(url, { headers: { "User-Agent": "agentgg-cli" } });
  if (!res.ok || !res.body) throw new Error(`the download from ${url} failed (HTTP ${res.status})`);
  const total = Number(res.headers.get("content-length")) || 0;
  let received = 0;
  let shown = -1;
  const progress = new Transform({
    transform(chunk: Buffer, _enc, cb) {
      received += chunk.length;
      const pct = total ? Math.floor((received * 100) / total) : -1;
      if (pct !== shown && pct >= 0) {
        shown = pct;
        process.stdout.write(`\rDownloading ${label}: ${pct}%`);
      }
      cb(null, chunk);
    },
  });
  await pipeline(
    Readable.fromWeb(res.body as unknown as WebReadableStream),
    progress,
    createWriteStream(dest),
  );
  if (shown >= 0) process.stdout.write("\n");
}

/** Runs with the terminal attached, so sudo and installers can ask the user. */
function run(cmd: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd[0], cmd.slice(1), { stdio: "inherit" });
    child.on("error", (err) => reject(new Error(`could not run ${cmd[0]}: ${err.message}`)));
    child.on("close", (code) =>
      code === 0 ? resolve() : reject(new Error(`${cmd[0]} exited with code ${code}`)),
    );
  });
}

// -EncodedCommand sidesteps every layer of quoting between node and PowerShell.
function encoded(script: string): string[] {
  return [
    "-NoProfile",
    "-NonInteractive",
    "-EncodedCommand",
    Buffer.from(script, "utf16le").toString("base64"),
  ];
}

function powershell(script: string): Promise<{ stdout: string }> {
  return pexec("powershell.exe", encoded(script));
}

function runPowershell(script: string): Promise<void> {
  return run(["powershell.exe", ...encoded(script)]);
}

function psQuote(s: string): string {
  return `'${s.replace(/'/g, "''")}'`;
}

function programFiles(): string {
  return process.env.ProgramFiles ?? "C:\\Program Files";
}

function isRoot(): boolean {
  return process.getuid?.() === 0;
}

function asRoot(cmd: string[]): string[] {
  return isRoot() ? cmd : ["sudo", ...cmd];
}

function currentUser(): string {
  try {
    return userInfo().username;
  } catch {
    return process.env.USER ?? process.env.USERNAME ?? "";
  }
}
