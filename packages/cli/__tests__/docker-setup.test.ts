import { describe, expect, it, vi } from "vitest";
import {
  type DockerSetupDeps,
  type DockerState,
  dockerDownloadUrl,
  setUpDocker,
} from "../src/validation/docker-setup.js";

/** Each `state()` call returns the next entry; the last one repeats. */
function deps(states: DockerState[], over: Partial<DockerSetupDeps> = {}) {
  const queue = [...states];
  const lines: string[] = [];
  const d: DockerSetupDeps = {
    platform: "win32",
    interactive: true,
    canInstall: true,
    username: "dev",
    state: vi.fn(async () => (queue.length > 1 ? (queue.shift() as DockerState) : queue[0])),
    confirm: vi.fn(async () => true),
    install: vi.fn(async () => {}),
    start: vi.fn(async () => {}),
    sleep: vi.fn(async () => {}),
    log: (line: string) => lines.push(line),
    ...over,
  };
  return { d, lines };
}

describe("setUpDocker", () => {
  it("does nothing when Docker already runs", async () => {
    const { d } = deps(["running"]);
    expect(await setUpDocker(d)).toEqual({ ok: true });
    expect(d.confirm).not.toHaveBeenCalled();
    expect(d.install).not.toHaveBeenCalled();
    expect(d.start).not.toHaveBeenCalled();
  });

  it("installs, starts, and waits for Docker when the user agrees", async () => {
    const { d } = deps(["missing", "stopped", "stopped", "running"]);
    expect(await setUpDocker(d)).toEqual({ ok: true });
    expect(d.install).toHaveBeenCalledTimes(1);
    expect(d.start).toHaveBeenCalledTimes(1);
  });

  it("asks only once when it installs, not again before the start", async () => {
    const { d } = deps(["missing", "stopped", "running"]);
    await setUpDocker(d);
    expect(d.confirm).toHaveBeenCalledTimes(1);
  });

  it("does not install when the user says no", async () => {
    const { d } = deps(["missing"], { confirm: vi.fn(async () => false) });
    const r = await setUpDocker(d);
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toContain("Docker is not installed");
    expect(d.install).not.toHaveBeenCalled();
  });

  it("never prompts or installs outside an interactive terminal", async () => {
    const { d } = deps(["missing"], { interactive: false });
    const r = await setUpDocker(d);
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toContain("Docker is not installed");
    expect(d.confirm).not.toHaveBeenCalled();
    expect(d.install).not.toHaveBeenCalled();
  });

  it("does not offer an install on a platform without an installer", async () => {
    const { d } = deps(["missing"], { platform: "freebsd", canInstall: false });
    const r = await setUpDocker(d);
    expect(r.ok).toBe(false);
    expect(d.confirm).not.toHaveBeenCalled();
    expect(d.install).not.toHaveBeenCalled();
  });

  it("reports an install failure and does not try to start Docker", async () => {
    const { d } = deps(["missing"], {
      install: vi.fn(async () => {
        throw new Error("the installer exited with code 1");
      }),
    });
    const r = await setUpDocker(d);
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toContain("the installer exited with code 1");
    expect(d.start).not.toHaveBeenCalled();
  });

  it("shows the Docker Desktop license terms before the Windows and macOS install", async () => {
    for (const platform of ["win32", "darwin"] as const) {
      const { d, lines } = deps(["missing"], { platform, confirm: vi.fn(async () => false) });
      await setUpDocker(d);
      expect(lines.join("\n")).toContain("docker-subscription-service-agreement");
    }
  });

  it("names the Docker install script and the docker group before the Linux install", async () => {
    const { d, lines } = deps(["missing"], {
      platform: "linux",
      confirm: vi.fn(async () => false),
    });
    await setUpDocker(d);
    expect(lines.join("\n")).toContain("https://get.docker.com");
    expect(lines.join("\n")).toContain("docker group");
  });

  it("starts a stopped Docker when the user agrees", async () => {
    const { d } = deps(["stopped", "stopped", "running"]);
    expect(await setUpDocker(d)).toEqual({ ok: true });
    expect(d.confirm).toHaveBeenCalledTimes(1);
    expect(d.start).toHaveBeenCalledTimes(1);
    expect(d.install).not.toHaveBeenCalled();
  });

  it("does not start Docker when the user says no", async () => {
    const { d } = deps(["stopped"], { confirm: vi.fn(async () => false) });
    const r = await setUpDocker(d);
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toContain("not running");
    expect(d.start).not.toHaveBeenCalled();
  });

  it("does not start Docker outside an interactive terminal", async () => {
    const { d } = deps(["stopped"], { interactive: false });
    const r = await setUpDocker(d);
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toContain("not running");
    expect(d.start).not.toHaveBeenCalled();
  });

  it("reports a start failure", async () => {
    const { d } = deps(["stopped"], {
      start: vi.fn(async () => {
        throw new Error("Docker Desktop is not in its default folder");
      }),
    });
    const r = await setUpDocker(d);
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toContain("Docker Desktop is not in its default folder");
  });

  it("gives up when Docker never responds, after a bounded wait", async () => {
    const { d } = deps(["stopped"]);
    const r = await setUpDocker(d);
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toContain("did not start");
    expect(vi.mocked(d.state).mock.calls.length).toBeLessThan(200);
  });

  it("tells a Linux user without socket access to join the docker group", async () => {
    const { d } = deps(["no-access"], { platform: "linux" });
    const r = await setUpDocker(d);
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toContain("usermod -aG docker");
    expect(d.start).not.toHaveBeenCalled();
  });

  it("tells a Linux user to log in again after agentgg added them to the docker group", async () => {
    const { d } = deps(["missing", "no-access"], { platform: "linux" });
    const r = await setUpDocker(d);
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toContain("log out and log in");
    expect(r.ok === false && r.reason).not.toContain("usermod");
  });

  it("tells a Windows user without access to join docker-users", async () => {
    const { d } = deps(["no-access"], { platform: "win32" });
    const r = await setUpDocker(d);
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toContain("net localgroup docker-users dev /add");
  });
});

describe("dockerDownloadUrl", () => {
  it("picks the Docker Desktop installer for each Windows and macOS CPU", () => {
    expect(dockerDownloadUrl("win32", "x64")).toBe(
      "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe",
    );
    expect(dockerDownloadUrl("win32", "arm64")).toBe(
      "https://desktop.docker.com/win/main/arm64/Docker%20Desktop%20Installer.exe",
    );
    expect(dockerDownloadUrl("darwin", "arm64")).toBe(
      "https://desktop.docker.com/mac/main/arm64/Docker.dmg",
    );
    expect(dockerDownloadUrl("darwin", "x64")).toBe(
      "https://desktop.docker.com/mac/main/amd64/Docker.dmg",
    );
  });

  it("uses Docker's install script on Linux", () => {
    expect(dockerDownloadUrl("linux", "x64")).toBe("https://get.docker.com");
    expect(dockerDownloadUrl("linux", "arm64")).toBe("https://get.docker.com");
  });

  it("has no installer for other platforms or CPUs", () => {
    expect(dockerDownloadUrl("freebsd", "x64")).toBeNull();
    expect(dockerDownloadUrl("win32", "ia32")).toBeNull();
  });
});
