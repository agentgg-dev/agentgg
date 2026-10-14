import { describe, expect, it } from "vitest";
import { dockerAvailable, staleSandboxIds } from "../src/validation/sandbox";

describe("sandbox", () => {
  it("exposes a docker availability probe", async () => {
    expect(typeof (await dockerAvailable())).toBe("boolean");
  });
});

describe("staleSandboxIds", () => {
  const alive = (pid: number) => pid === 100;

  it("selects a sandbox whose owner on this host has exited", () => {
    expect(staleSandboxIds("abc|agentgg.live-sandbox.owner=box:200", "box", alive)).toEqual([
      "abc",
    ]);
  });

  it("keeps a sandbox whose owner is still running", () => {
    expect(staleSandboxIds("abc|agentgg.live-sandbox.owner=box:100", "box", alive)).toEqual([]);
  });

  it("keeps a sandbox started from another host", () => {
    expect(staleSandboxIds("abc|agentgg.live-sandbox.owner=other:200", "box", alive)).toEqual([]);
  });

  it("finds the owner among the image's other labels", () => {
    const listing = [
      "a1|maintainer=x,agentgg.live-sandbox.owner=box:200,org.opencontainers.image.version=24.04",
      "b2|agentgg.live-sandbox.owner=box:100",
      "",
    ].join("\n");
    expect(staleSandboxIds(listing, "box", alive)).toEqual(["a1"]);
  });

  it("skips lines with no owner or an unreadable pid", () => {
    const listing = ["a1|maintainer=x", "b2|agentgg.live-sandbox.owner=box:", "garbage"].join("\n");
    expect(staleSandboxIds(listing, "box", () => false)).toEqual([]);
  });
});
