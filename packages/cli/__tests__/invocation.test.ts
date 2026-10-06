import { describe, expect, it } from "vitest";
import { buildInvocation } from "../src/commands/invocation.js";

const argvOf = (argv: string[]): string => buildInvocation({ command: "scan", argv }).argv ?? "";

describe("buildInvocation", () => {
  it("keeps the command and the non-credential flags", () => {
    expect(argvOf(["scan", "./src", "--provider", "anthropic", "-o", "./out"])).toBe(
      "scan ./src --provider anthropic -o ./out",
    );
  });

  it("masks the --api-key value", () => {
    expect(argvOf(["scan", "./src", "--api-key", "sk-ant-api03-secret"])).toBe(
      "scan ./src --api-key ***",
    );
  });

  it("masks the --oauth-token value", () => {
    expect(argvOf(["scan", "./src", "--oauth-token", "sk-ant-oat01-secret"])).toBe(
      "scan ./src --oauth-token ***",
    );
  });

  it("masks the --flag=value form", () => {
    expect(argvOf(["scan", "--api-key=sk-ant-api03-secret", "./src"])).toBe(
      "scan --api-key=*** ./src",
    );
  });

  it("leaves no secret behind when the flag ends the line", () => {
    expect(argvOf(["scan", "./src", "--api-key"])).toBe("scan ./src --api-key");
  });

  it("masks every occurrence", () => {
    expect(argvOf(["scan", "--api-key", "one", "--oauth-token", "two"])).toBe(
      "scan --api-key *** --oauth-token ***",
    );
  });
});
