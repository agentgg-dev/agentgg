import { describe, expect, it } from "vitest";
import { repairMojibake } from "../src/mojibake.js";

/** The text as a reader of its UTF-8 bytes one per character sees it. */
const bytesAsChars = (text: string): string => Buffer.from(text, "utf8").toString("latin1");

describe("repairMojibake", () => {
  it("restores punctuation whose UTF-8 bytes were read one per character", () => {
    for (const text of ["accurate — src/server.ts", "rules (“Bugs”)", "—’…"]) {
      expect(repairMojibake(bytesAsChars(text))).toBe(text);
    }
  });

  it("restores a two-byte character that holds a control byte", () => {
    expect(repairMojibake(bytesAsChars("Étape"))).toBe("Étape");
  });

  it("leaves a run with no control byte alone", () => {
    expect(repairMojibake(bytesAsChars("café"))).toBe(bytesAsChars("café"));
  });

  it("leaves clean text alone", () => {
    const text = "The sink is real — café costs £5 à la carte.";
    expect(repairMojibake(text)).toBe(text);
  });

  it("leaves a run that is not valid UTF-8 alone", () => {
    const overlong = `x ${Buffer.from([0xe0, 0x80, 0x80]).toString("latin1")} y`;
    expect(repairMojibake(overlong)).toBe(overlong);
  });
});
