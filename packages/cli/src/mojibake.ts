/**
 * One UTF-8 character read back as one Latin-1 character per byte: a lead
 * byte C2-DF, E0-EF or F0-F4, then 1, 2 or 3 continuation bytes 80-BF.
 */
const UTF8_AS_LATIN1 = /[Â-ß][\u0080-¿]|[à-ï][\u0080-¿]{2}|[ð-ô][\u0080-¿]{3}/g;

const C1_CONTROL = /[\u0080-\u009f]/;

/**
 * Undo UTF-8 bytes in model prose. A model can escape each byte of a character
 * in the JSON it writes (`â\u0080\u0094` for an em dash). Only a run that
 * holds a C1 control changes: prose never contains one, so clean text is safe.
 */
export function repairMojibake(text: string): string {
  return text.replace(UTF8_AS_LATIN1, (run) => {
    if (!C1_CONTROL.test(run)) return run;
    const decoded = Buffer.from(run, "latin1").toString("utf8");
    return decoded.includes("�") ? run : decoded;
  });
}
