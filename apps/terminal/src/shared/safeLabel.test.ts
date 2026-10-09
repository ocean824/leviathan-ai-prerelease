import { describe, expect, it } from "vitest";

import { isSafeDisplayLabel, isSafeIdentifier } from "./safeLabel";
import fixtureText from "./safeLabelCases.tsv?raw";

const fixtureRows = fixtureText.trimEnd().split(/\r?\n/).slice(1);

describe("Python and TypeScript lesson-19 fixture parity", () => {
  fixtureRows.forEach((row) => it(`matches ${row}`, () => {
    const [predicate, value, expected] = row.split("\t");
    const check = predicate === "display" ? isSafeDisplayLabel : isSafeIdentifier;
    expect(check(value)).toBe(expected === "true");
  }));
});
