import { describe, expect, it, vi } from "vitest";
import {
  isSafeKnowledgeArchiveTag,
  KnowledgeArchiveError,
  listKnowledgeIngestions,
  UNLISTED_TAG_MARKER,
} from "../wave26/api/knowledgeArchive";
import fixturesTsv from "./safeLabelCases.tsv?raw";
import * as safeLabelHelpers from "./safeLabel";
import { isSafeDisplayLabel, isSafeIdentifier } from "./safeLabel";

type Predicate = "display" | "identifier";
type Fixture = { predicate: Predicate; value: string; safe: boolean };

const FIXTURES = fixturesTsv
  .trim()
  .split(/\r?\n/)
  .slice(1)
  .map((line): Fixture => {
    const [predicate, value, expected] = line.split("\t");
    if ((predicate !== "display" && predicate !== "identifier") || value === undefined) {
      throw new Error("invalid safe-label fixture row");
    }
    return { predicate, value, safe: expected === "true" };
  });

const ACCEPTED = ["risk", "desk", "risk-control", "fx-majors"];
const ACCEPTED_DISPLAY_ONLY = ["Alpha v2", "hunter2", "my secretary"];
const ACCEPTED_IDENTIFIER_ONLY = ["wave-2", "bridge-1"];
const ACCEPTED_BOTH = ["my-secretary", "passwordless", "MY-SECRETARY", "PASSWORDLESS"];
const REJECTED = [
  "password123",
  "my-secret2",
  "apikeyprod",
  "api-gateway",
  "my password",
  "MY PASSWORD",
  "secret",
  "SECRET",
  "sk_live",
  "ghp_x",
  "akia-secret",
  "API-GATEWAY",
];
const CREDENTIAL_SHAPES = [
  "glpat-testfixturetoken",
  "pypi-testfixturetoken",
  "sk-testfixturetoken",
  "github_pat_testfixturetoken",
  "ghp_testfixturetoken",
  "xoxb-test-fixture-token",
  "AKIA000000000000TEST",
  "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl",
];
const EMBEDDED_CREDENTIAL_SHAPES = [
  "foo_glpat-testfixturetoken",
  "x_pypi-testfixturetoken",
  "a_ghp_testfixturetoken",
  "pre-sk-testfixturetoken",
  "a.github_pat_testfixturetoken",
  "x:xoxb-test-fixture-token",
];
const SAFE_IDENTIFIER_CONTROLS = ["wave-2", "risk_control", "desk_1", "alpha-v2"];
const LONG_DIGIT_INPUTS = ["123456789", "123456789012"];

describe("CL-SAFE-LABEL-UNIFY independent acceptance", () => {
  for (const { predicate, value, safe } of FIXTURES) {
    it(`matches shared ${predicate} fixture: ${value}`, () => {
    const verdict = predicate === "display" ? isSafeDisplayLabel(value) : isSafeIdentifier(value);
    expect(verdict).toBe(safe);
    });
  }

  for (const value of ACCEPTED) {
    it(`accepts required safe example ${value} in both shared predicates`, () => {
      expect(isSafeDisplayLabel(value)).toBe(true);
      expect(isSafeIdentifier(value)).toBe(true);
    });
  }

  for (const value of ACCEPTED_DISPLAY_ONLY) {
    it(`accepts ruled display example ${value}`, () => {
      expect(isSafeDisplayLabel(value)).toBe(true);
    });
  }

  for (const value of ACCEPTED_IDENTIFIER_ONLY) {
    it(`accepts ruled identifier/tag example ${value}`, () => {
      expect(isSafeIdentifier(value)).toBe(true);
      expect(isSafeDisplayLabel(value)).toBe(false);
    });
  }

  for (const value of ACCEPTED_BOTH) {
    it(`accepts whole-word negative ${value} in both predicates`, () => {
      expect(isSafeDisplayLabel(value)).toBe(true);
      expect(isSafeIdentifier(value)).toBe(true);
    });
  }

  for (const value of REJECTED) {
    it(`rejects required secret example ${value} in both shared predicates`, () => {
      expect(isSafeDisplayLabel(value)).toBe(false);
      expect(isSafeIdentifier(value)).toBe(false);
    });
  }

  for (const value of LONG_DIGIT_INPUTS) {
    it(`rejects long digit run ${value} in both predicates`, () => {
      expect(isSafeDisplayLabel(value)).toBe(false);
      expect(isSafeIdentifier(value)).toBe(false);
    });
  }

  for (const value of CREDENTIAL_SHAPES) {
    it(`rejects synthetic credential-family identifier ${value}`, () => {
      expect(isSafeIdentifier(value)).toBe(false);
    });
  }

  for (const value of EMBEDDED_CREDENTIAL_SHAPES) {
    it(`rejects embedded synthetic credential-family identifier ${value}`, () => {
      expect(isSafeIdentifier(value)).toBe(false);
    });
  }

  for (const value of SAFE_IDENTIFIER_CONTROLS) {
    it(`accepts benign identifier control ${value}`, () => {
      expect(isSafeIdentifier(value)).toBe(true);
    });
  }

  it("rejects hunter2 as an identifier", () => {
    expect(isSafeIdentifier("hunter2")).toBe(false);
    expect(isSafeDisplayLabel("hunter2")).toBe(true);
  });

  it("keeps identifier scanning bounded at the 64 KiB boundary", () => {
    const maximum = "x_".repeat(32_768);
    const started = performance.now();
    expect(isSafeIdentifier(maximum)).toBe(false);
    expect(performance.now() - started).toBeLessThan(100);
    expect(isSafeIdentifier(`${maximum}x`)).toBe(false);
  });


  it("requires all acceptance examples to appear in the shared fixture table", () => {
    const cases = new Set(FIXTURES.map(({ predicate, value, safe }) => `${predicate}\t${value}\t${safe}`));
    for (const value of ACCEPTED) {
      expect(cases.has(`display\t${value}\ttrue`)).toBe(true);
      expect(cases.has(`identifier\t${value}\ttrue`)).toBe(true);
    }
    for (const value of ACCEPTED_DISPLAY_ONLY) {
      expect(cases.has(`display\t${value}\ttrue`)).toBe(true);
    }
    for (const value of ACCEPTED_IDENTIFIER_ONLY) {
      expect(cases.has(`identifier\t${value}\ttrue`)).toBe(true);
      expect(cases.has(`display\t${value}\tfalse`)).toBe(true);
    }
    for (const value of ACCEPTED_BOTH) {
      expect(cases.has(`display\t${value}\ttrue`)).toBe(true);
      expect(cases.has(`identifier\t${value}\ttrue`)).toBe(true);
    }
    expect(cases.has("display\thunter2\ttrue")).toBe(true);
    expect(cases.has("identifier\thunter2\tfalse")).toBe(true);
    for (const value of REJECTED) {
      expect(cases.has(`display\t${value}\tfalse`)).toBe(true);
      expect(cases.has(`identifier\t${value}\tfalse`)).toBe(true);
    }
    for (const value of CREDENTIAL_SHAPES) {
      expect(cases.has(`identifier\t${value}\tfalse`)).toBe(true);
    }
    for (const value of EMBEDDED_CREDENTIAL_SHAPES) {
      expect(cases.has(`identifier\t${value}\tfalse`)).toBe(true);
    }
    for (const value of SAFE_IDENTIFIER_CONTROLS) {
      expect(cases.has(`identifier\t${value}\ttrue`)).toBe(true);
    }
    for (const predicate of ["display", "identifier"] as const) {
      expect(FIXTURES.some(({ predicate: rowPredicate, value, safe }) =>
        rowPredicate === predicate && !safe && /[0-9]{9,}/.test(value),
      )).toBe(true);
    }
  });

  for (const { predicate, value, safe } of FIXTURES) {
    if (predicate !== "identifier") continue;
    it(`knowledge archive tag consumer agrees with the helper for ${value}`, () => {
      // The archive keeps its narrower tag grammar before delegating.
      const tagGrammar = /^[a-z0-9][a-z0-9_-]{0,63}$/.test(value);
      expect(isSafeKnowledgeArchiveTag(value)).toBe(tagGrammar && safe);
    });
  }

  it("knowledge archive delegates identifier safety after its tag grammar", () => {
    const helper = vi.spyOn(safeLabelHelpers, "isSafeIdentifier").mockReturnValue(false);
    expect(isSafeKnowledgeArchiveTag("risk")).toBe(false);
    expect(helper).toHaveBeenCalledWith("risk");
    helper.mockRestore();
  });

  it("rejects api-gateway as a query tag before fetching", async () => {
    const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response("{}", { status: 200 }),
    );
    await expect(
      Promise.resolve().then(() => listKnowledgeIngestions({ tag: "api-gateway" }, fetcher)),
    ).rejects.toMatchObject({
      code: "INVALID_QUERY",
    } satisfies Partial<KnowledgeArchiveError>);
    expect(fetcher).not.toHaveBeenCalled();
  });

  for (const tag of ["risk", "desk", "risk-control"]) {
    it(`preserves safe query tag ${tag}`, async () => {
      const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response(JSON.stringify({
          data: [],
          meta: {
            cursor: null,
            warnings: [],
            replacement: { market_data_doc: "read-only", ea_builder_doc: "read-only" },
          },
        }), { status: 200, headers: { "content-type": "application/json" } }),
      );
      await listKnowledgeIngestions({ tag }, fetcher);
      expect(fetcher).toHaveBeenCalledTimes(1);
      expect(String(fetcher.mock.calls[0]?.[0])).toContain(`tag=${encodeURIComponent(tag)}`);
    });
  }

  it("sanitizes api-gateway response tags and preserves safe tags", async () => {
    const responseBody = {
      data: [{
        id: "ing-1",
        source_type: "file",
        created_at_ns: "1",
        updated_at_ns: "2",
        tags: ["api-gateway", "risk", "desk", "risk-control"],
        status: "archived",
        data: {},
      }],
      meta: {
        cursor: null,
        warnings: [],
        replacement: { market_data_doc: "read-only", ea_builder_doc: "read-only" },
      },
    };
    const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(JSON.stringify(responseBody), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    const page = await listKnowledgeIngestions({}, fetcher);
    expect(page.items[0]?.tags).toEqual([
      UNLISTED_TAG_MARKER,
      "risk",
      "desk",
      "risk-control",
    ]);
  });
});
