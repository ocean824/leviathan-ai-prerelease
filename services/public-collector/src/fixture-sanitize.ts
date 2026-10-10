import { parse as parseHtml } from "node-html-parser";

export type MappingRecipe = {
  format: "json" | "html" | "embedded";
  extract?: string;
  pick?: readonly string[];
};

const personalValue = /(?:\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|\b(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b|\b\d{3}-\d{2}-\d{4}\b|\b\d{1,6}\s+[\w.'-]+\s+(?:[Ss]treet|[Ss]t\.|[Rr]oad|[Rr]d\.|[Aa]venue|[Aa]ve\.|[Bb]oulevard|[Bb]lvd\.|[Dd]rive|[Dd]r\.)\b|\b(?:Senator|Representative|Filer)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b|\b[A-Z][a-z]+\s+[A-Z][a-z]+\b)/;
const credentialValue = /(?:\bBearer\s+\S{8,}|(?:^|[?&])(?:access_token|session|auth_token|api_key)=)/i;

function assertNoCredential(value: unknown): void {
  if (Array.isArray(value)) return value.forEach(assertNoCredential);
  if (value && typeof value === "object") {
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      if (/^(cookie|set-cookie|authorization|proxy-authorization|x-[\w-]*(token|secret|key))$/i.test(key)) throw new Error("CANDIDATE_CONTAINS_CREDENTIALS");
      assertNoCredential(nested);
    }
    return;
  }
  if (typeof value === "string" && credentialValue.test(value)) throw new Error("CANDIDATE_CONTAINS_CREDENTIALS");
}

function redactText(value: string): string {
  return value.replace(new RegExp(personalValue.source, "g"), "[REDACTED]");
}

function pathParts(path: string): string[] {
  return [...path.matchAll(/\[(\d+|\*)\]|\["((?:[^"\\]|\\.)*)"\]|[^.[\]]+/g)].map((match) =>
    match[1] ?? (match[2] !== undefined ? JSON.parse(`"${match[2]}"`) as string : match[0]),
  );
}

function consumedPaths(recipe?: MappingRecipe): string[][] {
  if (!recipe) return [];
  const root = recipe.extract ? pathParts(recipe.extract) : [];
  if (!recipe.pick?.length) return [root];
  return recipe.pick.flatMap((entry) => {
    const match = /^(?:[\w$-]+)=([\s\S]+)$/.exec(entry);
    const sourcePath = (match?.[1] ?? entry).split("~", 1)[0]!;
    return [[...root, ...pathParts(sourcePath)]];
  });
}

function childPaths(paths: string[][], key: string): string[][] {
  const result: string[][] = [];
  for (const path of paths) {
    if (!path.length) continue;
    if (path[0] === key || path[0] === "*") result.push(path.slice(1));
  }
  return result;
}

function redactJson(value: unknown, paths: string[][]): unknown {
  if (paths.some((path) => path.length === 0)) return value;
  if (Array.isArray(value)) {
    return value.map((item, index) => {
      const indexed = paths.filter((path) => path[0] === String(index) || path[0] === "*").map((path) => path.slice(1));
      const perItem = [...indexed, ...paths.filter((path) => path[0] !== String(index) && path[0] !== "*")];
      return redactJson(item, perItem);
    });
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, nested]) => {
      const preserve = childPaths(paths, key);
      return [key, preserve.length ? redactJson(nested, preserve) : redactJson(nested, [])];
    }));
  }
  return typeof value === "string" ? redactText(value) : value;
}

export function sanitizedFixtureBody(body: string, contentType: string, recipe?: MappingRecipe): string {
  if (contentType.includes("html")) {
    const document = parseHtml(body);
    for (const element of document.querySelectorAll("script,style,input,textarea,select,option,[hidden],[type=hidden]")) element.remove();
    let clean = document.toString();
    clean = clean.replace(/\s+(value|placeholder|aria-label|title|alt)=(['"])(.*?)\2/gi, (attribute, _name: string, _quote: string, value: string) =>
      personalValue.test(value) ? "" : attribute,
    ).replace(new RegExp(personalValue.source, "g"), "[REDACTED]");
    if (credentialValue.test(clean) || /(?:cookie|set-cookie|authorization)\s*:/i.test(clean)) throw new Error("CANDIDATE_CONTAINS_CREDENTIALS");
    return clean;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error("CANDIDATE_FIXTURE_NOT_JSON");
  }
  assertNoCredential(parsed);
  return JSON.stringify(redactJson(parsed, consumedPaths(recipe)));
}
