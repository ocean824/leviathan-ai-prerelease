export async function resolve(specifier, context, nextResolve) {
  if (context.parentURL?.endsWith("/dist/main.js") && specifier === "../vendor/api-anything/dist/heal.js") {
    const actual = new URL("../vendor/api-anything/dist/heal.js", context.parentURL);
    return { url: `${actual.href}?c5-learn-wall-test`, shortCircuit: true };
  }
  if (context.parentURL?.endsWith("/dist/main.js") && specifier === "./challenge.js") {
    const source = `export async function waitForHumanChallenge(_profile, _url, notify) { notify(); return "completed"; }`;
    return { url: `data:text/javascript,${encodeURIComponent(source)}`, shortCircuit: true };
  }
  return nextResolve(specifier, context);
}

export async function load(url, context, nextLoad) {
  if (!url.endsWith("?c5-learn-wall-test")) return nextLoad(url, context);
  const actual = new URL(url);
  actual.search = "";
  const vendorUrl = actual.href;
  const source = `
    import * as vendor from ${JSON.stringify(vendorUrl)};
    import { readFile } from "node:fs/promises";
    let captureIndex = 0;
    export const BotChallengeError = vendor.BotChallengeError;
    export const heal = vendor.heal;
    export async function addOperation(input) {
      const captures = JSON.parse(await readFile(process.env.LEVIATHAN_TEST_CAPTURE_FILE, "utf8"));
      const capture = captures[captureIndex++ === 0 ? "wall" : "success"];
      return vendor.addOperation({
        ...input,
        match: { method: "GET", host: "www.cnn.com", path: "/markets/fear-and-greed" },
        from: { capture },
      });
    }
  `;
  return { format: "module", source, shortCircuit: true };
}
