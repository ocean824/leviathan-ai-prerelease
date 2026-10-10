import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = new URL("..", import.meta.url);
const collectorRoot = fileURLToPath(root);
const vendorRoot = join(collectorRoot, "vendor", "api-anything");
const patchPath = join(collectorRoot, "patches", "api-anything-runtime.patch");
const scratch = await mkdtemp(join(tmpdir(), "leviathan-api-anything-patch-"));
const pristine = join(scratch, "pristine");
const patched = join(scratch, "patched");
const verify = join(scratch, "verify");
const copyVendor = async (from, to) => await cp(from, to, {
  recursive: true,
  force: true,
  filter: (path) => !["node_modules", "dist", ".git"].includes(path.split(/[\\/]/).at(-1)),
});
const git = (args, cwd) => {
  const result = spawnSync("git", args, { cwd, encoding: "utf8", shell: false });
  if (result.status !== 0) throw new Error(result.stderr || `git ${args.join(" ")} failed`);
  return result.stdout;
};

try {
  await mkdir(pristine, { recursive: true });
  await mkdir(patched, { recursive: true });
  await copyVendor(vendorRoot, patched);
  await copyVendor(patched, pristine);
  const reverseCheck = spawnSync("git", ["apply", "--reverse", "--check", patchPath], { cwd: pristine, encoding: "utf8", shell: false });
  if (reverseCheck.status !== 0) throw new Error(`existing patch cannot be reversed against vendored source: ${reverseCheck.stderr}`);
  git(["apply", "--reverse", patchPath], pristine);
  await copyVendor(pristine, verify);
  git(["init", "--quiet"], pristine);
  git(["add", "-A"], pristine);
  git(["-c", "user.name=Leviathan build", "-c", "user.email=build@localhost", "commit", "--quiet", "-m", "pristine api-anything pinned source"], pristine);
  for (const entry of await readdir(pristine, { withFileTypes: true })) {
    if (entry.name !== ".git") await rm(join(pristine, entry.name), { recursive: true, force: true });
  }
  await copyVendor(patched, pristine);
  git(["add", "-A"], pristine);
  const patch = git(["diff", "--cached", "--binary", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/", "HEAD"], pristine);
  if (!patch.startsWith("diff --git ") || (patch.match(/^diff --git /gm) ?? []).length === 0) throw new Error("generated patch is empty or not a unified git diff");
  await writeFile(patchPath, patch, "utf8");

  const check = spawnSync("git", ["apply", "--check", patchPath], { cwd: verify, encoding: "utf8", shell: false });
  if (check.status !== 0) throw new Error(`generated patch does not apply to pristine source: ${check.stderr}`);
  const bytes = await readFile(patchPath);
  console.log(JSON.stringify({ sha256: createHash("sha256").update(bytes).digest("hex"), files: (patch.match(/^diff --git /gm) ?? []).length }));
} finally {
  await rm(scratch, { recursive: true, force: true });
}
