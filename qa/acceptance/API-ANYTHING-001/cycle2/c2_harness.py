"""Cycle-2 acceptance harness (production entrypoint + test-only fetch seam).  Unlike the cycle-0 harness it NEVER sets AA_CONTROL (the env var the
cycle-1 sidecar treats as a test switch that relaxes its own policy); it drives the production path:
the committed PINNED.json shape, robots.txt, host allowlist, rate state, first-seen ledger.

Nothing contacts a live site: a preload replaces global fetch with an in-process fake internet, and
vendor behaviour is either the real vendored runtime or a stub controlled through AA_STUB_CONTROL."""

from __future__ import annotations

import hashlib
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import aa_harness as A  # noqa: E402  (cycle-0 harness: junctions, sockets, constants only; build is re-implemented below)

WORKTREE = A.WORKTREE
NODE = A.NODE
FAKENET = HERE / "fakenet.mjs"
REPO = A.WORKTREE

STUB_EXECUTE = r"""
import { appendFileSync, readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
const state = {};
const control = () => JSON.parse(readFileSync(process.env.AA_STUB_CONTROL, "utf8"));
function next(kind) {
  const c = control();
  const st = (state[kind] ??= { epoch: c.epoch, i: 0 });
  if (st.epoch !== c.epoch) { st.epoch = c.epoch; st.i = 0; }
  const queue = c[kind] ?? [];
  const item = queue[Math.min(st.i, queue.length - 1)];
  st.i += 1;
  return item;
}
const siteSha = (site) => {
  const f = join(process.env.API_ANYTHING_HOME, "sites", site + ".json");
  return existsSync(f) ? createHash("sha256").update(readFileSync(f)).digest("hex") : null;
};
async function run(kind, site, op, args, opts) {
  appendFileSync(process.env.AA_STUB_LOG, JSON.stringify({
    ev: kind, site, op, args, maxTier: opts?.maxTier, minIntervalMs: opts?.minIntervalMs,
    home: process.env.API_ANYTHING_HOME, site_sha: siteSha(site), env_ctl: process.env.AA_CONTROL ?? null,
  }) + "\n");
  const spec = next(kind);
  if (spec.fetch) { try { await opts.fetchImpl(spec.fetch, {}); } catch (e) { return { ok: false, class: "error", reason: String(e.message), ms: 1 }; } }
  if (spec.write_site) {
    const { writeFileSync, mkdirSync } = await import("node:fs");
    mkdirSync(join(process.env.API_ANYTHING_HOME, "sites"), { recursive: true });
    writeFileSync(join(process.env.API_ANYTHING_HOME, "sites", site + ".json"), spec.write_site);
  }
  return spec.result;
}
export const call = (site, op, args, opts) => run("call", site, op, args, opts);
export const heal = (site, op, args, opts) => run("heal", site, op, args, opts);
"""

STUB_HEAL = r"""
import { appendFileSync, readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const st = { epoch: -1, i: 0 };
export async function addOperation(opts) {
  appendFileSync(process.env.AA_STUB_LOG, JSON.stringify({
    ev: "learn", site: opts.site, op: opts.op, trigger: opts.trigger, examples: opts.examples,
    home: process.env.API_ANYTHING_HOME,
  }) + "\n");
  const c = JSON.parse(readFileSync(process.env.AA_STUB_CONTROL, "utf8"));
  if (st.epoch !== c.epoch) { st.epoch = c.epoch; st.i = 0; }
  const spec = c.learn[Math.min(st.i, c.learn.length - 1)];
  st.i += 1;
  if (spec.fetch) { await opts.fetchImpl(spec.fetch, {}); }
  if (spec.throw) { const e = new Error(spec.throw); if (spec.challenge) e.challenge = true; throw e; }
  mkdirSync(join(process.env.API_ANYTHING_HOME, "sites"), { recursive: true });
  writeFileSync(join(process.env.API_ANYTHING_HOME, "sites", opts.site + ".json"), spec.write_site);
}
"""

# Stub vendor "browser.js" so challenge.ts can import chromeAvailable()
STUB_BROWSER = "export const chromeAvailable = () => true;\n"

# Wraps the REAL addOperation: the browser trigger is replaced by a recorded capture from the control file, everything else
# (template inference, challenge classification, BotChallengeError) is the shipped vendor code.
MIXED_ADD_OPERATION = r"""

import { appendFileSync as __append, readFileSync as __read } from "node:fs";
const __state = { epoch: -1, i: 0 };
export async function addOperation(input) {
  const c = JSON.parse(__read(process.env.AA_STUB_CONTROL, "utf8"));
  if (__state.epoch !== c.epoch) { __state.epoch = c.epoch; __state.i = 0; }
  const spec = c.add_operation[Math.min(__state.i, c.add_operation.length - 1)];
  __state.i += 1;
  __append(process.env.AA_STUB_LOG, JSON.stringify({ ev: "learn", site: input.site, op: input.op, home: process.env.API_ANYTHING_HOME }) + "\n");
  return addOperationReal({ ...input, from: { capture: spec.capture }, ...(spec.capture2 ? { from2: spec.capture2 } : {}), match: spec.match, response: spec.response ?? input.response });
}
"""

FAKE_CHALLENGE = r"""
import { appendFileSync, readFileSync } from "node:fs";
export async function waitForHumanChallenge(profileDir, url, notify, open, timeoutMs, challengeHosts, dataDir) {
  appendFileSync(process.env.AA_STUB_LOG, JSON.stringify({ ev: "challenge", profileDir, url, timeoutMs, challengeHosts: challengeHosts ?? null, dataDir: dataDir ?? null }) + "\n");
  const c = JSON.parse(readFileSync(process.env.AA_STUB_CONTROL, "utf8"));
  if (c.challenge_notify !== false) notify();
  return c.challenge_outcome;
}
export const openVisibleChallenge = async () => { throw new Error("not available in fake"); };
"""


def build(scratch: Path) -> Path:
    """Copy the frozen collector to scratch and run its REAL build (scripts/build-vendor.mjs: reverse+apply the vendor
    patch, compile the runtime subset, write runtime-manifest + pin-hash), then compile the wrapper.  Optional mutant."""
    src = REPO / "services" / "public-collector"
    dst = scratch / "collector"
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("node_modules", "dist", ".vendor-build", ".git"))
    shutil.rmtree(dst / "vendor" / "api-anything" / "dist", ignore_errors=True)
    A.link_dir(dst / "node_modules", src / "node_modules")
    mutant = A.load_mutant()
    if mutant and mutant["target"] == "vendor-src":
        A.apply_mutation(dst / "vendor" / "api-anything" / "src" / mutant["file"], mutant["find"], mutant["replace"])
    A._run([NODE, "scripts/build-vendor.mjs"], cwd=dst)
    A._run([NODE, str(dst / "node_modules" / "typescript" / "bin" / "tsc"), "-p", "tsconfig.json"], cwd=dst)
    if mutant and (dst / "dist" / f"{mutant['target']}.js").is_file() and mutant["target"] not in {"pinned"}:
        A.apply_mutation(dst / "dist" / f"{mutant['target']}.js", mutant["find"], mutant["replace"])
    if mutant and mutant["target"] == "vendor-dist":
        A.apply_mutation(dst / "vendor" / "api-anything" / "dist" / mutant["file"], mutant["find"], mutant["replace"])
    if mutant and mutant["target"] == "pinned":
        pinned = dst / "templates" / "PINNED.json"
        A.apply_mutation(pinned, mutant["find"], mutant["replace"])
        seal_dist(dst / "dist", pinned)
    global RECIPE_DIST
    RECIPE_DIST = dst / "dist"
    return dst


_MAPPING_CACHE: dict[str, dict[str, Any]] = {}
RECORDED_REQUIRED = {"calendar.fed", "senate.efd.ptr"}
RECIPE_DIST: Path | None = None


def mapping_for(dist: Path) -> dict[str, Any]:
    """The reviewed native->contract mapping recipes compiled into this build, plus the sha256 of their stable JSON."""
    key = str(dist)
    if key not in _MAPPING_CACHE:
        script = "import {operationContracts as c} from " + json.dumps((dist / "contracts.js").as_uri()) + ";console.log(JSON.stringify(Object.fromEntries(Object.entries(c).map(([k,v])=>[k,{recipe:v.mappingRecipe,kind:v.mappingFixtureKind}]))));"
        out = subprocess.run([NODE, "--input-type=module", "-e", script], capture_output=True, text=True, check=True).stdout
        _MAPPING_CACHE[key] = json.loads(out)
    return _MAPPING_CACHE[key]


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def seal_dist(dist: Path, registry_path: Path) -> None:
    """Pins are per-test, so the scratch dist's baked registry hash is regenerated (production does this at build time)."""
    digest = hashlib.sha256(registry_path.read_bytes()).hexdigest()
    (dist / "pin-hash.js").write_text(f'export const PIN_REGISTRY_SHA256 = "{digest}";\n', encoding="utf-8")


def make_variant(collector: Path, name: str, *, vendor: str, challenge: str) -> Path:
    root = collector.parent / f"h1-{name}"
    shutil.copytree(collector / "dist", root / "dist")
    shutil.copytree(collector / "templates", root / "templates")
    (root / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    A.link_dir(root / "node_modules", collector / "node_modules")
    if vendor == "real":
        A.link_dir(root / "vendor", collector / "vendor")
    elif vendor == "mixed":
        shutil.copytree(collector / "vendor", root / "vendor", ignore=shutil.ignore_patterns("node_modules", "src", "test", "bench", "docs", "examples", "skills", "sites"))
        heal = root / "vendor" / "api-anything" / "dist" / "heal.js"
        text = heal.read_text(encoding="utf-8")
        marker = "export async function addOperation("
        assert marker in text, "vendor heal.js no longer exports addOperation"
        heal.write_text(text.replace(marker, "async function addOperationReal(", 1) + MIXED_ADD_OPERATION, encoding="utf-8")
    else:
        vdist = root / "vendor" / "api-anything" / "dist"
        vdist.mkdir(parents=True)
        (root / "vendor" / "api-anything" / "package.json").write_text('{"type":"module"}', encoding="utf-8")
        (vdist / "execute.js").write_text(STUB_EXECUTE, encoding="utf-8")
        (vdist / "heal.js").write_text(STUB_HEAL, encoding="utf-8")
        (vdist / "browser.js").write_text(STUB_BROWSER, encoding="utf-8")
    if challenge == "fake":
        (root / "dist" / "challenge.js").write_text(FAKE_CHALLENGE, encoding="utf-8")
    return root


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def now() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------- pins

SITE_HOST = {
    "calendar.fed": "www.federalreserve.gov",
    "earnings.forward": "finance.yahoo.com",
    "senate.efd.ptr": "efdsearch.senate.gov",
    "cboe.daily.stats": "www.cboe.com",
    "cnn.fear_greed": "www.cnn.com",
}
FEED_PATH = "/fixture/feed.json"


def template_for(op_id: str, host: str | None = None, path: str = FEED_PATH, extract: str = "data", recipe: bool = True) -> bytes:
    site = A.SITES[op_id]
    operation = {
        "calendar.fed": "release-calendar", "earnings.forward": "forward-calendar", "senate.efd.ptr": "periodic-transactions",
        "cboe.daily.stats": "daily-statistics", "cnn.fear_greed": "current-index",
    }[op_id]
    params = {
        "calendar.fed": [{"name": "year", "type": "number", "example": 2026}],
        "earnings.forward": [{"name": "symbols", "type": "array", "example": ["AAPL"]}],
        "senate.efd.ptr": [{"name": "page", "type": "number", "example": 1}],
        "cboe.daily.stats": [{"name": "date", "type": "string", "example": "2026-10-09"}],
        "cnn.fear_greed": [],
    }[op_id]
    host = host or SITE_HOST[op_id]
    url = f"https://{host}{path}"
    op = {
        "name": operation, "description": "acceptance fake",
        "request": {"method": "GET", "url": url, "headers": {"accept": "application/json"}},
        "slots": [], "volatile": [], "trigger": {"url": f"https://{host}/"}, "match": {"path": path},
        "response": {"format": "json", "contentType": "application/json", "extract": extract},
        "params": params, "readOnly": True, "minTier": 1, "learnedLoggedIn": False, "learnedAt": "2026-10-01T00:00:00Z",
    }
    if recipe:
        assert RECIPE_DIST is not None, "build() must run first"
        r = mapping_for(RECIPE_DIST)[op_id]["recipe"]
        op["response"] = {"format": r["format"], "contentType": "application/json", "extract": r["extract"], "pick": list(r["pick"])}
    return json.dumps({"name": site, "displayName": "fake", "baseUrl": f"https://{host}", "description": "acceptance fake", "operations": [op]}).encode()


_BASE = datetime.now(UTC).replace(microsecond=0)


def _set_path(node: dict[str, Any], parts: list[str], value: Any) -> None:
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def infer_op(rows: list[dict[str, Any]]) -> str:
    keys = set(rows[0]) if rows else set()
    if "event_name" in keys:
        return "calendar.fed"
    if "fiscal_period" in keys:
        return "earnings.forward"
    if "report_url" in keys:
        return "senate.efd.ptr"
    if "metric" in keys:
        return "cboe.daily.stats"
    return "cnn.fear_greed"


def native_body(op_id: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    """The site-shaped (native) JSON body whose reviewed recipe yields exactly `rows`."""
    assert RECIPE_DIST is not None, "build() must run first"
    recipe = mapping_for(RECIPE_DIST)[op_id]["recipe"]
    items = []
    for row in rows:
        item: dict[str, Any] = {}
        for entry in recipe["pick"]:
            out, sep, src = entry.partition("=")
            src = src if sep else out
            if out in row:
                _set_path(item, src.split("."), row[out])
        items.append(item)
    body: Any = items
    for key in reversed(recipe["extract"].split(".")):
        body = {key: body}
    return body


def fresh_rows(op_id: str, *, age_minutes: int = 60, extra: dict[str, Any] | None = None, at: datetime | None = None) -> list[dict[str, Any]]:
    ref = at or _BASE
    t = ref - timedelta(minutes=age_minutes)
    if op_id == "cnn.fear_greed":
        row = {"value": 55, "label": "Greed", "observed_at": iso(t)}
    elif op_id == "calendar.fed":
        row = {"event_name": "FOMC", "agency": "FRB", "scheduled_at": iso(ref + timedelta(days=30)), "release_type": "meeting",
               "published_at": iso(t)}
    elif op_id == "earnings.forward":
        row = {"ticker": "AAPL", "fiscal_period": "Q4 2026", "event_type": "earnings", "scheduled_at": iso(ref + timedelta(days=20)), "status": "confirmed"}
    elif op_id == "senate.efd.ptr":
        row = {"report_url": "https://efdsearch.senate.gov/search/view/ptr/abc/", "filed_at": iso(t),
               "transactions": [{"ticker": "MSFT", "trade_date": iso(t - timedelta(days=3)), "transaction_type": "Purchase", "amount_range": "$1,001 - $15,000"}]}
    else:
        row = {"observed_at": iso(t), "metric": "put_call_ratio", "value": 0.87, "unit": "ratio", "maturity": None}
    row.update(extra or {})
    return [row]


def envelope(rows: list[dict[str, Any]], *, fetched_at: datetime | None = None, raw_body: str | None = None, content_type: str = "application/json", op: str | None = None) -> dict[str, Any]:
    """A cycle-3 pinned fixture entry: the recorded raw response, when it was fetched, and the typed rows it must yield."""
    return {"fetched_at": iso(fetched_at or now()), "raw_body": raw_body if raw_body is not None else json.dumps(native_body(op or infer_op(rows), rows)),
            "content_type": content_type, "rows": rows}


def write_pin(variant: Path, op_id: str, *, rows: list[dict[str, Any]] | None = None, template: bytes | None = None,
              hosts: list[str] | None = None, approved_at: datetime | None = None,
              review_note: str = "acceptance fixture review", mutate: dict[str, Any] | None = None,
              fixture_at: datetime | None = None, raw_body: str | None = None, fixtures: list[Any] | None = None,
              fixture_text: str | None = None) -> dict[str, Any]:
    """Write a production-shaped PINNED.json entry (+ template + raw-envelope fixture) into the variant's templates dir."""
    tdir = variant / "templates"
    template = template if template is not None else template_for(op_id)
    version = "pin-" + hashlib.sha256(template).hexdigest()[:8]
    rel = f"{op_id}/{version}.json"
    (tdir / op_id).mkdir(parents=True, exist_ok=True)
    (tdir / rel).write_bytes(template)
    rows = rows if rows is not None else fresh_rows(op_id, at=fixture_at)
    if fixture_text is not None:
        fixture = fixture_text.encode()
    else:
        fixture = json.dumps(fixtures if fixtures is not None else [envelope(rows, fetched_at=fixture_at, raw_body=raw_body, op=op_id)]).encode()
    frel = f"{op_id}/{version}.fixture.json"
    (tdir / frel).write_bytes(fixture)
    contract_hosts = {
        "calendar.fed": ["www.federalreserve.gov"], "earnings.forward": ["finance.yahoo.com"], "senate.efd.ptr": ["efdsearch.senate.gov"],
        "cboe.daily.stats": ["www.cboe.com"], "cnn.fear_greed": ["www.cnn.com"],
    }[op_id]
    tos = {"calendar.fed": "fed-public-schedule-2026-10-09", "earnings.forward": "yahoo-finance-owner-review-2026-10-09",
           "senate.efd.ptr": "senate-efd-public-filings-2026-10-09", "cboe.daily.stats": "cboe-market-data-owner-review-2026-10-09",
           "cnn.fear_greed": "cnn-owner-review-2026-10-09"}[op_id]
    entry = {
        "version": version, "sha256": hashlib.sha256(template).hexdigest(), "template_path": rel,
        "allowed_hosts": hosts if hosts is not None else contract_hosts, "challenge_hosts": [],
        "tos_review_id": tos, "review_note": review_note,
        "fixture_path": frel, "fixture_sha256": hashlib.sha256(fixture).hexdigest(),
        "approved_at": iso(approved_at or (now() - timedelta(minutes=5))),
    }
    mapping = mapping_for(variant / "dist")[op_id]
    entry.update({
        "mapping_recipe": mapping["recipe"], "mapping_sha256": hashlib.sha256(stable_json(mapping["recipe"]).encode()).hexdigest(),
        "mapping_fixture_kind": "recorded-native-body" if op_id in RECORDED_REQUIRED else "hand-built-native-body",
        "fixture_origin": "recorded-live-response" if op_id in RECORDED_REQUIRED else "hand-built-test-fixture",
        "mapping_review_note": "acceptance fixture mapping review",
    })
    entry.update(mutate or {})
    reg_path = tdir / "PINNED.json"
    registry = json.loads(reg_path.read_text(encoding="utf-8"))
    registry["operations"][op_id] = entry
    reg_path.write_text(json.dumps(registry, indent=2), encoding="utf-8")
    seal_dist(variant / "dist", reg_path)
    entry["_rows"] = rows
    return entry


def read_registry(variant: Path) -> dict[str, Any]:
    return json.loads((variant / "templates" / "PINNED.json").read_text(encoding="utf-8"))


def set_tos(variant: Path, review_id: str, **changes: Any) -> None:
    path = variant / "templates" / "PINNED.json"
    registry = json.loads(path.read_text(encoding="utf-8"))
    if changes.get("_delete"):
        registry["tos_reviews"].pop(review_id, None)
    else:
        registry["tos_reviews"][review_id].update(changes)
    path.write_text(json.dumps(registry, indent=2), encoding="utf-8")
    registry_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    (variant / "dist" / "pin-hash.js").write_text(
        f'export const PIN_REGISTRY_SHA256 = "{registry_sha}";\n', encoding="utf-8"
    )


# --------------------------------------------------------------------------- fake internet

def default_world(op_id: str = "cnn.fear_greed", rows: list[dict[str, Any]] | None = None, robots: Any = "User-agent: *\nDisallow: /private/\n") -> dict[str, Any]:
    host = SITE_HOST[op_id]
    return {"hosts": {
        host: {"robots": robots, "routes": {FEED_PATH: {"status": 200, "json": native_body(op_id, rows if rows is not None else fresh_rows(op_id))}}},
        "evil.example": {"robots": None, "routes": {"/steal": {"status": 200, "json": {"data": []}}, "/x": {"status": 200, "json": {"data": []}}}},
    }}


class Sidecar1:
    """A real `node dist/main.js`, speaking NDJSON over stdio, with the fake internet preloaded."""

    def __init__(self, variant: Path, data_dir: Path, *, world: dict[str, Any] | None = None, extra_env: dict[str, str] | None = None,
                 node_args: tuple[str, ...] = (), no_net: bool = False) -> None:
        self.variant = variant
        self.data_dir = data_dir
        stem = data_dir.parent / f"{data_dir.name}"
        self.control = Path(str(stem) + "-stub-control.json")
        self.stub_log = Path(str(stem) + "-stub-log.jsonl")
        self.net = Path(str(stem) + "-fakenet.json")
        self.net_log = Path(str(stem) + "-fakenet-log.jsonl")
        self._epoch = 0
        self.set_control({})
        self.set_world(world or {"hosts": {}})
        self.stub_log.write_text("", encoding="utf-8")
        if not self.net_log.exists():
            self.net_log.write_text("", encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if not k.startswith("API_ANYTHING") and k != "AA_CONTROL"}
        env["LEVIATHAN_COLLECTOR_DATA"] = str(data_dir)
        env.update({"AA_STUB_CONTROL": str(self.control), "AA_STUB_LOG": str(self.stub_log), "AA_FAKENET": str(self.net), "AA_FAKENET_LOG": str(self.net_log)})
        env.update(extra_env or {})
        args = [NODE, *node_args]
        if not no_net:
            args += ["--import", FAKENET.as_uri()]
        self.proc = subprocess.Popen([*args, str(variant / "dist" / "main.js")], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, env=env)
        self.lines: queue.Queue[bytes | None] = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()
        threading.Thread(target=self._drain, daemon=True).start()
        self.stderr: list[bytes] = []

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        for line in iter(self.proc.stdout.readline, b""):
            self.lines.put(line)
        self.lines.put(None)

    def _drain(self) -> None:
        assert self.proc.stderr is not None
        for chunk in iter(lambda: self.proc.stderr.read(4096), b""):  # type: ignore[union-attr]
            self.stderr.append(chunk)

    def set_control(self, data: dict[str, Any]) -> None:
        self._epoch += 1
        self.control.write_text(json.dumps({**data, "epoch": self._epoch}), encoding="utf-8")

    def set_world(self, world: dict[str, Any]) -> None:
        self.net.write_text(json.dumps(world), encoding="utf-8")

    def send_raw(self, raw: bytes) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(raw)
        self.proc.stdin.flush()

    def read_line(self, timeout: float = 20.0) -> dict[str, Any] | None:
        try:
            raw = self.lines.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError(f"no sidecar output within {timeout}s") from None
        return None if raw is None else json.loads(raw)

    def exchange(self, message: dict[str, Any], timeout: float = 20.0) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        self.send_raw(json.dumps(message).encode() + b"\n")
        notes: list[dict[str, Any]] = []
        deadline = time.monotonic() + timeout
        while True:
            item = self.read_line(max(0.05, deadline - time.monotonic()))
            if item is None:
                raise EOFError("sidecar closed stdout")
            if item.get("type") == "notification":
                notes.append(item)
                continue
            return item, notes

    def call(self, op: str, args: dict[str, Any] | None = None, **kw: Any):
        return self.exchange({"method": "call", "request_id": str(uuid.uuid4()), "operation_id": op, "args": args if args is not None else A.VALID_ARGS[op]}, **kw)

    def repair(self, op: str, args: dict[str, Any] | None = None, **kw: Any):
        return self.exchange({"method": "repair", "request_id": str(uuid.uuid4()), "operation_id": op, "args": args if args is not None else A.VALID_ARGS[op]}, **kw)

    def learn(self, op: str, examples: list[dict[str, Any]] | None = None, **kw: Any):
        ex = examples if examples is not None else [A.VALID_ARGS[op], A.VALID_ARGS[op]]
        return self.exchange({"method": "learn", "request_id": str(uuid.uuid4()), "operation_id": op, "examples": ex}, **kw)

    def health(self, **kw: Any):
        return self.exchange({"method": "health", "request_id": str(uuid.uuid4())}, **kw)

    @staticmethod
    def _rows(path: Path) -> list[dict[str, Any]]:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def stub_events(self, ev: str | None = None) -> list[dict[str, Any]]:
        return [r for r in self._rows(self.stub_log) if ev is None or r["ev"] == ev]

    def requests(self) -> list[dict[str, Any]]:
        return self._rows(self.net_log)

    def non_robots_requests(self) -> list[dict[str, Any]]:
        return [r for r in self.requests() if not r["path"].startswith("/robots.txt")]

    def rate_state(self) -> dict[str, Any]:
        path = self.data_dir / "rate-state.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"operations": {}}

    def set_rate_state(self, state: dict[str, Any]) -> None:
        (self.data_dir / "rate-state.json").write_text(json.dumps(state), encoding="utf-8")

    def age_rate_state(self, op: str, seconds: int) -> None:
        """Pretend `seconds` have passed since the last send/success/learn/repair (no sleeping in tests)."""
        state = self.rate_state()
        entry = state["operations"].get(op, {})
        for key in ("last_send_at", "last_success_at", "last_learn_at", "last_repair_at"):
            if key in entry:
                entry[key] = iso(datetime.fromisoformat(entry[key].replace("Z", "+00:00")) - timedelta(seconds=seconds))
        if "backoff_until" in entry:
            entry["backoff_until"] = iso(datetime.fromisoformat(entry["backoff_until"].replace("Z", "+00:00")) - timedelta(seconds=seconds))
        state["operations"][op] = entry
        self.set_rate_state(state)

    def alive(self) -> bool:
        return self.proc.poll() is None

    def close(self) -> None:
        if self.proc.poll() is None:
            try:
                assert self.proc.stdin is not None
                self.proc.stdin.close()
            except OSError:
                pass
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        for stream in (self.proc.stdout, self.proc.stderr):
            if stream:
                stream.close()


sys.dont_write_bytecode = True


def load_templates():
    """api_anything_templates, or a scratch-mutated copy of it when AA_MUTANT targets it."""
    import importlib
    import importlib.util
    import tempfile

    name = "leviathan_market_data.public_sources.api_anything_templates"
    mutant = A.load_mutant()
    if not (mutant and mutant["target"] == "templates"):
        return importlib.import_module(name)
    original = importlib.import_module(name)
    scratch = Path(tempfile.mkdtemp(prefix="aa-templates-mutant-")) / "api_anything_templates.py"
    scratch.write_text(Path(original.__file__).read_text(encoding="utf-8"), encoding="utf-8")
    A.apply_mutation(scratch, mutant["find"], mutant["replace"])
    spec = importlib.util.spec_from_file_location(name, scratch)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def native_case(op_id: str, *, at: datetime | None = None, tag: str = "1", mutate: Any = None) -> dict[str, Any]:
    """A realistic NATIVE (site-shaped) JSON body for the operation and the strict contract rows its recipe must yield."""
    ref = at or _BASE
    t = ref - timedelta(hours=1)
    if op_id == "cnn.fear_greed":
        item = {"id": f"cnn-{tag}", "value": 55, "rating": "Greed", "timestamp": iso(t)}
        body = {"fear_and_greed_historical": {"data": [item]}, "fear_and_greed": {"score": 55}}
        rows = [{"value": 55, "label": "Greed", "observed_at": iso(t), "record_id": f"cnn-{tag}"}]
        items = body["fear_and_greed_historical"]["data"]
    elif op_id == "calendar.fed":
        item = {"id": f"fed-{tag}", "name": "FOMC meeting", "agency": "Federal Reserve Board", "date": iso(ref + timedelta(days=30)), "type": "meeting", "publishedAt": iso(t)}
        body = {"events": [item], "generatedAt": iso(ref)}
        rows = [{"event_name": "FOMC meeting", "agency": "Federal Reserve Board", "scheduled_at": item["date"], "release_type": "meeting", "record_id": item["id"], "published_at": item["publishedAt"]}]
        items = body["events"]
    elif op_id == "earnings.forward":
        item = {"id": f"earn-{tag}", "ticker": {"symbol": "AAPL"}, "quarter": "2026 Q4", "type": "earnings", "date": iso(ref + timedelta(days=20)), "status": "scheduled"}
        body = {"calendar": [item]}
        rows = [{"ticker": "AAPL", "fiscal_period": "2026 Q4", "event_type": "earnings", "scheduled_at": item["date"], "status": "scheduled", "record_id": item["id"]}]
        items = body["calendar"]
    elif op_id == "senate.efd.ptr":
        tx = {"ticker": "MSFT", "trade_date": iso(t - timedelta(days=3)), "transaction_type": "Purchase", "amount_range": "$1,001 - $15,000"}
        item = {"id": f"ptr-{tag}", "url": "https://efdsearch.senate.gov/search/report/0042", "filedAt": iso(t), "availableAt": iso(t), "transactions": [tx]}
        body = {"reports": [item]}
        rows = [{"report_url": item["url"], "filed_at": item["filedAt"], "transactions": [tx], "record_id": item["id"], "knowable_at": item["availableAt"]}]
        items = body["reports"]
    else:
        item = {"id": f"cboe-{tag}", "timestamp": iso(t), "name": "put_call_ratio", "value": 0.91, "unit": "ratio", "expiry": None}
        body = {"dailyStatistics": [item]}
        rows = [{"observed_at": iso(t), "metric": "put_call_ratio", "value": 0.91, "unit": "ratio", "maturity": None, "record_id": item["id"]}]
        items = body["dailyStatistics"]
    if mutate:
        mutate(body, items, rows)
    return {"body": body, "text": json.dumps(body), "rows": rows}
