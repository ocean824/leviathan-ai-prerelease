"""Acceptance harness for API-ANYTHING-001 (independent tester; fakes and fixtures only).

Nothing here contacts a live site.  The sidecar under test is compiled from the frozen
worktree's own TypeScript sources into a scratch directory (the frozen tree stays pristine), then
run as a real child process over stdio.  Vendor behaviour is either the real vendored api-anything
pointed at a loopback fake server, or a stub vendor controlled by a JSON control file.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import re
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
TEST_VARIANT: Path | None = None
TEST_VARIANTS: dict[Path, Path] = {}
WORKTREE = HERE.parents[2]  # qa/acceptance/API-ANYTHING-001 -> worktree root
COLLECTOR_SRC = WORKTREE / "services" / "public-collector"
CLIENT_SRC = (
    WORKTREE
    / "packages"
    / "leviathan-market-data"
    / "src"
    / "leviathan_market_data"
    / "public_sources"
    / "api_anything_client.py"
)
NIL_UUID = "00000000-0000-4000-8000-000000000000"


def _tooling_root() -> Path:
    """Where node_modules (installed deps) live; the frozen snapshot ships none."""
    explicit = os.environ.get("AA_TOOLING_ROOT")
    candidates = [Path(explicit)] if explicit else []
    candidates += [WORKTREE, WORKTREE.parent / "api-anything-001"]
    for candidate in candidates:
        if (candidate / "services" / "public-collector" / "node_modules" / "zod").is_dir():
            return candidate
    raise RuntimeError("no installed node_modules found; set AA_TOOLING_ROOT")


TOOLING = _tooling_root()
TOOLING_NM = TOOLING / "services" / "public-collector" / "node_modules"
NODE = shutil.which("node") or "node"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def link_dir(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
    else:
        os.symlink(target, link, target_is_directory=True)


def _run(cmd: list[str], cwd: Path | None = None) -> None:
    done = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=300)
    if done.returncode != 0:
        raise RuntimeError(f"command failed {cmd}\n{done.stdout}\n{done.stderr}")


def load_mutant() -> dict[str, str] | None:
    path = os.environ.get("AA_MUTANT")
    if not path:
        return None
    return json.loads(Path(path).read_text(encoding="utf-8"))


def apply_mutation(file: Path, find: str, replace: str) -> None:
    text = file.read_text(encoding="utf-8")
    if find not in text:
        raise RuntimeError(f"MUTANT_NOT_APPLICABLE: {find!r} not in {file.name}")
    file.write_text(text.replace(find, replace, 1), encoding="utf-8")


def build_collector(scratch: Path) -> Path:
    """Copy frozen sources to scratch, build vendor + wrapper there, apply any mutant."""
    dst = scratch / "collector"
    shutil.copytree(
        COLLECTOR_SRC, dst, ignore=shutil.ignore_patterns("node_modules", "dist", ".git")
    )
    link_dir(dst / "node_modules", TOOLING_NM)
    tsc = TOOLING_NM / "typescript" / "bin" / "tsc"
    _run([NODE, str(tsc), "-p", str(dst / "vendor" / "api-anything" / "tsconfig.build.json")])
    _run([NODE, str(tsc), "-p", str(dst / "tsconfig.json")])
    mutant = load_mutant()
    if mutant and mutant["target"] in {"main", "challenge", "canary", "contracts"}:
        apply_mutation(
            dst / "dist" / f"{mutant['target']}.js", mutant["find"], mutant["replace"]
        )
    return dst


STUB_EXECUTE = r"""
import { appendFileSync, readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
const state = {};
const control = () => JSON.parse(readFileSync(process.env.AA_TEST_CONTROL, "utf8"));
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
  appendFileSync(process.env.AA_LOG, JSON.stringify({
    ev: kind, site, op, args, maxTier: opts?.maxTier, minIntervalMs: opts?.minIntervalMs,
    home: process.env.API_ANYTHING_HOME, site_sha: siteSha(site),
  }) + "\n");
  const spec = next(kind);
  if (spec.delay_ms) await new Promise((r) => setTimeout(r, spec.delay_ms));
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
  appendFileSync(process.env.AA_LOG, JSON.stringify({
    ev: "learn", site: opts.site, op: opts.op, trigger: opts.trigger, examples: opts.examples,
    home: process.env.API_ANYTHING_HOME,
  }) + "\n");
  const c = JSON.parse(readFileSync(process.env.AA_TEST_CONTROL, "utf8"));
  if (st.epoch !== c.epoch) { st.epoch = c.epoch; st.i = 0; }
  const spec = c.learn[Math.min(st.i, c.learn.length - 1)];
  st.i += 1;
  if (spec.throw) {
    const error = new Error(spec.throw);
    if (/captcha|challenge/i.test(spec.throw)) error.challenge = true;
    throw error;
  }
  mkdirSync(join(process.env.API_ANYTHING_HOME, "sites"), { recursive: true });
  writeFileSync(join(process.env.API_ANYTHING_HOME, "sites", opts.site + ".json"), spec.write_site);
}
"""

FAKE_CHALLENGE = r"""
import { appendFileSync, readFileSync } from "node:fs";
export async function waitForHumanChallenge(profileDir, url, notify, open, timeoutMs) {
  appendFileSync(process.env.AA_LOG, JSON.stringify({ ev: "challenge", profileDir, url, timeoutMs }) + "\n");
  const c = JSON.parse(readFileSync(process.env.AA_TEST_CONTROL, "utf8"));
  notify();
  return c.challenge_outcome;
}
export const openVisibleChallenge = async () => { throw new Error("not available in fake"); };
"""


def make_variant(collector: Path, name: str, *, vendor: str, challenge: str) -> Path:
    """vendor: 'real' | 'stub'; challenge: 'real' | 'fake'."""
    global TEST_VARIANT
    root = collector.parent / f"h-{name}"
    TEST_VARIANT = root
    shutil.copytree(collector / "dist", root / "dist")
    shutil.copytree(collector / "templates", root / "templates")
    (root / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    link_dir(root / "node_modules", collector / "node_modules")
    if vendor == "real":
        link_dir(root / "vendor", collector / "vendor")
    else:
        vdist = root / "vendor" / "api-anything" / "dist"
        vdist.mkdir(parents=True)
        (root / "vendor" / "api-anything" / "package.json").write_text(
            '{"type":"module"}', encoding="utf-8"
        )
        (vdist / "execute.js").write_text(STUB_EXECUTE, encoding="utf-8")
        (vdist / "heal.js").write_text(STUB_HEAL, encoding="utf-8")
    if challenge == "fake":
        (root / "dist" / "challenge.js").write_text(FAKE_CHALLENGE, encoding="utf-8")
    return root


class Sidecar:
    """A real `node dist/main.js` child spoken to over NDJSON on stdio."""

    def __init__(
        self,
        variant: Path,
        data_dir: Path,
        *,
        extra_env: dict[str, str] | None = None,
        node_args: tuple[str, ...] = (),
    ) -> None:
        self.data_dir = data_dir
        TEST_VARIANTS[data_dir.resolve()] = variant
        self.control = data_dir.parent / f"{data_dir.name}-control.json"
        self.log = data_dir.parent / f"{data_dir.name}-log.jsonl"
        env = {k: v for k, v in os.environ.items() if not k.startswith("API_ANYTHING")}
        env["LEVIATHAN_COLLECTOR_DATA"] = str(data_dir)
        env["AA_TEST_CONTROL"] = str(self.control)
        env["AA_LOG"] = str(self.log)
        env.update(extra_env or {})
        self.set_control({})
        self.log.write_text("", encoding="utf-8")
        test_args = node_args or ("--import", (HERE / "offline-injection.mjs").as_uri())
        self.proc = subprocess.Popen(
            [NODE, *test_args, str(variant / "dist" / "main.js")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.lines: queue.Queue[bytes | None] = queue.Queue()
        self.stderr_chunks: list[bytes] = []
        threading.Thread(target=self._pump, daemon=True).start()
        threading.Thread(target=self._pump_err, daemon=True).start()
        self._epoch = 0

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        for line in iter(self.proc.stdout.readline, b""):
            self.lines.put(line)
        self.lines.put(None)

    def _pump_err(self) -> None:
        assert self.proc.stderr is not None
        for chunk in iter(lambda: self.proc.stderr.read(4096), b""):  # type: ignore[union-attr]
            self.stderr_chunks.append(chunk)

    def set_control(self, data: dict[str, Any]) -> None:
        self._epoch = getattr(self, "_epoch", 0) + 1
        data = {**data, "epoch": self._epoch}
        self.control.write_text(json.dumps(data), encoding="utf-8")

    def send_raw(self, raw: bytes) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(raw)
        self.proc.stdin.flush()

    def send(self, message: dict[str, Any]) -> str:
        self.send_raw(json.dumps(message).encode() + b"\n")
        return str(message.get("request_id"))

    def read_line(self, timeout: float = 20.0) -> dict[str, Any] | None:
        try:
            raw = self.lines.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError(f"no sidecar output within {timeout}s") from None
        return None if raw is None else json.loads(raw)

    def exchange(
        self, message: dict[str, Any], timeout: float = 20.0
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Send one request; return (reply, notifications emitted before the reply)."""
        self.send(message)
        notes: list[dict[str, Any]] = []
        deadline = time.monotonic() + timeout
        while True:
            item = self.read_line(max(0.05, deadline - time.monotonic()))
            if item is None:
                details = b"".join(self.stderr_chunks).decode("utf-8", errors="replace")
                raise EOFError(f"sidecar closed stdout: {details}")
            if item.get("type") == "notification":
                notes.append(item)
                continue
            return item, notes

    def call(self, op: str, args: dict[str, Any], **kw: Any):
        return self.exchange(
            {"method": "call", "request_id": str(uuid.uuid4()), "operation_id": op, "args": args},
            **kw,
        )

    def repair(self, op: str, args: dict[str, Any], **kw: Any):
        return self.exchange(
            {"method": "repair", "request_id": str(uuid.uuid4()), "operation_id": op, "args": args},
            **kw,
        )

    def learn(self, op: str, examples: list[dict[str, Any]], **kw: Any):
        return self.exchange(
            {
                "method": "learn",
                "request_id": str(uuid.uuid4()),
                "operation_id": op,
                "examples": examples,
            },
            **kw,
        )

    def health(self, **kw: Any):
        return self.exchange({"method": "health", "request_id": str(uuid.uuid4())}, **kw)

    def log_events(self, ev: str | None = None) -> list[dict[str, Any]]:
        rows = [
            json.loads(line)
            for line in self.log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        return [r for r in rows if ev is None or r["ev"] == ev]

    def registry(self) -> dict[str, Any]:
        path = self.data_dir / "template-registry.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

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


def open_sockets(pid: int) -> list[str]:
    """Listening TCP sockets or any UDP endpoint owned by pid (empty list == none)."""
    found: list[str] = []
    if os.name == "nt":
        out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
        for line in out.splitlines():
            parts = line.split()
            if not parts or parts[-1] != str(pid):
                continue
            if parts[0] == "UDP" or (parts[0] == "TCP" and "LISTENING" in parts):
                found.append(line.strip())
    else:  # pragma: no cover - Windows host here
        out = subprocess.run(
            ["lsof", "-nP", "-a", "-p", str(pid), "-i"], capture_output=True, text=True
        ).stdout
        found = [ln for ln in out.splitlines()[1:] if "LISTEN" in ln or "UDP" in ln]
    return found


def plant_template(data_dir: Path, site: str, template: bytes, op_id: str, *, variant: Path | None = None) -> dict[str, str]:
    """Test-only injection into a temporary variant's production-shaped PINNED registry."""
    target_variant = variant or TEST_VARIANTS.get(data_dir.resolve()) or TEST_VARIANT
    if target_variant is None:
        raise RuntimeError("test variant must be constructed before pin injection")
    version = "planted-1"
    rel = f"{op_id}/{version}.json"
    template_root = target_variant / "templates"
    path = template_root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(template)
    now = datetime.now(UTC)
    day_ago = (now - timedelta(days=1)).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def stamp_days(days: int) -> str:
        return (now + timedelta(days=days)).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    rows = {
        "calendar.fed": [{"event_name": "FOMC", "agency": "FRB", "scheduled_at": stamp_days(30), "release_type": "meeting"}],
        "earnings.forward": [{"ticker": "AAPL", "fiscal_period": "Q4", "event_type": "earnings", "scheduled_at": stamp_days(20), "status": "confirmed"}],
        "senate.efd.ptr": [{"report_url": "https://efdsearch.senate.gov/search/view/ptr/fixture/", "filed_at": day_ago, "transactions": [{"ticker": "MSFT", "trade_date": day_ago, "transaction_type": "Purchase", "amount_range": "$1,001 - $15,000"}]}],
        "cboe.daily.stats": [{"observed_at": day_ago, "metric": "put_call_ratio", "value": 0.87, "unit": "ratio", "maturity": None}],
        "cnn.fear_greed": [{"value": 55, "label": "Greed", "observed_at": day_ago}],
    }[op_id]
    fixture_rel = f"{op_id}/{version}.fixture.json"
    fetched_at = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    fixture_rows = [
        {
            "fetched_at": fetched_at,
            "raw_body": json.dumps({"data": rows}),
            "content_type": "application/json",
            "rows": rows,
        }
    ]
    fixture = json.dumps(fixture_rows).encode()
    (template_root / fixture_rel).write_bytes(fixture)
    registry_path = template_root / "PINNED.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    mapping_recipes = {
        "calendar.fed": {"format": "json", "extract": "events", "pick": ["event_name=name", "agency=agency", "scheduled_at=date", "release_type=type", "record_id=id", "published_at=publishedAt"]},
        "earnings.forward": {"format": "json", "extract": "calendar", "pick": ["ticker=ticker.symbol", "fiscal_period=quarter", "event_type=type", "scheduled_at=date", "status=status", "record_id=id"]},
        "senate.efd.ptr": {"format": "json", "extract": "reports", "pick": ["report_url=url", "filed_at=filedAt", "transactions=transactions", "record_id=id", "knowable_at=availableAt"]},
        "cboe.daily.stats": {"format": "json", "extract": "dailyStatistics", "pick": ["observed_at=timestamp", "metric=name", "value=value", "unit=unit", "maturity=expiry", "record_id=id"]},
        "cnn.fear_greed": {"format": "json", "extract": "fear_and_greed_historical.data", "pick": ["value=value", "label=rating", "observed_at=timestamp", "record_id=id"]},
    }
    mapping_recipe = mapping_recipes[op_id]
    entry = {
        "version": version,
        "sha256": hashlib.sha256(template).hexdigest(),
        "template_path": rel,
        "allowed_hosts": {
            "calendar.fed": ["www.federalreserve.gov"], "earnings.forward": ["finance.yahoo.com"],
            "senate.efd.ptr": ["efdsearch.senate.gov"], "cboe.daily.stats": ["www.cboe.com"], "cnn.fear_greed": ["www.cnn.com"],
        }[op_id],
        "challenge_hosts": [],
        "tos_review_id": {
            "calendar.fed": "fed-public-schedule-2026-10-09", "earnings.forward": "yahoo-finance-owner-review-2026-10-09",
            "senate.efd.ptr": "senate-efd-public-filings-2026-10-09", "cboe.daily.stats": "cboe-market-data-owner-review-2026-10-09",
            "cnn.fear_greed": "cnn-owner-review-2026-10-09",
        }[op_id],
        "review_note": "Temporary acceptance fixture pin.",
        "fixture_path": fixture_rel,
        "fixture_sha256": hashlib.sha256(fixture).hexdigest(),
        "approved_at": day_ago,
        "mapping_recipe": mapping_recipe,
        "mapping_sha256": hashlib.sha256(json.dumps(mapping_recipe, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
    }
    registry["operations"][op_id] = entry
    registry_path.write_text(json.dumps(registry, indent=2), encoding="utf-8")
    registry_sha = hashlib.sha256(registry_path.read_bytes()).hexdigest()
    (target_variant / "dist" / "pin-hash.js").write_text(
        f'export const PIN_REGISTRY_SHA256 = "{registry_sha}";\n', encoding="utf-8"
    )
    return entry


SITES = {
    "calendar.fed": "fed-calendar",
    "earnings.forward": "earnings-calendar",
    "senate.efd.ptr": "senate-efd",
    "cboe.daily.stats": "cboe-market-stats",
    "cnn.fear_greed": "cnn-fear-greed",
}
VALID_ARGS: dict[str, dict[str, Any]] = {
    "calendar.fed": {"year": 2026},
    "earnings.forward": {"symbols": ["AAPL"]},
    "senate.efd.ptr": {"page": 1},
    "cboe.daily.stats": {"date": "2026-10-08"},
    "cnn.fear_greed": {},
}
FORBIDDEN = re.compile(
    r"2captcha|capsolver|anti-?captcha|deathbycaptcha|(?<![a-z])solver|stealth|AutomationControlled|"
    r"navigator\.webdriver|webdriver|fingerprint|spoof|undetected|puppeteer-extra|"
    r"cf_clearance|flaresolverr|curl[-_]impersonate|ja3",
    re.IGNORECASE,
)

sys.dont_write_bytecode = True
