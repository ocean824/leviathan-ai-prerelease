"""Rules 1 and 6: private stdio transport, bounded framing/lifetime/timeouts, allowlist,
and the no-learned-templates state (all five ops TEMPLATE_UNAVAILABLE, nothing crashes)."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

import aa_harness as H
import pytest
from conftest import client, registry, leviathan_market_data

OPS = list(H.SITES)


def test_imports_resolve_to_frozen_worktree() -> None:
    for module in (leviathan_market_data, client, registry):
        path = Path(module.__file__).resolve()
        assert H.WORKTREE in path.parents, f"{module.__name__} resolved outside worktree: {path}"
    if H.load_mutant() is None:
        assert Path(client.__file__).resolve() == H.CLIENT_SRC.resolve()


def test_allowlist_is_identical_in_node_python_and_registry(collector: Path, tmp_path: Path) -> None:
    probe = tmp_path / "keys.mjs"
    uri = (collector / "dist" / "contracts.js").as_uri()
    probe.write_text(
        f'import {{operationContracts as c}} from "{uri}";\n'
        "console.log(JSON.stringify(Object.keys(c)));\n",
        encoding="utf-8",
    )
    out = subprocess.run([H.NODE, str(probe)], capture_output=True, text=True, check=True, cwd=collector).stdout
    assert set(json.loads(out)) == set(OPS)
    assert set(client._INPUT_MODELS) == set(OPS)
    assert set(client._VALUE_MODELS) == set(OPS)
    assert {s.source_id for s in registry.PUBLIC_SOURCES} == {f"api_anything.{o}" for o in OPS}
    assert len(registry.PUBLIC_SOURCES) == 5


def test_health_and_no_listening_socket(v_real: Path, data_dir: Path, sidecar_factory) -> None:
    sc = sidecar_factory(v_real, data_dir)
    reply, notes = sc.health()
    assert reply["status"] == "OK" and reply["redistribution"] is False and notes == []
    assert H.open_sockets(sc.proc.pid) == [], "sidecar must not listen on any port"
    for op in OPS:
        sc.call(op, H.VALID_ARGS[op])
    assert H.open_sockets(sc.proc.pid) == []
    # a loopback port scan of the process tree is overkill; sockets table check above is the proof


def test_source_has_no_listener_or_network_server_primitives() -> None:
    src = H.COLLECTOR_SRC / "src"
    pat = re.compile(r"\.listen\(|createServer\(|node:net|node:http\b|node:https\b|node:dgram|WebSocketServer|--remote-debugging-port")
    for path in src.glob("*.ts"):
        if path.name.endswith(".test.ts"):
            continue
        assert not pat.search(path.read_text(encoding="utf-8")), path.name
    # vendor modules reachable from the wrapper's imports (execute/heal and their closure)
    vendor_src = H.COLLECTOR_SRC / "vendor" / "api-anything" / "src"
    for name in ("execute.ts", "heal.ts", "http.ts", "browser.ts", "session.ts", "store.ts"):
        text = (vendor_src / name).read_text(encoding="utf-8")
        assert not re.search(r"\.listen\(|node:net\b|createServer\(|--remote-debugging-port", text), name


@pytest.mark.parametrize("op", OPS)
def test_each_operation_reports_template_unavailable_without_crash(
    v_real: Path, data_dir: Path, sidecar_factory, op: str
) -> None:
    sc = sidecar_factory(v_real, data_dir)
    reply, notes = sc.call(op, H.VALID_ARGS[op])
    assert reply["error_code"] == "TEMPLATE_UNAVAILABLE"
    assert reply["status"] == "DEGRADED"
    assert reply["records"] == [] and reply["redistribution"] is False
    assert reply["source_tier"] == 3 and reply["operation_id"] == op
    assert reply["source_id"] == f"api_anything.{op}"
    assert notes == [] and sc.alive()
    assert sc.health()[0]["status"] == "OK"
    for method in ("repair",):
        r2, _ = sc.repair(op, H.VALID_ARGS[op])
        assert r2["error_code"] == "TEMPLATE_UNAVAILABLE" and r2["records"] == []
    assert not (data_dir / "template-registry.json").exists() or sc.registry()["active"] == {}


def test_all_five_via_typed_client_raise_template_unavailable(v_real: Path, data_dir: Path) -> None:
    sup = client.CollectorSupervisor(H.NODE, v_real / "dist" / "main.js", data_dir=data_dir)
    try:
        assert sup.health().status is client.OperationStatus.OK
        for op in OPS:
            with pytest.raises(client.PublicOperationError) as exc:
                sup.call(op, H.VALID_ARGS[op])
            assert exc.value.code is client.PublicOperationErrorCode.TEMPLATE_UNAVAILABLE
        assert sup._proc is not None and sup._proc.poll() is None
    finally:
        sup.close()


@pytest.mark.parametrize(
    "message",
    [
        {"method": "call", "operation_id": "unknown.site", "args": {}},
        {"method": "call", "operation_id": "cnn.fear_greed", "args": {"url": "https://evil.invalid"}},
        {"method": "call", "operation_id": "calendar.fed", "args": {"year": 2026, "url": "https://x.invalid"}},
        {"method": "call", "operation_id": "calendar.fed", "args": {"year": "2026"}},
        {"method": "call", "operation_id": "../../etc/passwd", "args": {}},
        {"method": "call", "operation_id": "calendar.fed"},
        {"method": "login", "operation_id": "cnn.fear_greed", "args": {}},
        {"method": "import", "operation_id": "cnn.fear_greed", "args": {}},
        {"method": "fetch", "url": "https://example.invalid"},
        {"method": "call", "operation_id": "cnn.fear_greed", "args": {}, "extra": 1},
        {"method": "learn", "operation_id": "calendar.fed", "examples": [{"year": 2026}]},
        {"method": "repair", "operation_id": "nope", "args": {}},
    ],
)
def test_non_allowlisted_or_malformed_requests_are_rejected(
    v_real: Path, data_dir: Path, sidecar_factory, message: dict
) -> None:
    sc = sidecar_factory(v_real, data_dir)
    message = {"request_id": str(uuid.uuid4()), **message}
    reply, _ = sc.exchange(message)
    assert reply["error_code"] == "SCHEMA_INVALID", reply
    assert reply["records"] == [] and reply["status"] == "DEGRADED"
    assert sc.alive() and sc.health()[0]["status"] == "OK"


def test_garbage_and_nonuuid_lines_do_not_kill_the_process(v_real: Path, data_dir: Path, sidecar_factory) -> None:
    sc = sidecar_factory(v_real, data_dir)
    for raw in (b"not json\n", b"[]\n", b'{"method":"health","request_id":"not-a-uuid"}\n', b"\x00\xff\xfe\n"):
        sc.send_raw(raw)
        reply = sc.read_line()
        assert reply is not None and reply["error_code"] == "SCHEMA_INVALID"
    assert sc.health()[0]["status"] == "OK"


def test_oversized_frame_is_rejected_and_stops_serving(v_real: Path, data_dir: Path, sidecar_factory) -> None:
    sc = sidecar_factory(v_real, data_dir)
    sc.send_raw(b'{"method":"health","request_id":"' + b"a" * 1_200_000 + b'"}' + bytes([10]))
    reply = sc.read_line()
    assert reply is not None and reply["error_code"] == "SCHEMA_INVALID"
    sc.send(  # after an oversize frame the stream is untrustworthy: no further service
        {"method": "health", "request_id": str(uuid.uuid4())}
    )
    try:
        again = sc.read_line(timeout=3)
    except TimeoutError:
        again = None
    assert again is None


@pytest.mark.xfail(reason="OBSERVATION (low): after an oversize frame the wrapper sets exitCode=1 and closes "
                   "readline but the process stays alive while the parent holds stdin open; "
                   "the Python supervisor kills it on the id-mismatch reply, so impact is nil today",
                   strict=False)
def test_finding_oversize_frame_process_exits_by_itself(v_real: Path, data_dir: Path, sidecar_factory) -> None:
    sc = sidecar_factory(v_real, data_dir)
    sc.send_raw(b'{"method":"health","request_id":"' + b"a" * 1_200_000 + b'"}' + bytes([10]))
    sc.read_line()
    sc.proc.wait(timeout=5)


@pytest.mark.xfail(reason="OBSERVATION (low): EarningsQueryV1.symbols has no per-symbol pattern, so malformed "
                   "tickers are sent to Node (which rejects them) instead of failing in the client; "
                   "design says the client validates exact input schemas", strict=False)
def test_finding_client_rejects_malformed_tickers_before_launch(tmp_path: Path) -> None:
    marker = tmp_path / "started.txt"
    script = _fake_child(tmp_path, f"open({str(marker)!r},'w').write('x')\n" + ECHO_HEALTH)
    sup = _sup(script, tmp_path)
    for bad in (["lower"], ["A" * 17], ["AAPL; DROP"]):
        with pytest.raises(client.PublicOperationError) as exc:
            sup.call("earnings.forward", {"symbols": bad})
        assert exc.value.code is client.PublicOperationErrorCode.SCHEMA_INVALID
    assert not marker.exists()


def test_sidecar_exits_when_parent_closes_stdin(v_real: Path, data_dir: Path, sidecar_factory) -> None:
    sc = sidecar_factory(v_real, data_dir)
    sc.health()
    sc.proc.stdin.close()
    sc.proc.wait(timeout=10)
    assert sc.proc.returncode == 0


def test_sidecar_refuses_to_start_without_app_data_dir(collector: Path, v_real: Path) -> None:
    import os

    env = {k: v for k, v in os.environ.items() if k != "LEVIATHAN_COLLECTOR_DATA"}
    done = subprocess.run([H.NODE, str(v_real / "dist" / "main.js")], input=b"", env=env, capture_output=True, timeout=20)
    assert done.returncode != 0


# ---- Python supervisor: framing, size bounds, lifetime, timeouts (fake child processes) ----

def _fake_child(tmp_path: Path, body: str) -> Path:
    script = tmp_path / "fake_sidecar.py"
    script.write_text("import sys,json,os,time\n" + body, encoding="utf-8")
    return script


ECHO_HEALTH = """
for line in sys.stdin.buffer:
    req = json.loads(line)
    print(json.dumps({"schema_version":1,"request_id":req["request_id"],"operation_id":None,"template_version":None,"source_id":None,"source_tier":None,"status":"OK","fetched_at":"2026-10-09T15:00:00Z","as_of":None,"knowable_at":None,"redistribution":False,"records":[]}), flush=True)
"""


def _sup(script: Path, tmp_path: Path, timeout_s: float = 150.0):
    return client.CollectorSupervisor(sys.executable, script, data_dir=tmp_path / "d", timeout_s=timeout_s)


def test_python_timeout_is_enforced_and_child_is_killed(tmp_path: Path) -> None:
    sup = _sup(_fake_child(tmp_path, "time.sleep(60)\n"), tmp_path, timeout_s=0.7)
    t0 = time.monotonic()
    with pytest.raises(client.PublicOperationError) as exc:
        sup.health()
    assert time.monotonic() - t0 < 5
    assert exc.value.code is client.PublicOperationErrorCode.COLLECTOR_UNAVAILABLE
    assert sup._proc is None


def test_timeout_bounds_are_validated() -> None:
    for bad in (0, -1, 181):
        with pytest.raises(ValueError):
            client.CollectorSupervisor("node", "x.js", data_dir="d", timeout_s=bad)
    assert client.CALL_TIMEOUT_SECONDS <= 180 and client.MAX_PROCESS_LIFETIME_SECONDS <= 900


def test_process_lifetime_is_bounded_and_restarted(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(client, "MAX_PROCESS_LIFETIME_SECONDS", 0.3)
    sup = _sup(_fake_child(tmp_path, ECHO_HEALTH), tmp_path)
    try:
        sup.health()
        first = sup._proc
        assert first is not None
        time.sleep(0.5)
        sup.health()
        assert sup._proc is not first
        assert first.poll() is not None, "expired child must be terminated, not leaked"
    finally:
        sup.close()


def test_oversized_reply_line_is_schema_invalid(tmp_path: Path) -> None:
    body = "sys.stdin.readline()\nsys.stdout.buffer.write(b'x'*1_200_000+b'\\n'); sys.stdout.flush(); time.sleep(5)\n"
    sup = _sup(_fake_child(tmp_path, body), tmp_path, timeout_s=10)
    with pytest.raises(client.PublicOperationError) as exc:
        sup.health()
    assert exc.value.code is client.PublicOperationErrorCode.SCHEMA_INVALID
    assert sup._proc is None


@pytest.mark.parametrize("payload", ["not json", "[]", '{"schema_version":1}', "{}"])
def test_malformed_reply_fails_closed(tmp_path: Path, payload: str) -> None:
    body = f"sys.stdin.readline()\nprint({payload!r}, flush=True); time.sleep(5)\n"
    sup = _sup(_fake_child(tmp_path, body), tmp_path, timeout_s=10)
    with pytest.raises(client.PublicOperationError) as exc:
        sup.health()
    assert exc.value.code is client.PublicOperationErrorCode.SCHEMA_INVALID


def test_reply_with_wrong_request_id_is_rejected(tmp_path: Path) -> None:
    body = ECHO_HEALTH.replace('req["request_id"]', '"95c8cf46-15bc-4509-9961-59d6dbe44144"')
    sup = _sup(_fake_child(tmp_path, body), tmp_path, timeout_s=10)
    with pytest.raises(client.PublicOperationError) as exc:
        sup.health()
    assert exc.value.code is client.PublicOperationErrorCode.SCHEMA_INVALID


def test_child_exit_and_missing_node_are_collector_unavailable(tmp_path: Path) -> None:
    sup = _sup(_fake_child(tmp_path, "sys.stdin.readline()\nsys.exit(3)\n"), tmp_path, timeout_s=10)
    with pytest.raises(client.PublicOperationError) as exc:
        sup.health()
    assert exc.value.code is client.PublicOperationErrorCode.COLLECTOR_UNAVAILABLE
    sup2 = client.CollectorSupervisor(tmp_path / "no-such-node.exe", "x.js", data_dir=tmp_path / "d")
    with pytest.raises(client.PublicOperationError) as exc2:
        sup2.health()
    assert exc2.value.code is client.PublicOperationErrorCode.COLLECTOR_UNAVAILABLE


def test_client_allowlist_blocks_before_any_process_is_started(tmp_path: Path) -> None:
    marker = tmp_path / "started.txt"
    script = _fake_child(tmp_path, f"open({str(marker)!r},'w').write('x')\n" + ECHO_HEALTH)
    sup = _sup(script, tmp_path)
    cases = [
        ("unknown.site", {}),
        ("calendar.fed", {"year": 2026, "url": "https://evil.invalid"}),
        ("calendar.fed", {"year": 1999}),
        ("calendar.fed", {"year": "2026"}),
        ("earnings.forward", {"symbols": []}),
        ("cboe.daily.stats", {"date": "2026-13-45"}),
        ("senate.efd.ptr", {"page": 11}),
        ("cnn.fear_greed", {"x": 1}),
    ]
    for op, args in cases:
        for method in (sup.call, sup.repair):
            with pytest.raises(client.PublicOperationError) as exc:
                method(op, args)  # type: ignore[arg-type]
            assert exc.value.code is client.PublicOperationErrorCode.SCHEMA_INVALID, (op, args)
    with pytest.raises(client.PublicOperationError):
        sup.learn("nope.op", ({}, {}))
    assert not marker.exists() and sup._proc is None


def test_request_frame_is_size_bounded_before_launch(tmp_path: Path) -> None:
    sup = _sup(_fake_child(tmp_path, ECHO_HEALTH), tmp_path)
    with pytest.raises(client.PublicOperationError) as exc:
        sup._request("call", "cnn.fear_greed", {"x": "a" * 2_000_000})
    assert exc.value.code is client.PublicOperationErrorCode.SCHEMA_INVALID
    assert sup._proc is None


def test_child_is_started_without_shell_and_with_pipes(tmp_path: Path) -> None:
    sup = _sup(_fake_child(tmp_path, ECHO_HEALTH), tmp_path)
    try:
        sup.health()
        assert sup._proc is not None and not isinstance(sup._proc.args, str)
        assert sup._proc.stdin is not None and sup._proc.stdout is not None
    finally:
        sup.close()
