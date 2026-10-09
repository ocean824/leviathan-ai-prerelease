from __future__ import annotations

import datetime as dt
import hashlib
import importlib
import json
import re
import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from starlette.requests import Request

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
for package in ("leviathan-core", "leviathan-store", "leviathan-vault"):
    package_source = ROOT / "packages" / package / "src"
    if package_source.is_dir():
        sys.path.insert(0, str(package_source))


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8-sig")


def _decoded_candidates(raw: bytes) -> list[str]:
    if raw.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        encodings = ("utf-32", "utf-16-le", "utf-16-be")
    elif raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        encodings = ("utf-16", "utf-16-le", "utf-16-be")
    elif b"\x00" in raw:
        encodings = ("utf-8-sig", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be")
    else:
        encodings = ("utf-8-sig",)

    decoded: list[str] = []
    for encoding in encodings:
        try:
            decoded.append(raw.decode(encoding).replace("\x00", "").casefold())
        except UnicodeDecodeError:
            continue
    return decoded


def test_native_updater_plugins_are_exactly_pinned_and_registered() -> None:
    cargo = tomllib.loads(_text("apps/desktop/src-tauri/Cargo.toml"))
    dependencies = cargo["dependencies"]
    for name in ("tauri-plugin-updater", "tauri-plugin-process"):
        value = dependencies[name]
        version = value["version"] if isinstance(value, dict) else value
        assert isinstance(version, str) and re.fullmatch(r"=\d+\.\d+\.\d+", version)

    main = _text("apps/desktop/src-tauri/src/main.rs")
    assert ".plugin(tauri_plugin_updater::Builder::new().build())" in main
    assert ".plugin(tauri_plugin_process::init())" in main


def test_native_config_injects_only_the_public_key_and_shipped_feed() -> None:
    config = json.loads(_text("apps/desktop/src-tauri/tauri.conf.json"))
    build = _text("apps/desktop/scripts/build.ps1")
    public_key_lines = [
        line.strip()
        for line in _text("infra/release/updater.pub").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    public_key = "\n".join(public_key_lines)
    feed = json.loads(_text("infra/release/feed.json"))
    feed_base = feed.get("base", feed.get("base_url", feed.get("baseUrl")))

    assert public_key
    assert feed_base == "https://leviathan-release-feed.ocean824.workers.dev"
    assert "updater.pub" in build
    assert "feed.json" in build
    assert "--config" in build
    assert (
        "leviathan-release-feed.ocean824.workers.dev"
        in json.dumps(config) + build + json.dumps(feed)
    )
    assert config["plugins"]["updater"]["pubkey"] == public_key
    assert config["plugins"]["updater"]["endpoints"] == [feed_base + feed["endpoint"]]
    assert re.search(r"(?i)pubkey\s*=\s*\$publicKey", build)
    assert re.search(r"(?i)endpoints\s*=\s*@\(\$endpoint\)", build)
    assert re.search(r"(?i)\$endpoint\s*=\s*\$feedConfig\.base.*\$feedConfig\.endpoint", build)
    assert re.search(
        r"(?i)\$signingEnabled\s*=\s*-not\s+\[string\]::IsNullOrWhiteSpace\(\$env:TAURI_SIGNING_PRIVATE_KEY\)",
        build,
    )
    assert re.search(r"(?i)createUpdaterArtifacts\s*=\s*\$signingEnabled", build)


def test_repository_has_no_private_signing_key_material() -> None:
    private_headers = (
        "untrusted " + "comment: " + "rustsign",
        "untrusted " + "comment: minisign " + "secret key",
        "untrusted " + "comment: minisign " + "private key",
    )
    key_assignment = "TAURI_SIGNING_" + "PRIVATE_KEY="
    excluded = {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "node_modules",
        ".venv",
        "target",
        "dist",
        "build",
        "__pycache__",
    }
    findings: list[str] = []

    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in excluded for part in path.parts):
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        decoded = _decoded_candidates(raw)
        if any(
            key_assignment.casefold() in content
            or any(header.casefold() in content for header in private_headers)
            for content in decoded
        ):
            findings.append(path.relative_to(ROOT).as_posix())

    assert findings == []


def _feed_writer():
    return importlib.import_module("infra.release.feed_manifest").write_latest_manifest


def _write_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    # Opaque inert fixture: never executed or opened as an installer.
    (bundle / "synthetic-update.nsis.zip").write_bytes(b"synthetic updater bundle fixture")
    return bundle


def _write_latest(
    bundle: Path,
    *,
    version: str,
    signature: str | None = "synthetic-signature",
    require_signature: bool = False,
    prior_latest: Path | None = None,
    base_url: str = "https://releases.invalid",
) -> Path:
    return _feed_writer()(
        bundle_dir=bundle,
        base_url=base_url,
        version=version,
        notes="synthetic acceptance fixture",
        pub_date=dt.datetime(2026, 10, 6, 12, 0, tzinfo=dt.UTC),
        signature=signature,
        require_signature=require_signature,
        prior_latest=prior_latest,
    )


def test_feed_writer_emits_deterministic_schema_and_contained_url(tmp_path: Path) -> None:
    bundle = _write_bundle(tmp_path)
    first = _write_latest(bundle, version="1.2.3")
    first_bytes = first.read_bytes()
    first_digest = hashlib.sha256(first_bytes).hexdigest()

    second = _write_latest(bundle, version="1.2.3")
    assert second == first
    assert second.read_bytes() == first_bytes
    assert hashlib.sha256(second.read_bytes()).hexdigest() == first_digest

    manifest = json.loads(first_bytes)
    assert manifest["version"] == "1.2.3"
    assert manifest["notes"] == "synthetic acceptance fixture"
    assert manifest["pub_date"] == "2026-10-06T12:00:00Z"
    platform = manifest["platforms"]["windows-x86_64"]
    assert platform["signature"] == "synthetic-signature"
    assert platform["url"].startswith(
        "https://releases.invalid/v1/updates/desktop/windows/x86_64/1.2.3/"
    )
    parsed_url = urlsplit(platform["url"])
    assert parsed_url.scheme == "https"
    assert parsed_url.netloc == "releases.invalid"


def test_feed_writer_keeps_generated_url_under_configured_base_path(tmp_path: Path) -> None:
    url = json.loads(
        _write_latest(
            _write_bundle(tmp_path),
            version="1.2.3",
            base_url="https://releases.invalid/allowed",
        ).read_text(encoding="utf-8")
    )["platforms"]["windows-x86_64"]["url"]
    assert url.startswith("https://releases.invalid/allowed/")
    assert urlsplit(url).netloc == "releases.invalid"


@pytest.mark.parametrize("base_url", ["http://releases.invalid", "https://user@releases.invalid"])
def test_feed_writer_rejects_non_https_or_credentialed_base(tmp_path: Path, base_url: str) -> None:
    with pytest.raises(ValueError):
        _write_latest(_write_bundle(tmp_path), version="1.2.4", base_url=base_url)


@pytest.mark.parametrize(
    ("version", "prior_version"),
    [
        ("1.2.3", "1.2.3"),
        ("1.2.2", "1.2.3"),
        ("1.2.3+build.2", "1.2.3+build.1"),
        ("1.2.3-rc.1", "1.2.3-rc.2"),
        ("1.2.3-rc.2", "1.2.3-rc.alpha"),
        ("1.2.3-rc.alpha", "1.2.3-rc.beta"),
        ("1.2.3-rc", "1.2.3-rc.1"),
    ],
)
def test_feed_writer_refuses_equal_or_older_prior_version(
    tmp_path: Path, version: str, prior_version: str
) -> None:
    bundle = _write_bundle(tmp_path)
    prior = tmp_path / "prior-latest.json"
    prior.write_text(json.dumps({"version": prior_version}), encoding="utf-8")
    with pytest.raises(ValueError):
        _write_latest(bundle, version=version, prior_latest=prior)


@pytest.mark.parametrize(
    "version",
    ["01.2.3", "1.2.3-alpha..beta", "1.2.3-alpha.", "1.2.3+build..2"],
)
def test_feed_writer_rejects_malformed_semver(tmp_path: Path, version: str) -> None:
    with pytest.raises(ValueError):
        _write_latest(_write_bundle(tmp_path), version=version)


def test_feed_writer_allows_prerelease_to_release_transition(tmp_path: Path) -> None:
    prior = tmp_path / "prior-latest.json"
    prior.write_text(json.dumps({"version": "1.2.3-rc.2"}), encoding="utf-8")
    manifest = json.loads(
        _write_latest(_write_bundle(tmp_path), version="1.2.3", prior_latest=prior).read_text(
            encoding="utf-8"
        )
    )
    assert manifest["version"] == "1.2.3"


@pytest.mark.parametrize(
    ("version", "prior_version"),
    [
        ("1.2.3-rc.3", "1.2.3-rc.2"),
        ("1.2.3-rc.beta", "1.2.3-rc.alpha"),
        ("1.2.3-rc.alpha", "1.2.3-rc.2"),
    ],
)
def test_feed_writer_allows_strictly_newer_prerelease(
    tmp_path: Path, version: str, prior_version: str
) -> None:
    prior = tmp_path / "prior-latest.json"
    prior.write_text(json.dumps({"version": prior_version}), encoding="utf-8")
    manifest = json.loads(
        _write_latest(_write_bundle(tmp_path), version=version, prior_latest=prior).read_text(
            encoding="utf-8"
        )
    )
    assert manifest["version"] == version


def test_feed_writer_requires_signature_when_requested(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        _write_latest(
            _write_bundle(tmp_path), version="1.2.4", signature=None, require_signature=True
        )


def test_feed_cli_requires_signature_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    feed_manifest = importlib.import_module("infra.release.feed_manifest")
    bundle = _write_bundle(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "feed_manifest.py",
            "--bundle-dir",
            str(bundle),
            "--feed",
            str(ROOT / "infra/release/feed.json"),
            "--version",
            "1.2.4",
            "--pub-date",
            "2026-10-06T12:00:00Z",
            "--require-signature",
        ],
    )
    with pytest.raises(SystemExit) as error:
        feed_manifest._cli()
    assert error.value.code == 2
    assert "a signature is required" in capsys.readouterr().err
    assert not (bundle / "latest.json").exists()


def test_rust_update_policy_has_downgrade_refusal_unit_case() -> None:
    source = _text("apps/desktop/src-tauri/src/update_policy.rs")
    assert "fn accepts_strictly_newer_semver_only()" in source
    assert "Ok(candidate > current)" in source
    assert re.search(r'strictly_newer\("1\.2\.4",\s*"1\.2\.3"\),\s*Ok\(false\)', source)
    assert "strictly_newer" in source


def test_readiness_helper_fails_closed_for_each_unsafe_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "apps/desktop/sidecar"))
    # The generated build constant is supplied by the native packaging step;
    # stub only that import so acceptance stays source/unit-level.
    monkeypatch.setitem(sys.modules, "build_constants", SimpleNamespace(RISK_LOCK_SHA256="0" * 64))
    sidecar = importlib.import_module("leviathan_desktop")
    helper = sidecar.update_readiness

    assert helper(live_session_active=False, open_paper_orders=False, halt_pending=False) == {
        "safe": True,
        "reasons": [],
    }
    for state, reason in (
        (
            {"live_session_active": True, "open_paper_orders": False, "halt_pending": False},
            "live_session_active",
        ),
        (
            {"live_session_active": False, "open_paper_orders": True, "halt_pending": False},
            "open_paper_orders",
        ),
        (
            {"live_session_active": False, "open_paper_orders": False, "halt_pending": True},
            "halt_pending",
        ),
    ):
        result = helper(**state)
        assert result["safe"] is False
        assert result["reasons"] == [reason]

    unavailable = helper(
        live_session_active=False,
        open_paper_orders=False,
        halt_pending=False,
        state_available=False,
    )
    assert unavailable["safe"] is False
    assert "readiness_unavailable" in unavailable["reasons"]


def test_runtime_readiness_derives_and_fails_closed_on_unsafe_inputs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "apps/desktop/sidecar"))
    monkeypatch.setitem(sys.modules, "build_constants", SimpleNamespace(RISK_LOCK_SHA256="0" * 64))
    sidecar = importlib.import_module("leviathan_desktop")
    from leviathan_core.risk.halt_store import HaltStore

    def fake_api(
        *,
        mode: str = "PAPER",
        live_enabled: bool = False,
        fault: str | None = None,
        halted: bool = False,
    ):
        runtime = SimpleNamespace(
            settings=SimpleNamespace(operating_mode=mode),
            orders=SimpleNamespace(live_enabled=live_enabled),
            halts=SimpleNamespace(fault_code=fault, halted=halted),
        )
        return SimpleNamespace(state=SimpleNamespace(leviathan=runtime))

    data_root = tmp_path / "data-root"
    data_dir = data_root / "data"
    data_dir.mkdir(parents=True)
    (data_dir / "halt-state.sqlite3").touch()
    (data_dir / "leviathan.db").touch()
    monkeypatch.setattr(sidecar, "ensure_no_pending_migration", lambda _root: None)
    monkeypatch.setattr(HaltStore, "_read", staticmethod(lambda _connection, **_kwargs: (None, ())))
    monkeypatch.setattr(sidecar, "_has_open_paper_orders", lambda _database: False)

    live = sidecar._runtime_readiness(fake_api(mode="LIVE"), data_root)
    assert live["safe"] is False
    assert live["reasons"] == ["live_session_active"]

    monkeypatch.setattr(sidecar, "_has_open_paper_orders", lambda _database: True)
    orders = sidecar._runtime_readiness(fake_api(), data_root)
    assert orders["safe"] is False
    assert orders["reasons"] == ["open_paper_orders"]

    monkeypatch.setattr(sidecar, "_has_open_paper_orders", lambda _database: False)
    monkeypatch.setattr(
        HaltStore,
        "_read",
        staticmethod(lambda _connection, **_kwargs: (None, ("synthetic-pending-halt",))),
    )
    halt = sidecar._runtime_readiness(fake_api(), data_root)
    assert halt["safe"] is False
    assert halt["reasons"] == ["halt_pending"]

    unavailable = sidecar._runtime_readiness(fake_api(), tmp_path / "missing-data-root")
    assert unavailable["safe"] is False
    assert unavailable["reasons"] == ["readiness_unavailable"]


def test_update_readiness_route_uses_the_exact_capability_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "apps/desktop/sidecar"))
    guard = importlib.import_module("request_guard")

    def make_request(headers: list[tuple[bytes, bytes]]) -> Request:
        return Request(
            {
                "type": "http",
                "http_version": "1.1",
                "method": "GET",
                "scheme": "http",
                "path": "/desktop/update-readiness",
                "raw_path": b"/desktop/update-readiness",
                "query_string": b"",
                "headers": headers,
                "client": ("127.0.0.1", 43100),
                "server": ("127.0.0.1", 43101),
            }
        )

    common = [(b"host", b"127.0.0.1:43101")]
    missing = guard.reject_request(make_request(common), capability="a" * 64, port=43101)
    wrong = guard.reject_request(
        make_request([*common, (b"x-leviathan-capability", b"b" * 64)]),
        capability="a" * 64,
        port=43101,
    )
    accepted = guard.reject_request(
        make_request([*common, (b"x-leviathan-capability", b"a" * 64)]),
        capability="a" * 64,
        port=43101,
    )
    wrong_origin = guard.reject_request(
        make_request(
            [
                *common,
                (b"origin", b"http://attacker.invalid"),
                (b"x-leviathan-capability", b"a" * 64),
            ]
        ),
        capability="a" * 64,
        port=43101,
    )

    assert missing is not None and missing.status_code == 403
    assert wrong is not None and wrong.status_code == 403
    assert accepted is None
    assert wrong_origin is not None and wrong_origin.status_code == 403
    desktop_source = _text("apps/desktop/sidecar/leviathan_desktop.py")
    assert re.search(
        r'@desktop\.get\("/desktop/update-readiness"\)\s+'
        r"async def desktop_update_readiness\(\).*?return _runtime_readiness\(api_app, data_root\)",
        desktop_source,
        flags=re.DOTALL,
    )
    assert re.search(
        r'@desktop\.middleware\("http"\).*?'
        r"reject_request\(request, capability=capability, port=port\)",
        desktop_source,
        flags=re.DOTALL,
    )


def test_build_script_never_logs_the_signing_key() -> None:
    build = _text("apps/desktop/scripts/build.ps1")
    output_line = re.compile(
        r"(?i)^\s*(?:write-(?:host|output|verbose|information|warning|error)|tee-object)\b.*$"
    )
    key_reference = re.compile(
        r"(?i)(?:TAURI_SIGNING_PRIVATE_KEY|signing[_-]?private[_-]?key|\$signingKey)"
    )
    leaking_lines = [
        line.strip()
        for line in build.splitlines()
        if output_line.search(line) and key_reference.search(line)
    ]
    assert leaking_lines == []
