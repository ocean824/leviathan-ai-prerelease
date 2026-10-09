from __future__ import annotations

import hashlib
import io
import json
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest
from infra.release.publish_feed import PublishError, main, publish
from infra.release.r2_s3 import HttpResponse, R2S3Client

_ACCOUNT_ID = "0123456789abcdef0123456789abcdef"
_BUCKET = "release-bucket"
_PUBLIC_BASE = "https://releases.example.test"
_ALLOWED_HOST = ("releases.example.test",)
_WINDOWS = "LeviathanAI_1.2.3_x64-setup.nsis.zip"
_MAC = "LeviathanAI_1.2.3_aarch64.app.tar.gz"
_MAC_X86 = "LeviathanAI_1.2.3_x86_64.app.tar.gz"


class FakeR2Transport:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], bytes] = {}
        self.calls: list[tuple[str, str, Mapping[str, str], bytes]] = []
        self.fail_conditional_put = False

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
    ) -> HttpResponse:
        self.calls.append((method, url, dict(headers), body))
        path = unquote(urlsplit(url).path).lstrip("/")
        bucket, separator, key = path.partition("/")
        if not separator:
            return HttpResponse(200, {}, b"")
        record_key = (bucket, key)
        if method == "GET":
            value = self.objects.get(record_key)
            return HttpResponse(404, {}, b"") if value is None else HttpResponse(200, {}, value)
        if method == "HEAD":
            value = self.objects.get(record_key)
            if value is None:
                return HttpResponse(404, {}, b"")
            return HttpResponse(200, {"Content-Length": str(len(value))}, b"")
        if method == "PUT":
            if headers.get("If-None-Match") == "*" and record_key in self.objects:
                return HttpResponse(412, {}, b"private response body")
            if headers.get("If-None-Match") == "*" and self.fail_conditional_put:
                return HttpResponse(412, {}, b"private response body")
            self.objects[record_key] = body
            return HttpResponse(200, {}, b"")
        return HttpResponse(405, {}, b"")


def _client(monkeypatch: pytest.MonkeyPatch, transport: FakeR2Transport) -> R2S3Client:
    monkeypatch.setenv("R2_ACCESS_KEY_ID", "synthetic-access")
    monkeypatch.setenv("R2_SECRET_ACCESS_KEY", "synthetic-secret")
    monkeypatch.setenv("R2_ACCOUNT_ID", _ACCOUNT_ID)
    return R2S3Client(transport)


def _bundle(bundle_dir: Path, *, version: str = "1.2.3") -> dict[str, object]:
    bundle_dir.mkdir(parents=True, exist_ok=True)
    windows_name = _WINDOWS.replace("1.2.3", version)
    mac_name = _MAC.replace("1.2.3", version)
    mac_x86_name = _MAC_X86.replace("1.2.3", version)
    (bundle_dir / windows_name).write_bytes(b"windows release bytes")
    (bundle_dir / mac_name).write_bytes(b"mac release bytes")
    (bundle_dir / mac_x86_name).write_bytes(b"mac x86 release bytes")
    manifest = {
        "version": version,
        "notes": "Synthetic release notes",
        "pub_date": "2026-10-07T12:00:00Z",
        "platforms": {
            "windows-x86_64": {
                "url": f"https://origin.example.test/releases/{version}/{windows_name}",
                "signature": "synthetic-windows-signature",
            },
            "darwin-aarch64": {
                "url": f"https://origin.example.test/releases/{version}/{mac_name}",
                "signature": "synthetic-mac-signature",
            },
            "darwin-x86_64": {
                "url": f"https://origin.example.test/releases/{version}/{mac_x86_name}",
                "signature": "synthetic-mac-x86-signature",
            },
        },
    }
    (bundle_dir / "latest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return manifest


def _publish(client: R2S3Client, bundle: Path, **kwargs: object):
    return publish(
        _BUCKET,
        "desktop",
        bundle,
        client,
        public_base_url=_PUBLIC_BASE,
        allowed_hosts=_ALLOWED_HOST,
        **kwargs,
    )


def test_publish_rewrites_public_urls_uploads_immutable_artifacts_and_latest_last(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = _bundle(tmp_path / "bundle")
    transport = FakeR2Transport()
    client = _client(monkeypatch, transport)

    result = _publish(client, tmp_path / "bundle")

    expected_artifacts = {
        f"releases/desktop/1.2.3/{_MAC}",
        f"releases/desktop/1.2.3/{_MAC_X86}",
        f"releases/desktop/1.2.3/{_WINDOWS}",
    }
    expected_latest = "channels/desktop/latest.json"
    assert {item.key for item in result.objects} == expected_artifacts | {expected_latest}
    put_calls = [call for call in transport.calls if call[0] == "PUT"]
    assert [urlsplit(call[1]).path.removeprefix(f"/{_BUCKET}/") for call in put_calls][
        -1
    ] == expected_latest
    assert len(put_calls) == 4
    assert all(call[2].get("If-None-Match") == "*" for call in put_calls[:-1])
    assert put_calls[-1][2]["Cache-Control"] == "no-store"
    assert "Cache-Control" not in put_calls[0][2]

    written = json.loads(transport.objects[(_BUCKET, expected_latest)])
    for platform, item in written["platforms"].items():
        filename = Path(urlsplit(original["platforms"][platform]["url"]).path).name
        assert item["url"] == f"{_PUBLIC_BASE}/releases/desktop/1.2.3/{filename}"
        assert item["signature"] == original["platforms"][platform]["signature"]
        assert "r2.cloudflarestorage.com" not in item["url"]
    assert (
        result.objects[-1].sha256
        == hashlib.sha256(transport.objects[(_BUCKET, expected_latest)]).hexdigest()
    )


def test_dry_run_reports_redacted_plan_and_makes_no_puts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _bundle(tmp_path / "bundle")
    transport = FakeR2Transport()
    client = _client(monkeypatch, transport)
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = main(
        [
            "publish",
            "--bucket",
            _BUCKET,
            "--channel",
            "desktop",
            "--bundle-dir",
            str(tmp_path / "bundle"),
            "--public-base-url",
            _PUBLIC_BASE,
            "--allowed-host",
            _ALLOWED_HOST[0],
            "--dry-run",
        ],
        client=client,
        stdout=stdout,
        stderr=stderr,
    )

    assert status == 0
    assert stderr.getvalue() == ""
    summary = json.loads(stdout.getvalue())
    assert summary["dry_run"] is True
    assert len(summary["objects"]) == 4
    assert all(item["sha256"] and item["size"] for item in summary["objects"])
    assert not any(method == "PUT" for method, *_ in transport.calls)
    assert "synthetic-secret" not in stdout.getvalue()
    assert "synthetic-access" not in stdout.getvalue()


def test_create_bucket_dry_run_makes_zero_requests_and_reports_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = FakeR2Transport()
    client = _client(monkeypatch, transport)
    stdout = io.StringIO()
    status = main(
        ["create-bucket", "--bucket", _BUCKET, "--dry-run"],
        client=client,
        stdout=stdout,
        stderr=io.StringIO(),
    )
    assert status == 0
    assert json.loads(stdout.getvalue()) == {
        "action": "create-bucket",
        "bucket": _BUCKET,
        "channel": None,
        "dry_run": True,
        "objects": [],
    }
    assert transport.calls == []


def test_rejects_non_monotonic_versions_without_uploading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _bundle(tmp_path / "bundle", version="1.2.2")
    transport = FakeR2Transport()
    transport.objects[(_BUCKET, "channels/desktop/latest.json")] = json.dumps(
        _bundle(tmp_path / "current", version="1.2.3")
    ).encode()
    client = _client(monkeypatch, transport)

    with pytest.raises(PublishError) as raised:
        _publish(client, tmp_path / "bundle")

    assert raised.value.code == "NON_MONOTONIC_VERSION"
    assert not any(method == "PUT" for method, *_ in transport.calls)


def test_refuses_existing_immutable_artifact_before_any_put(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _bundle(tmp_path / "bundle")
    transport = FakeR2Transport()
    transport.objects[(_BUCKET, f"releases/desktop/1.2.3/{_MAC}")] = b"prior immutable bytes"
    transport.objects[(_BUCKET, f"releases/desktop/1.2.3/{_MAC_X86}")] = b"prior immutable bytes"
    client = _client(monkeypatch, transport)

    with pytest.raises(PublishError) as raised:
        _publish(client, tmp_path / "bundle")

    assert raised.value.code == "OBJECT_EXISTS"
    assert not any(method == "PUT" for method, *_ in transport.calls)


def test_rejects_unallowlisted_public_host_before_r2_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _bundle(tmp_path / "bundle")
    transport = FakeR2Transport()
    client = _client(monkeypatch, transport)

    with pytest.raises(PublishError) as raised:
        publish(
            _BUCKET,
            "desktop",
            tmp_path / "bundle",
            client,
            public_base_url="https://evil.example.test",
            allowed_hosts=_ALLOWED_HOST,
        )

    assert raised.value.code == "PUBLIC_HOST_NOT_ALLOWED"
    assert transport.calls == []


def test_every_platform_requires_nonempty_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _bundle(tmp_path / "bundle")
    manifest["platforms"]["darwin-aarch64"]["signature"] = " "
    (tmp_path / "bundle" / "latest.json").write_text(json.dumps(manifest), encoding="utf-8")
    transport = FakeR2Transport()
    client = _client(monkeypatch, transport)

    with pytest.raises(PublishError) as raised:
        _publish(client, tmp_path / "bundle")

    assert raised.value.code == "SIGNATURE_MISSING"
    assert transport.calls == []


def test_conditional_put_race_does_not_publish_latest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _bundle(tmp_path / "bundle")
    transport = FakeR2Transport()
    transport.fail_conditional_put = True
    client = _client(monkeypatch, transport)

    with pytest.raises(PublishError) as raised:
        _publish(client, tmp_path / "bundle")

    assert raised.value.code == "OBJECT_EXISTS"
    assert not any(
        method == "PUT" and urlsplit(url).path.endswith("/channels/desktop/latest.json")
        for method, url, _, _ in transport.calls
    )
