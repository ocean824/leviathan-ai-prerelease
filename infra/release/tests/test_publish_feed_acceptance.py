from __future__ import annotations

import hashlib
import hmac
import io
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from infra.release.publish_feed import PublishError, PublishResult, main, publish  # noqa: E402
from infra.release.r2_s3 import HttpResponse, R2Error, R2S3Client  # noqa: E402

AWS_EXAMPLE_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
CANARY_ACCESS_KEY = "synthetic-r2-access-canary"
CANARY_SECRET_KEY = "synthetic-r2-secret-canary"
CANARY_ACCOUNT_ID = "synthetic-r2-account-canary"
FIXED_NOW = datetime(2013, 5, 24, tzinfo=UTC)
PUBLIC_BASE_URL = "https://releases.invalid"
ALLOWED_HOSTS = ("releases.invalid",)


class FakeTransport:
    """In-memory S3-shaped transport; it never opens a network connection."""

    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], bytes] = {}
        self.calls: list[tuple[str, str, dict[str, str], bytes]] = []

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
    ) -> HttpResponse:
        self.calls.append((method, url, dict(headers), body))
        path = urlsplit(url).path.lstrip("/")
        bucket, separator, key = path.partition("/")
        if not separator:
            if method == "PUT":
                return HttpResponse(200, {}, b"")
            return HttpResponse(404, {}, b"")
        object_key = (bucket, key)
        if method == "GET":
            value = self.objects.get(object_key)
            if value is not None:
                return HttpResponse(200, {}, value)
            return HttpResponse(404, {}, b"")
        if method == "HEAD":
            return (
                HttpResponse(200, {}, b"")
                if object_key in self.objects
                else HttpResponse(404, {}, b"")
            )
        if method == "PUT":
            if headers.get("If-None-Match") == "*" and object_key in self.objects:
                return HttpResponse(412, {}, b"")
            self.objects[object_key] = body
            return HttpResponse(200, {}, b"")
        return HttpResponse(405, {}, b"")


def _client(transport: FakeTransport) -> R2S3Client:
    return R2S3Client(transport, clock=lambda: FIXED_NOW)


def _set_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("R2_ACCESS_KEY_ID", CANARY_ACCESS_KEY)
    monkeypatch.setenv("R2_SECRET_ACCESS_KEY", CANARY_SECRET_KEY)
    monkeypatch.setenv("R2_ACCOUNT_ID", CANARY_ACCOUNT_ID)


def _bundle(
    tmp_path: Path,
    *,
    version: str = "1.2.3",
    signature: str | None = "synthetic-signature",
) -> Path:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    artifact_name = f"desktop-{version}.nsis.zip"
    (bundle / artifact_name).write_bytes(b"inert synthetic release artifact")
    payload = {
        "version": version,
        "notes": "synthetic acceptance manifest",
        "pub_date": "2026-10-07T12:00:00Z",
        "platforms": {
            "windows-x86_64": {
                "url": f"https://origin.invalid/{version}/{artifact_name}",
                "signature": signature,
            }
        },
    }
    (bundle / "latest.json").write_text(
        json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return bundle


def _prior_manifest(version: str) -> bytes:
    return json.dumps(
        {
            "version": version,
            "notes": "prior synthetic release",
            "pub_date": "2026-10-06T12:00:00Z",
            "platforms": {
                "windows-x86_64": {
                    "url": f"https://releases.invalid/{version}/desktop-{version}.nsis.zip",
                    "signature": "prior-synthetic-signature",
                }
            },
        }
    ).encode()


def _latest_key(channel: str = "desktop") -> tuple[str, str]:
    return "release-bucket", f"channels/{channel}/latest.json"


def _publish(bundle: Path, client: R2S3Client, *, dry_run: bool = False) -> PublishResult:
    return publish(
        "release-bucket",
        "desktop",
        bundle,
        client,
        public_base_url=PUBLIC_BASE_URL,
        allowed_hosts=ALLOWED_HOSTS,
        dry_run=dry_run,
    )


def test_sigv4_matches_published_aws_s3_known_answer() -> None:
    """AWS S3 GET Object example from the SigV4 header-auth guide."""
    from infra.release import r2_s3

    payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    canonical_request = "\n".join(
        (
            "GET",
            "/test.txt",
            "",
            "host:examplebucket.s3.amazonaws.com\n"
            "range:bytes=0-9\n"
            f"x-amz-content-sha256:{payload_hash}\n"
            "x-amz-date:20130524T000000Z\n",
            "host;range;x-amz-content-sha256;x-amz-date",
            payload_hash,
        )
    )
    signature = r2_s3._sigv4_signature(
        canonical_request,
        "20130524T000000Z",
        AWS_EXAMPLE_SECRET,
        region="us-east-1",
        service="s3",
    )

    assert signature == "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"


def test_sigv4_matches_published_aws_iam_known_answer() -> None:
    """AWS IAM Query API vector independently exercises canonical request signing."""
    from infra.release import r2_s3

    canonical_request = (
        "GET\n/\nAction=ListUsers&Version=2010-05-08\n"
        "content-type:application/x-www-form-urlencoded; charset=utf-8\n"
        "host:iam.amazonaws.com\n"
        "x-amz-date:20150830T123600Z\n\n"
        "content-type;host;x-amz-date\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    signature = r2_s3._sigv4_signature(
        canonical_request,
        "20150830T123600Z",
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "us-east-1",
        "iam",
    )

    assert signature == "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"


def test_r2_client_signature_is_independently_recomputed_for_fake_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_credentials(monkeypatch)
    transport = FakeTransport()
    _client(transport).get_object("release-bucket", "path/to/object.json")

    method, url, headers, body = transport.calls[0]
    assert method == "GET"
    assert body == b""
    expected = _expected_signature(method, url, headers, body)

    assert headers["Host"] == urlsplit(url).netloc
    assert headers["Authorization"].endswith(f"Signature={expected}")


def _independent_signing_key(secret: str, date_stamp: str, region: str, service: str) -> bytes:
    def sign(key: bytes, value: str) -> bytes:
        return hmac.new(key, value.encode(), hashlib.sha256).digest()

    date_key = sign(("AWS4" + secret).encode(), date_stamp)
    return sign(sign(sign(date_key, region), service), "aws4_request")


def _expected_signature(method: str, url: str, headers: dict[str, str], body: bytes) -> str:
    parsed = urlsplit(url)
    signed = [(key, value) for key, value in headers.items() if key.lower() != "authorization"]
    canonical_headers = "".join(
        f"{key.lower()}:{value.strip()}\n"
        for key, value in sorted(signed, key=lambda pair: pair[0].lower())
    )
    signed_headers = ";".join(sorted(key.lower() for key, _ in signed))
    payload_hash = hashlib.sha256(body).hexdigest()
    canonical_request = "\n".join(
        (method, parsed.path, "", canonical_headers, signed_headers, payload_hash)
    )
    timestamp = headers["x-amz-date"]
    date_stamp = timestamp[:8]
    scope = f"{date_stamp}/auto/s3/aws4_request"
    string_to_sign = "\n".join(
        (
            "AWS4-HMAC-SHA256",
            timestamp,
            scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        )
    )
    key = _independent_signing_key(CANARY_SECRET_KEY, date_stamp, "auto", "s3")
    return hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()


def test_publish_orders_immutable_artifact_before_no_store_latest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_credentials(monkeypatch)
    transport = FakeTransport()
    bundle = _bundle(tmp_path)

    result = _publish(bundle, _client(transport))

    assert result.action == "publish"
    assert result.dry_run is False
    assert all(
        canary not in repr(result)
        for canary in (CANARY_ACCESS_KEY, CANARY_SECRET_KEY, CANARY_ACCOUNT_ID)
    )
    puts = [call for call in transport.calls if call[0] == "PUT"]
    assert len(puts) == 2
    assert puts[-1][2].get("Cache-Control", puts[-1][2].get("cache-control")) == "no-store"
    assert urlsplit(puts[-1][1]).path.endswith("/channels/desktop/latest.json")
    assert urlsplit(puts[0][1]).path.endswith("/releases/desktop/1.2.3/desktop-1.2.3.nsis.zip")
    assert puts[0][2].get("If-None-Match") == "*"
    assert all(call[0] != "PUT" or "latest.json" not in call[1] for call in puts[:-1])
    latest_put = puts[-1]
    expected = _expected_signature(*latest_put)
    assert "cache-control" in latest_put[2]["Authorization"].lower()
    assert latest_put[2]["Authorization"].endswith(f"Signature={expected}")
    uploaded_latest = transport.objects[_latest_key()]
    uploaded_manifest = json.loads(uploaded_latest)
    assert uploaded_manifest["platforms"]["windows-x86_64"]["url"] == (
        "https://releases.invalid/releases/desktop/1.2.3/desktop-1.2.3.nsis.zip"
    )
    assert b"origin.invalid" not in uploaded_latest


def test_public_base_host_must_be_allowlisted_before_any_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_credentials(monkeypatch)
    transport = FakeTransport()

    with pytest.raises(PublishError) as error:
        publish(
            "release-bucket",
            "desktop",
            _bundle(tmp_path),
            _client(transport),
            public_base_url="https://attacker.invalid",
            allowed_hosts=ALLOWED_HOSTS,
        )

    assert error.value.code == "PUBLIC_HOST_NOT_ALLOWED"
    assert transport.calls == []


@pytest.mark.parametrize("missing_option", ["--public-base-url", "--allowed-host"])
def test_publish_cli_requires_public_url_and_allowlist_before_request(
    tmp_path: Path, missing_option: str
) -> None:
    transport = FakeTransport()
    argv = [
        "publish",
        "--bucket",
        "release-bucket",
        "--channel",
        "desktop",
        "--bundle-dir",
        str(_bundle(tmp_path)),
        "--public-base-url",
        PUBLIC_BASE_URL,
        "--allowed-host",
        "releases.invalid",
    ]
    argv.remove(missing_option)
    if missing_option == "--public-base-url":
        argv.remove(PUBLIC_BASE_URL)
    else:
        argv.remove("releases.invalid")

    with pytest.raises(SystemExit) as error:
        main(argv, client=_client(transport), stdout=io.StringIO(), stderr=io.StringIO())

    assert error.value.code == 2
    assert transport.calls == []


@pytest.mark.parametrize("current", ["1.2.3", "1.2.4"])
def test_publish_refuses_equal_or_older_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, current: str
) -> None:
    _set_credentials(monkeypatch)
    transport = FakeTransport()
    transport.objects[_latest_key()] = _prior_manifest(current)

    with pytest.raises(PublishError) as error:
        _publish(_bundle(tmp_path), _client(transport))

    assert error.value.code == "NON_MONOTONIC_VERSION"
    assert not any(call[0] == "PUT" for call in transport.calls)


def test_publish_requires_signature_and_does_not_write_on_missing_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_credentials(monkeypatch)
    transport = FakeTransport()

    with pytest.raises(PublishError) as error:
        _publish(_bundle(tmp_path, signature=""), _client(transport))

    assert error.value.code == "SIGNATURE_MISSING"
    assert transport.calls == []


def test_existing_artifact_key_is_never_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_credentials(monkeypatch)
    transport = FakeTransport()
    bundle = _bundle(tmp_path)
    key = ("release-bucket", "releases/desktop/1.2.3/desktop-1.2.3.nsis.zip")
    transport.objects[key] = b"pre-existing immutable bytes"

    with pytest.raises(PublishError) as error:
        _publish(bundle, _client(transport))

    assert error.value.code == "OBJECT_EXISTS"
    assert transport.objects[key] == b"pre-existing immutable bytes"
    assert not any(
        call[0] == "PUT" and urlsplit(call[1]).path.endswith("/latest.json")
        for call in transport.calls
    )


def test_immutable_put_precondition_closes_head_put_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_credentials(monkeypatch)

    class RacedTransport(FakeTransport):
        def request(
            self, method: str, url: str, headers: dict[str, str], body: bytes
        ) -> HttpResponse:
            path = urlsplit(url).path
            if method == "HEAD" and path.endswith("desktop-1.2.3.nsis.zip"):
                self.calls.append((method, url, dict(headers), body))
                return HttpResponse(404, {}, b"")
            if method == "PUT" and path.endswith("desktop-1.2.3.nsis.zip"):
                self.calls.append((method, url, dict(headers), body))
                return HttpResponse(412, {}, b"")
            return super().request(method, url, headers, body)

    transport = RacedTransport()
    with pytest.raises(PublishError) as error:
        _publish(_bundle(tmp_path), _client(transport))

    assert error.value.code == "OBJECT_EXISTS"
    artifact_puts = [
        call for call in transport.calls if call[0] == "PUT" and "releases/" in call[1]
    ]
    assert len(artifact_puts) == 1
    assert artifact_puts[0][2].get("If-None-Match") == "*"
    assert not any(
        call[0] == "PUT" and call[1].endswith("/channels/desktop/latest.json")
        for call in transport.calls
    )


@pytest.mark.parametrize("command", ["publish", "create-bucket"])
def test_dry_run_never_puts_or_creates_bucket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    _set_credentials(monkeypatch)
    transport = FakeTransport()
    client = _client(transport)
    stdout = io.StringIO()
    stderr = io.StringIO()
    if command == "publish":
        argv = [
            "publish",
            "--bucket",
            "release-bucket",
            "--channel",
            "desktop",
            "--bundle-dir",
            str(_bundle(tmp_path)),
            "--public-base-url",
            PUBLIC_BASE_URL,
            "--allowed-host",
            "releases.invalid",
            "--dry-run",
        ]
    else:
        argv = ["create-bucket", "--bucket", "release-bucket", "--dry-run"]

    assert main(argv, client=client, stdout=stdout, stderr=stderr) == 0
    if command == "create-bucket":
        assert transport.calls == []
    else:
        assert not any(call[0] == "PUT" for call in transport.calls)
    assert stderr.getvalue() == ""
    for canary in (CANARY_ACCESS_KEY, CANARY_SECRET_KEY, CANARY_ACCOUNT_ID):
        assert canary not in stdout.getvalue()


@pytest.mark.parametrize(
    "missing",
    ("R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_ACCOUNT_ID"),
)
def test_missing_credentials_fail_before_fake_transport_request(
    monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    _set_credentials(monkeypatch)
    monkeypatch.delenv(missing, raising=False)
    transport = FakeTransport()

    with pytest.raises(R2Error) as error:
        _client(transport).head_object("release-bucket", "missing.json")

    assert error.value.code == "MISSING_CREDENTIALS"
    assert transport.calls == []


def test_credential_canaries_are_absent_from_cli_output_errors_and_logs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _set_credentials(monkeypatch)

    class FailingTransport(FakeTransport):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str],
            body: bytes,
        ) -> HttpResponse:
            self.calls.append((method, url, dict(headers), body))
            raise RuntimeError(f"transport diagnostic {CANARY_SECRET_KEY}")

    transport = FailingTransport()
    output = io.StringIO()
    errors = io.StringIO()
    code = main(
        [
            "publish",
            "--bucket",
            "release-bucket",
            "--channel",
            "desktop",
            "--bundle-dir",
            str(_bundle(tmp_path)),
            "--public-base-url",
            PUBLIC_BASE_URL,
            "--allowed-host",
            "releases.invalid",
        ],
        client=_client(transport),
        stdout=output,
        stderr=errors,
    )
    observable = output.getvalue() + errors.getvalue() + caplog.text

    assert code == 1
    assert json.loads(errors.getvalue()) == {"error": "R2_REQUEST_FAILED"}
    assert CANARY_SECRET_KEY not in output.getvalue() + errors.getvalue()
    for canary in (CANARY_ACCESS_KEY, CANARY_SECRET_KEY, CANARY_ACCOUNT_ID):
        assert canary not in observable
    assert transport.calls
    assert CANARY_SECRET_KEY not in repr(transport.calls)

    with pytest.raises(R2Error) as error:
        _client(FailingTransport()).head_object("release-bucket", "missing.json")
    assert error.value.code == "TRANSPORT_ERROR"
    assert all(
        canary not in str(error.value) + repr(error.value)
        for canary in (CANARY_ACCESS_KEY, CANARY_SECRET_KEY, CANARY_ACCOUNT_ID)
    )
    assert error.value.__cause__ is None

    fixture_root = ROOT / "infra" / "release" / "tests" / "fixtures"
    if fixture_root.exists():
        for fixture in fixture_root.rglob("*"):
            if fixture.is_file():
                content = fixture.read_bytes()
                assert all(
                    canary.encode() not in content
                    for canary in (CANARY_ACCESS_KEY, CANARY_SECRET_KEY, CANARY_ACCOUNT_ID)
                )
