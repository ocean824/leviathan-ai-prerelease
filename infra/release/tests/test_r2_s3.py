from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

import pytest
from infra.release.r2_s3 import (
    HttpResponse,
    R2Error,
    R2S3Client,
    _sigv4_signature,
)


class RecordingTransport:
    def __init__(self, response: HttpResponse | None = None) -> None:
        self.response = response or HttpResponse(200, {}, b"")
        self.calls: list[tuple[str, str, Mapping[str, str], bytes]] = []

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
    ) -> HttpResponse:
        self.calls.append((method, url, headers, body))
        return self.response


def test_aws_sigv4_iam_known_answer_vector() -> None:
    canonical_request = (
        "GET\n/\nAction=ListUsers&Version=2010-05-08\n"
        "content-type:application/x-www-form-urlencoded; charset=utf-8\n"
        "host:iam.amazonaws.com\n"
        "x-amz-date:20150830T123600Z\n\n"
        "content-type;host;x-amz-date\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    assert (
        _sigv4_signature(
            canonical_request,
            "20150830T123600Z",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "iam",
        )
        == "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
    )


def test_r2_request_uses_auto_s3_scope_and_can_add_cache_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("R2_ACCESS_KEY_ID", "test-access")
    monkeypatch.setenv("R2_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("R2_ACCOUNT_ID", "0123456789abcdef0123456789abcdef")
    transport = RecordingTransport()
    client = R2S3Client(
        transport,
        clock=lambda: datetime(2026, 10, 7, 12, 34, 56, tzinfo=UTC),
    )

    client.put_object(
        "release-bucket",
        "channels/desktop/latest.json",
        b"{}",
        "application/json",
        cache_control="no-store",
    )

    method, url, headers, body = transport.calls[0]
    assert method == "PUT"
    assert url == (
        "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com/"
        "release-bucket/channels/desktop/latest.json"
    )
    assert headers["x-amz-date"] == "20261007T123456Z"
    assert headers["Authorization"].startswith(
        "AWS4-HMAC-SHA256 Credential=test-access/20261007/auto/s3/aws4_request,"
    )
    assert headers["Cache-Control"] == "no-store"
    assert headers["x-amz-content-sha256"] == (
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    )
    assert body == b"{}"


def test_conditional_put_and_missing_objects_are_typed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("R2_ACCESS_KEY_ID", "test-access")
    monkeypatch.setenv("R2_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("R2_ACCOUNT_ID", "0123456789abcdef0123456789abcdef")
    transport = RecordingTransport(HttpResponse(412, {}, b"secret response body"))
    client = R2S3Client(transport)
    with pytest.raises(R2Error) as raised:
        client.put_object(
            "release-bucket", "releases/desktop/1.0.0/a.msi", b"x", "application/octet-stream", "*"
        )
    assert raised.value.code == "PRECONDITION_FAILED"
    assert "secret response body" not in str(raised.value)

    missing = R2S3Client(RecordingTransport(HttpResponse(404, {}, b"private")))
    assert missing.head_object("release-bucket", "channels/admin/latest.json") is None
    assert missing.get_object("release-bucket", "channels/admin/latest.json") is None


def test_credentials_are_environment_only_and_never_appear_in_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("R2_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("R2_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("R2_ACCOUNT_ID", raising=False)
    client = R2S3Client(RecordingTransport())
    with pytest.raises(R2Error) as missing:
        client.head_object("release-bucket", "key")
    assert missing.value.code == "MISSING_CREDENTIALS"

    monkeypatch.setenv("R2_ACCESS_KEY_ID", "synthetic-access")
    monkeypatch.setenv("R2_SECRET_ACCESS_KEY", "synthetic-secret")
    monkeypatch.setenv("R2_ACCOUNT_ID", "0123456789abcdef0123456789abcdef")

    class LeakingTransport:
        def request(
            self, method: str, url: str, headers: Mapping[str, str], body: bytes
        ) -> HttpResponse:
            raise RuntimeError("synthetic-secret must never escape")

    with pytest.raises(R2Error) as transport_error:
        R2S3Client(LeakingTransport()).get_object("release-bucket", "key")
    assert transport_error.value.code == "TRANSPORT_ERROR"
    assert "synthetic-secret" not in str(transport_error.value)
