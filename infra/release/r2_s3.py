"""Small stdlib-only Cloudflare R2 S3 client with AWS Signature V4."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import quote

_ACCOUNT_ID = re.compile(r"[A-Za-z0-9-]{1,63}\Z")
_BUCKET = re.compile(r"[a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9])\Z")
_KEY = re.compile(r"[^\x00-\x20\x7f\\?#]+\Z")
_ALGORITHM = "AWS4-HMAC-SHA256"
_REGION = "auto"
_SERVICE = "s3"


class R2Error(Exception):
    """Content-free R2 request failure with a stable code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes


class HttpTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
    ) -> HttpResponse: ...


class UrllibTransport:
    """Default synchronous transport. Callers can inject an offline fake."""

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
    ) -> HttpResponse:
        request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return HttpResponse(
                    status_code=response.status,
                    headers=dict(response.headers.items()),
                    body=response.read(),
                )
        except urllib.error.HTTPError as response:
            return HttpResponse(
                status_code=response.code,
                headers=dict(response.headers.items()),
                body=response.read(),
            )
        except (urllib.error.URLError, TimeoutError, OSError):
            raise R2Error("TRANSPORT_ERROR") from None


def _sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hmac(key: bytes, value: str) -> bytes:
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, date_stamp: str, region: str, service: str) -> bytes:
    date_key = _hmac(("AWS4" + secret).encode("utf-8"), date_stamp)
    region_key = _hmac(date_key, region)
    service_key = _hmac(region_key, service)
    return _hmac(service_key, "aws4_request")


def _sigv4_signature(
    canonical_request: str,
    timestamp: str,
    secret_key: str,
    region: str,
    service: str,
) -> str:
    """Pure signing seam used by the AWS published known-answer test."""
    date_stamp = timestamp[:8]
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        (
            _ALGORITHM,
            timestamp,
            scope,
            _sha256_hex(canonical_request.encode("utf-8")),
        )
    )
    return hmac.new(
        _signing_key(secret_key, date_stamp, region, service),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _canonical_uri(bucket: str, key: str | None = None) -> str:
    segments = [bucket]
    if key is not None:
        segments.extend(key.split("/"))
    return "/" + "/".join(quote(segment, safe="-_.~") for segment in segments)


def _validate_bucket(value: object) -> str:
    if type(value) is not str or _BUCKET.fullmatch(value) is None:
        raise R2Error("INVALID_BUCKET")
    if ".." in value or ".-" in value or "-." in value:
        raise R2Error("INVALID_BUCKET")
    return value


def _validate_key(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or value.startswith("/")
        or _KEY.fullmatch(value) is None
        or any(segment in {"", ".", ".."} for segment in value.split("/"))
    ):
        raise R2Error("INVALID_KEY")
    return value


class R2S3Client:
    """S3-compatible R2 operations. Credentials are read only from process env."""

    def __init__(
        self,
        transport: HttpTransport | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._transport = transport or UrllibTransport()
        self._clock = clock or (lambda: datetime.now(UTC))

    def create_bucket(self, name: str) -> HttpResponse:
        bucket = _validate_bucket(name)
        response = self._request("PUT", bucket, None, b"", "application/xml")
        if response.status_code not in {200, 201, 204}:
            raise R2Error("BUCKET_CREATE_FAILED")
        return response

    def head_object(self, bucket: str, key: str) -> HttpResponse | None:
        response = self._request("HEAD", _validate_bucket(bucket), _validate_key(key), b"", None)
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise R2Error("OBJECT_HEAD_FAILED")
        return response

    def get_object(self, bucket: str, key: str) -> HttpResponse | None:
        response = self._request("GET", _validate_bucket(bucket), _validate_key(key), b"", None)
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise R2Error("OBJECT_GET_FAILED")
        return response

    def put_object(
        self,
        bucket: str,
        key: str,
        body: bytes,
        content_type: str,
        if_none_match: str | None = None,
        cache_control: str | None = None,
    ) -> HttpResponse:
        if (
            type(body) is not bytes
            or type(content_type) is not str
            or not content_type
            or any(char in content_type for char in "\r\n")
        ):
            raise R2Error("INVALID_REQUEST")
        if if_none_match is not None and if_none_match != "*":
            raise R2Error("INVALID_REQUEST")
        if cache_control is not None and (
            type(cache_control) is not str
            or not cache_control
            or any(c in cache_control for c in "\r\n")
        ):
            raise R2Error("INVALID_REQUEST")
        response = self._request(
            "PUT",
            _validate_bucket(bucket),
            _validate_key(key),
            body,
            content_type,
            if_none_match=if_none_match,
            cache_control=cache_control,
        )
        if response.status_code == 412:
            raise R2Error("PRECONDITION_FAILED")
        if response.status_code not in {200, 201, 204}:
            raise R2Error("OBJECT_PUT_FAILED")
        return response

    def _request(
        self,
        method: str,
        bucket: str,
        key: str | None,
        body: bytes,
        content_type: str | None,
        *,
        if_none_match: str | None = None,
        cache_control: str | None = None,
    ) -> HttpResponse:
        access_key = os.environ.get("R2_ACCESS_KEY_ID")
        secret_key = os.environ.get("R2_SECRET_ACCESS_KEY")
        account_id = os.environ.get("R2_ACCOUNT_ID")
        if not access_key or not secret_key or not account_id:
            raise R2Error("MISSING_CREDENTIALS")
        if _ACCOUNT_ID.fullmatch(account_id) is None or any(
            char in access_key + secret_key for char in "\r\n"
        ):
            raise R2Error("INVALID_CREDENTIALS")

        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise R2Error("INVALID_CLOCK")
        timestamp = now.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
        date_stamp = timestamp[:8]
        host = f"{account_id}.r2.cloudflarestorage.com"
        canonical_uri = _canonical_uri(bucket, key)
        payload_hash = _sha256_hex(body)
        headers = {
            "Host": host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": timestamp,
        }
        if content_type is not None:
            headers["Content-Type"] = content_type
        if if_none_match is not None:
            headers["If-None-Match"] = if_none_match
        if cache_control is not None:
            headers["Cache-Control"] = cache_control
        canonical_headers = "".join(
            f"{name.lower()}:{value.strip()}\n"
            for name, value in sorted(headers.items(), key=lambda pair: pair[0].lower())
        )
        signed_headers = ";".join(sorted(name.lower() for name in headers))
        canonical_request = "\n".join(
            (method, canonical_uri, "", canonical_headers, signed_headers, payload_hash)
        )
        scope = f"{date_stamp}/{_REGION}/{_SERVICE}/aws4_request"
        signature = _sigv4_signature(
            canonical_request,
            timestamp,
            secret_key,
            _REGION,
            _SERVICE,
        )
        headers["Authorization"] = (
            f"{_ALGORITHM} Credential={access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        url = f"https://{host}{canonical_uri}"
        try:
            return self._transport.request(method, url, headers, body)
        except R2Error:
            raise
        except Exception:
            raise R2Error("TRANSPORT_ERROR") from None


__all__ = ["HttpResponse", "HttpTransport", "R2Error", "R2S3Client", "UrllibTransport"]
