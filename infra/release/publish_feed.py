"""Publish signed Tauri update bundles to channel-scoped Cloudflare R2 keys.

Every platform signature is required. Public artifact URLs are rewritten to
the allowlisted ``--public-base-url`` and the same channel path used in R2; the
credentialed R2 S3 endpoint is never exposed in the feed manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TextIO
from urllib.parse import unquote, urlsplit

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from infra.release.feed_manifest import FeedManifestError, _newer, _version_key
from infra.release.r2_s3 import R2Error, R2S3Client

_CHANNELS = frozenset({"desktop", "admin"})
_PLATFORM = re.compile(r"[a-z0-9]+-[a-z0-9_]+\Z")
_HOST = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\Z"
)
_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\Z")
_RFC3339 = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z"
)
_MAX_MANIFEST_BYTES = 1024 * 1024


class PublishError(Exception):
    """Content-free publisher error with a stable code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class PublishedObject:
    key: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class PublishResult:
    action: str
    bucket: str
    channel: str | None
    dry_run: bool
    objects: tuple[PublishedObject, ...]


def _error(code: str) -> PublishError:
    return PublishError(code)


def _validate_manifest(raw: bytes) -> dict[str, object]:
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise _error("MANIFEST_TOO_LARGE")
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        raise _error("INVALID_MANIFEST") from None
    if type(payload) is not dict or set(payload) != {"version", "notes", "pub_date", "platforms"}:
        raise _error("INVALID_MANIFEST")
    version = payload["version"]
    notes = payload["notes"]
    pub_date = payload["pub_date"]
    platforms = payload["platforms"]
    if type(version) is not str or type(notes) is not str or type(pub_date) is not str:
        raise _error("INVALID_MANIFEST")
    try:
        _version_key(version)
    except FeedManifestError:
        raise _error("INVALID_MANIFEST") from None
    if _RFC3339.fullmatch(pub_date) is None:
        raise _error("INVALID_MANIFEST")
    try:
        datetime.fromisoformat(pub_date.replace("Z", "+00:00"))
    except ValueError:
        raise _error("INVALID_MANIFEST") from None
    if type(platforms) is not dict or not platforms:
        raise _error("INVALID_MANIFEST")
    for platform, item in platforms.items():
        if (
            type(platform) is not str
            or _PLATFORM.fullmatch(platform) is None
            or type(item) is not dict
        ):
            raise _error("INVALID_MANIFEST")
        if set(item) != {"url", "signature"}:
            raise _error("INVALID_MANIFEST")
        url = item["url"]
        signature = item["signature"]
        if type(signature) is not str or not signature.strip():
            raise _error("SIGNATURE_MISSING")
        if len(signature) > 64 * 1024 or type(url) is not str or len(url) > 4096:
            raise _error("INVALID_MANIFEST")
        try:
            parsed = urlsplit(url)
            host = parsed.hostname
            port = parsed.port
        except ValueError:
            raise _error("INVALID_MANIFEST") from None
        if (
            parsed.scheme != "https"
            or host is None
            or _HOST.fullmatch(host.lower()) is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or port not in (None, 443)
        ):
            raise _error("INVALID_MANIFEST")
    return payload


def _validate_public_base(public_base_url: str, allowed_hosts: Sequence[str]) -> str:
    if (
        type(public_base_url) is not str
        or not public_base_url
        or not isinstance(allowed_hosts, Sequence)
        or isinstance(allowed_hosts, (str, bytes))
        or not allowed_hosts
        or len(allowed_hosts) > 16
    ):
        raise _error("PUBLIC_BASE_URL_REQUIRED")
    try:
        parsed = urlsplit(public_base_url)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise _error("INVALID_PUBLIC_BASE_URL") from None
    if (
        parsed.scheme != "https"
        or host is None
        or _HOST.fullmatch(host.lower()) is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
        or port not in (None, 443)
    ):
        raise _error("INVALID_PUBLIC_BASE_URL")
    normalized_hosts: set[str] = set()
    for item in allowed_hosts:
        if type(item) is not str or _HOST.fullmatch(item.lower()) is None:
            raise _error("INVALID_ALLOWED_HOST")
        normalized_hosts.add(item.lower())
    if host.lower() not in normalized_hosts:
        raise _error("PUBLIC_HOST_NOT_ALLOWED")
    return f"https://{host.lower()}"


def _artifact_names(manifest: dict[str, object]) -> tuple[str, ...]:
    platforms = manifest["platforms"]
    assert type(platforms) is dict
    names: set[str] = set()
    for item in platforms.values():
        assert type(item) is dict
        path = urlsplit(item["url"]).path
        name = unquote(path.rsplit("/", 1)[-1])
        if _FILENAME.fullmatch(name) is None or name in {".", ".."}:
            raise _error("INVALID_ARTIFACT_URL")
        names.add(name)
    return tuple(sorted(names))


def _bundle_file(bundle: Path, filename: str) -> bytes:
    try:
        bundle_root = bundle.resolve(strict=True)
        if not bundle_root.is_dir():
            raise _error("BUNDLE_INVALID")
        source = (bundle_root / filename).resolve(strict=True)
        if not source.is_relative_to(bundle_root) or not source.is_file():
            raise _error("BUNDLE_INVALID")
        return source.read_bytes()
    except PublishError:
        raise
    except (OSError, RuntimeError, ValueError):
        raise _error("BUNDLE_INVALID") from None


def _manifest_bytes(response_body: bytes) -> tuple[bytes, dict[str, object]]:
    if type(response_body) is not bytes:
        raise _error("INVALID_MANIFEST")
    return response_body, _validate_manifest(response_body)


def publish(
    bucket: str,
    channel: str,
    bundle_dir: str | Path,
    client: R2S3Client,
    *,
    public_base_url: str,
    allowed_hosts: Sequence[str],
    dry_run: bool = False,
) -> PublishResult:
    """Validate a bundle, preflight immutable keys and publish latest last."""
    if channel not in _CHANNELS:
        raise _error("INVALID_CHANNEL")
    if type(dry_run) is not bool or type(client) is not R2S3Client:
        raise _error("INVALID_REQUEST")
    public_base = _validate_public_base(public_base_url, allowed_hosts)
    bundle = Path(bundle_dir)
    try:
        latest_path = bundle / "latest.json"
        latest_body = latest_path.read_bytes()
    except (OSError, ValueError):
        raise _error("BUNDLE_INVALID") from None
    manifest = _validate_manifest(latest_body)
    version = manifest["version"]
    assert type(version) is str
    platforms = manifest["platforms"]
    assert type(platforms) is dict
    filenames_by_platform: dict[str, str] = {}
    for platform, item in platforms.items():
        assert type(item) is dict
        filename = unquote(urlsplit(item["url"]).path.rsplit("/", 1)[-1])
        if _FILENAME.fullmatch(filename) is None:
            raise _error("INVALID_ARTIFACT_URL")
        filenames_by_platform[platform] = filename
    for platform, item in platforms.items():
        assert type(item) is dict
        filename = filenames_by_platform[platform]
        item["url"] = f"{public_base}/releases/{channel}/{version}/{filename}"
    latest_body = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if len(latest_body) > _MAX_MANIFEST_BYTES:
        raise _error("MANIFEST_TOO_LARGE")
    latest_key = f"channels/{channel}/latest.json"

    try:
        current = client.get_object(bucket, latest_key)
        if current is not None:
            _, current_manifest = _manifest_bytes(current.body)
            current_version = current_manifest["version"]
            if type(current_version) is not str or not _newer(version, current_version):
                raise _error("NON_MONOTONIC_VERSION")

        objects: list[tuple[str, bytes, str]] = []
        for filename in _artifact_names(manifest):
            body = _bundle_file(bundle, filename)
            key = f"releases/{channel}/{version}/{filename}"
            if client.head_object(bucket, key) is not None:
                raise _error("OBJECT_EXISTS")
            objects.append((key, body, "application/octet-stream"))

        latest_item = (latest_key, latest_body, "application/json")
        all_objects = [*objects, latest_item]
        if not dry_run:
            for key, body, content_type in objects:
                try:
                    client.put_object(bucket, key, body, content_type, if_none_match="*")
                except R2Error as exc:
                    if exc.code == "PRECONDITION_FAILED":
                        raise _error("OBJECT_EXISTS") from None
                    raise _error("R2_REQUEST_FAILED") from None
            client.put_object(
                bucket,
                latest_key,
                latest_body,
                "application/json",
                cache_control="no-store",
            )
        return PublishResult(
            action="publish",
            bucket=bucket,
            channel=channel,
            dry_run=dry_run,
            objects=tuple(
                PublishedObject(key, len(body), hashlib.sha256(body).hexdigest())
                for key, body, _ in all_objects
            ),
        )
    except R2Error:
        raise _error("R2_REQUEST_FAILED") from None


def create_bucket(bucket: str, client: R2S3Client, *, dry_run: bool = False) -> PublishResult:
    if type(dry_run) is not bool or type(client) is not R2S3Client:
        raise _error("INVALID_REQUEST")
    if not dry_run:
        try:
            client.create_bucket(bucket)
        except R2Error:
            raise _error("R2_REQUEST_FAILED") from None
    return PublishResult("create-bucket", bucket, None, dry_run, ())


def _summary(result: PublishResult) -> str:
    return json.dumps(
        {
            "action": result.action,
            "bucket": result.bucket,
            "channel": result.channel,
            "dry_run": result.dry_run,
            "objects": [
                {"key": item.key, "size": item.size, "sha256": item.sha256}
                for item in result.objects
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    client: R2S3Client | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    publish_parser = commands.add_parser("publish")
    publish_parser.add_argument("--bucket", required=True)
    publish_parser.add_argument("--channel", choices=sorted(_CHANNELS), required=True)
    publish_parser.add_argument("--bundle-dir", type=Path, required=True)
    publish_parser.add_argument("--public-base-url", required=True)
    publish_parser.add_argument("--allowed-host", action="append", required=True)
    publish_parser.add_argument("--dry-run", action="store_true")
    bucket_parser = commands.add_parser("create-bucket")
    bucket_parser.add_argument("--bucket", required=True)
    bucket_parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    sink = stdout if stdout is not None else sys.stdout
    error_sink = stderr if stderr is not None else sys.stderr
    active_client = client if client is not None else R2S3Client()
    try:
        if args.command == "publish":
            result = publish(
                args.bucket,
                args.channel,
                args.bundle_dir,
                active_client,
                public_base_url=args.public_base_url,
                allowed_hosts=args.allowed_host,
                dry_run=args.dry_run,
            )
        else:
            result = create_bucket(args.bucket, active_client, dry_run=args.dry_run)
    except PublishError as exc:
        error_sink.write(
            json.dumps({"error": exc.code}, sort_keys=True, separators=(",", ":")) + "\n"
        )
        return 1
    sink.write(_summary(result) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "PublishError",
    "PublishResult",
    "PublishedObject",
    "create_bucket",
    "main",
    "publish",
]
