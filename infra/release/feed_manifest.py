"""Create deterministic signed Tauri updater manifests for desktop targets."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_PRERELEASE_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
_SEMVER = re.compile(
    rf"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    rf"(?:-({_PRERELEASE_IDENTIFIER}(?:\.{_PRERELEASE_IDENTIFIER})*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_ARTIFACT = "LeviathanAI_{version}_x64-setup.nsis.zip"


class FeedManifestError(ValueError):
    """A release manifest input violates the update feed contract."""


def _version_key(value: str) -> tuple[int, int, int, tuple[tuple[int, int | str], ...] | None]:
    match = _SEMVER.fullmatch(value)
    if match is None:
        raise FeedManifestError("invalid semantic version")
    major, minor, patch = (int(match.group(i)) for i in (1, 2, 3))
    prerelease = match.group(4)
    if prerelease is None:
        return major, minor, patch, None
    identifiers: list[tuple[int, int | str]] = []
    for item in prerelease.split("."):
        if item.isdigit():
            if len(item) > 1 and item.startswith("0"):
                raise FeedManifestError("invalid semantic version")
            identifiers.append((0, int(item)))
        else:
            identifiers.append((1, item))
    return major, minor, patch, tuple(identifiers)


def _newer(candidate: str, current: str) -> bool:
    left = _version_key(candidate)
    right = _version_key(current)
    if left[:3] != right[:3]:
        return left[:3] > right[:3]
    left_pre, right_pre = left[3], right[3]
    if left_pre is None:
        return right_pre is not None
    if right_pre is None:
        return False
    for left_item, right_item in zip(left_pre, right_pre, strict=False):
        if left_item == right_item:
            continue
        if left_item[0] != right_item[0]:
            return left_item[0] == 1
        if left_item[0] == 0:
            return int(left_item[1]) > int(right_item[1])
        return str(left_item[1]) > str(right_item[1])
    return len(left_pre) > len(right_pre)


def _normalize_pub_date(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise FeedManifestError("pub_date must be timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _base_url(value: str) -> str:
    if not isinstance(value, str):
        raise FeedManifestError("base_url must be an absolute HTTPS URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(char in value for char in "\r\n\t\\")
    ):
        raise FeedManifestError("base_url must be an absolute HTTPS URL")
    return value.rstrip("/")


def _safe_signature(signature: str | None, require_signature: bool) -> str | None:
    if signature is None:
        if require_signature:
            raise FeedManifestError("a signature is required")
        return None
    if not isinstance(signature, str) or not signature.strip() or "\x00" in signature:
        raise FeedManifestError("signature must be non-empty text")
    return signature.strip()


def _load_prior_version(path: Path | None) -> str | None:
    if path is None or not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        version = payload["version"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise FeedManifestError("prior latest.json is invalid") from exc
    if not isinstance(version, str):
        raise FeedManifestError("prior latest.json is invalid")
    _version_key(version)
    return version


def build_latest_manifest(
    *,
    base_url: str,
    version: str,
    notes: str,
    pub_date: datetime,
    signature: str | None,
    require_signature: bool = False,
    platform_artifacts: Mapping[str, tuple[str, str | None]] | None = None,
) -> dict[str, Any]:
    """Build a canonical Tauri v2 update manifest for supplied target artifacts."""
    _version_key(version)
    if not isinstance(notes, str):
        raise FeedManifestError("notes must be text")
    base = _base_url(base_url)
    if platform_artifacts is None:
        normalized_signature = _safe_signature(signature, require_signature)
        platform_artifacts = {
            "windows-x86_64": (_ARTIFACT.format(version=version), normalized_signature)
        }
    if not platform_artifacts or set(platform_artifacts) - {
        "windows-x86_64",
        "darwin-aarch64",
        "darwin-x86_64",
    }:
        raise FeedManifestError("unsupported update platform")
    platforms: dict[str, dict[str, str | None]] = {}
    for platform, (artifact, artifact_signature) in sorted(platform_artifacts.items()):
        target, arch = platform.split("-", 1)
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", artifact)
            or Path(artifact).name != artifact
            or "/" in artifact
            or "\\" in artifact
        ):
            raise FeedManifestError("invalid updater artifact name")
        checked_signature = _safe_signature(artifact_signature, require_signature)
        url = f"{base}/v1/updates/desktop/{target}/{arch}/{version}/{artifact}"
        platforms[platform] = {"signature": checked_signature, "url": url}
    base_parts = urlsplit(base)
    url_parts = urlsplit(url)
    if (
        url_parts.scheme != base_parts.scheme
        or url_parts.netloc != base_parts.netloc
        or not url_parts.path.startswith(base_parts.path.rstrip("/") + "/")
    ):
        raise FeedManifestError("update URL is outside the configured base")
    return {
        "version": version,
        "notes": notes,
        "pub_date": _normalize_pub_date(pub_date),
        "platforms": platforms,
    }


def write_latest_manifest(
    *,
    bundle_dir: Path,
    base_url: str,
    version: str,
    notes: str,
    pub_date: datetime,
    signature: str | None,
    require_signature: bool = False,
    prior_latest: Path | None = None,
    platform_artifacts: Mapping[str, tuple[str, str | None]] | None = None,
) -> Path:
    """Write deterministic `latest.json`, refusing equal or older releases."""
    prior_version = _load_prior_version(prior_latest)
    if prior_version is not None and not _newer(version, prior_version):
        raise FeedManifestError("release version must be newer than prior latest.json")
    payload = build_latest_manifest(
        base_url=base_url,
        version=version,
        notes=notes,
        pub_date=pub_date,
        signature=signature,
        require_signature=require_signature,
        platform_artifacts=platform_artifacts,
    )
    destination = Path(bundle_dir) / "latest.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    destination.write_text(serialized, encoding="utf-8", newline="\n")
    return destination


def _cli() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--feed", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--notes", default="")
    parser.add_argument("--pub-date", required=True)
    parser.add_argument("--signature-file", type=Path)
    parser.add_argument("--require-signature", action="store_true")
    parser.add_argument("--prior-latest", type=Path)
    parser.add_argument("--artifact", action="append", default=[], metavar="PLATFORM=FILENAME")
    parser.add_argument(
        "--platform-signature", action="append", default=[], metavar="PLATFORM=FILE"
    )
    args = parser.parse_args()
    try:
        feed = json.loads(args.feed.read_text(encoding="utf-8"))
        signature = (
            args.signature_file.read_text(encoding="utf-8")
            if args.signature_file is not None
            else None
        )
        platform_artifacts = None
        if args.artifact:
            files = dict(item.split("=", 1) for item in args.artifact)
            signatures = dict(item.split("=", 1) for item in args.platform_signature)
            platform_artifacts = {
                platform: (
                    filename,
                    Path(signatures[platform]).read_text(encoding="utf-8")
                    if platform in signatures
                    else None,
                )
                for platform, filename in files.items()
            }
            if set(signatures) - set(files):
                raise FeedManifestError("signature provided for an unknown platform")
        output = write_latest_manifest(
            bundle_dir=args.bundle_dir,
            base_url=feed["base"],
            version=args.version,
            notes=args.notes,
            pub_date=datetime.fromisoformat(args.pub_date.replace("Z", "+00:00")),
            signature=signature,
            require_signature=args.require_signature,
            platform_artifacts=platform_artifacts,
            prior_latest=args.prior_latest,
        )
    except (
        FeedManifestError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
    ) as exc:
        parser.error(str(exc))
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
