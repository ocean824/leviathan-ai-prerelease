from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from infra.release.feed_manifest import (
    FeedManifestError,
    build_latest_manifest,
    write_latest_manifest,
)

STAMP = datetime(2026, 10, 6, 12, 30, 0, tzinfo=UTC)


def test_manifest_is_deterministic_and_uses_platform_schema(tmp_path: Path) -> None:
    first = write_latest_manifest(
        bundle_dir=tmp_path / "a",
        base_url="https://releases.invalid",
        version="1.2.3",
        notes="release notes",
        pub_date=STAMP,
        signature="signed payload",
        require_signature=True,
    )
    second = write_latest_manifest(
        bundle_dir=tmp_path / "b",
        base_url="https://releases.invalid",
        version="1.2.3",
        notes="release notes",
        pub_date=STAMP,
        signature="signed payload",
        require_signature=True,
    )
    assert first.read_bytes() == second.read_bytes()
    payload = json.loads(first.read_text(encoding="utf-8"))
    assert payload == {
        "version": "1.2.3",
        "notes": "release notes",
        "pub_date": "2026-10-06T12:30:00Z",
        "platforms": {
            "windows-x86_64": {
                "signature": "signed payload",
                "url": "https://releases.invalid/v1/updates/desktop/windows/x86_64/1.2.3/LeviathanAI_1.2.3_x64-setup.nsis.zip",
            }
        },
    }
    assert payload["platforms"]["windows-x86_64"]["url"].startswith("https://releases.invalid/")


def test_prior_latest_must_increase_strictly(tmp_path: Path) -> None:
    prior = tmp_path / "prior.json"
    prior.write_text('{"version":"1.2.3"}', encoding="utf-8")
    arguments = {
        "bundle_dir": tmp_path / "bundle",
        "base_url": "https://releases.invalid",
        "notes": "",
        "pub_date": STAMP,
        "signature": None,
    }
    with pytest.raises(FeedManifestError, match="newer"):
        write_latest_manifest(version="1.2.3", prior_latest=prior, **arguments)
    with pytest.raises(FeedManifestError, match="newer"):
        write_latest_manifest(version="1.2.2", prior_latest=prior, **arguments)
    assert not (tmp_path / "bundle" / "latest.json").exists()


def test_manifest_supports_signed_per_architecture_darwin_artifacts() -> None:
    payload = build_latest_manifest(
        base_url="https://releases.invalid",
        version="1.2.3",
        notes="macOS release",
        pub_date=STAMP,
        signature=None,
        require_signature=True,
        platform_artifacts={
            "darwin-aarch64": ("LeviathanAI_1.2.3_aarch64.app.tar.gz", "arm signature"),
            "darwin-x86_64": ("LeviathanAI_1.2.3_x86_64.app.tar.gz", "intel signature"),
        },
    )
    assert payload["platforms"] == {
        "darwin-aarch64": {
            "signature": "arm signature",
            "url": "https://releases.invalid/v1/updates/desktop/darwin/aarch64/1.2.3/LeviathanAI_1.2.3_aarch64.app.tar.gz",
        },
        "darwin-x86_64": {
            "signature": "intel signature",
            "url": "https://releases.invalid/v1/updates/desktop/darwin/x86_64/1.2.3/LeviathanAI_1.2.3_x86_64.app.tar.gz",
        },
    }


def test_newer_prerelease_order_is_semver_aware(tmp_path: Path) -> None:
    prior = tmp_path / "prior.json"
    prior.write_text('{"version":"1.2.3-rc.1"}', encoding="utf-8")
    output = write_latest_manifest(
        bundle_dir=tmp_path,
        base_url="https://releases.invalid",
        version="1.2.3",
        notes="",
        pub_date=STAMP,
        signature=None,
        prior_latest=prior,
    )
    assert json.loads(output.read_text(encoding="utf-8"))["version"] == "1.2.3"


def test_required_signature_and_invalid_url_base_are_rejected() -> None:
    arguments = {
        "version": "1.0.0",
        "notes": "",
        "pub_date": STAMP,
        "signature": None,
    }
    with pytest.raises(FeedManifestError, match="signature"):
        build_latest_manifest(
            base_url="https://releases.invalid", require_signature=True, **arguments
        )
    with pytest.raises(FeedManifestError, match="HTTPS"):
        build_latest_manifest(
            base_url="http://releases.invalid", require_signature=False, **arguments
        )
    with pytest.raises(FeedManifestError, match="HTTPS"):
        build_latest_manifest(base_url="https://user:password@releases.invalid", **arguments)


def test_pub_date_must_be_timezone_aware() -> None:
    with pytest.raises(FeedManifestError, match="timezone-aware"):
        build_latest_manifest(
            base_url="https://releases.invalid",
            version="1.0.0",
            notes="",
            pub_date=datetime(2026, 10, 6),
            signature=None,
        )
