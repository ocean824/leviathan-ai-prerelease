from __future__ import annotations

import json
from pathlib import Path

import pytest

from leviathan_market_data.public_sources.api_anything_client import (
    PublicOperationError,
    PublicOperationErrorCode,
)
from leviathan_market_data.public_sources.api_anything_templates import import_pinned_template


def test_template_import_rejects_traversal_before_writing_outside_templates(
    tmp_path: Path,
) -> None:
    templates = tmp_path / "templates"
    templates.mkdir()
    registry = templates / "PINNED.json"
    digest = "a" * 64
    registry.write_text(
        json.dumps(
            {
                "operations": {
                    "cnn.fear_greed": {
                        "version": "v1",
                        "sha256": digest,
                        "template_path": "../../outside.json",
                        "allowed_hosts": ["www.cnn.com"],
                        "challenge_hosts": [],
                        "review_note": "reviewed",
                        "tos_review_id": "cnn-review",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle.json"
    bundle.write_text(
        json.dumps({"schema_version": 1, "operation_id": "cnn.fear_greed"}), encoding="utf-8"
    )

    with pytest.raises(PublicOperationError) as raised:
        import_pinned_template(bundle, registry_path=registry, data_dir=tmp_path / "state")

    assert raised.value.code is PublicOperationErrorCode.TEMPLATE_UNPINNED
    assert not (tmp_path / "outside.json").exists()
