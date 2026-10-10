"""Validation for the immutable sidecar identity supplied by the desktop shell."""

from __future__ import annotations

import hashlib

from leviathan_api.auth import LocalOperatorProfileV1, make_local_operator_profile


def session_identity_from_shell_env(
    principal_id: str | None,
    entitlement_sha256: str | None,
    features_csv: str | None,
) -> tuple[LocalOperatorProfileV1 | None, frozenset[str]]:
    """Accept only a valid subject and digest over the exact sorted feature list."""
    features = features_csv.split(",") if type(features_csv) is str and features_csv else []
    valid_features = features == sorted(set(features)) and all(
        feature and all(ch.isascii() and (ch.isalnum() or ch == "_") for ch in feature)
        for feature in features
    )
    valid_principal = (
        type(principal_id) is str
        and bool(principal_id)
        and len(principal_id) <= 128
        and principal_id[0].isascii()
        and principal_id[0].isalnum()
        and all(ch.isascii() and (ch.isalnum() or ch in "_.:-") for ch in principal_id)
    )
    valid_digest = (
        type(entitlement_sha256) is str
        and len(entitlement_sha256) == 64
        and all(ch in "0123456789abcdef" for ch in entitlement_sha256)
        and type(features_csv) is str
        and hashlib.sha256(features_csv.encode("utf-8")).hexdigest() == entitlement_sha256
    )
    if not (valid_principal and valid_digest and valid_features):
        return None, frozenset()
    return (
        make_local_operator_profile(
            principal_id=principal_id,
            project_id="leviathan-ai",
            env="paper",
        ),
        frozenset(features),
    )
