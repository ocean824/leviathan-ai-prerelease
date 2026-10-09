"""Content-free errors for sealed issuance."""

from __future__ import annotations

from typing import Final

SEAL_CODES: Final[frozenset[str]] = frozenset({
    "SEAL_NOT_ISSUED",
    "SEAL_TAMPERED",
    "SEAL_WRONG_ISSUER",
    "SEAL_ALREADY_ISSUED",
    "SEAL_UNSUPPORTED_TYPE",
    "SEAL_INVALID_TAG",
    "SEAL_DUPLICATE_TAG",
    "SEAL_FORBIDDEN_OPERATION",
    "SEAL_DIGEST_LIMIT",
    "SEAL_INVALID_MODEL",
})


class SealError(ValueError):
    """An error whose message and arguments contain only a closed code."""

    def __init__(self, code: str) -> None:
        safe_code = code if type(code) is str and code in SEAL_CODES else "SEAL_INVALID_MODEL"
        self.code = safe_code
        super().__init__(safe_code)
