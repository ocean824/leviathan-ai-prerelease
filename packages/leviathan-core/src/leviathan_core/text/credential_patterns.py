"""Bounded, shared detection for common credential-shaped text values."""

from __future__ import annotations

import base64
import binascii
import json
import re

MAX_CREDENTIAL_SCAN_CHARS = 65_536

_JWT_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9])(?P<header>eyJ[A-Za-z0-9_-]{1,509})\."
    r"(?P<payload>[A-Za-z0-9_-]{1,8192})(?:\.(?P<signature>[A-Za-z0-9_-]{0,8192}))?"
    r"(?![A-Za-z0-9_-])",
    re.ASCII,
)

# These bounded patterns are kept aligned with omega_link.task_bridge until
# CL-CRED-PATTERN-DEDUP makes that consumer import this neutral module.
_CREDENTIAL_PATTERN_SOURCES = (
    r"\b[a-z][a-z0-9+.-]{0,31}://[^\s/@:]{1,128}:[^\s/@]{1,256}@",
    r"[?&;](?:api[_-]?key|token|secret)=[^&#;\s]{1,65536}",
    r"\bsk_(?:live|test)_[A-Za-z0-9_-]{4,65536}\b",
    r"\bgh[pso]_[A-Za-z0-9_-]{8,65536}\b",
    r"\bgh[ur]_[A-Za-z0-9_-]{8,65536}\b",
    r"\bgithub_pat_[A-Za-z0-9_]{8,65536}\b",
    r"\bxox[abpr]-[A-Za-z0-9-]{8,65536}\b",
    r"\bsk-[A-Za-z0-9_-]{8,65536}\b",
    r"\bglpat-[A-Za-z0-9_-]{8,65536}\b",
    r"\bAIza[A-Za-z0-9_-]{20,65536}\b",
    r"\bxoxe-[A-Za-z0-9-]{8,65536}\b",
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    r"\bhttps?://hooks\.slack\.com/services/[A-Za-z0-9/_-]{16,65536}",
    r"\bhttps?://discord(?:app)?\.com/api/webhooks/[0-9]{5,32}/[A-Za-z0-9._-]{16,65536}",
    r"\bhttps?://hooks\.[A-Za-z0-9.-]{1,253}/(?:services|webhooks|hooks)/[A-Za-z0-9/_-]{16,65536}",
    r"\b(?:password|passwd)\s{0,16}[:=]\s{0,16}[^\s,;]{1,65536}",
    r"\b(?:cookie|set-cookie|authorization)\s{0,16}[:=]\s{0,16}[^\r\n]{1,65536}",
    r"\bbearer\s{1,16}[A-Za-z0-9._~+/=-]{8,65536}",
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    r"\bpypi-[A-Za-z0-9_-]{8,65536}\b",
)
_CREDENTIAL_VALUE_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE | re.ASCII)
    for pattern in _CREDENTIAL_PATTERN_SOURCES
)


def _contains_jwt_shape(value: str) -> bool:
    """Recognize compact JWTs, including unsigned and weak-signature forms."""
    if "eyJ" not in value:
        return False

    def decode_segment(encoded: str) -> bytes:
        segment = encoded.encode("ascii")
        padded = segment + b"=" * (-len(segment) % 4)
        return base64.b64decode(padded, altchars=b"-_", validate=True)

    for match in _JWT_CANDIDATE.finditer(value):
        encoded_header = match.group("header")
        encoded_payload = match.group("payload")
        try:
            payload = json.loads(decode_segment(encoded_payload))
        except (UnicodeEncodeError, binascii.Error, json.JSONDecodeError, ValueError):
            continue
        if type(payload) is not dict:
            continue
        try:
            header = json.loads(decode_segment(encoded_header))
        except (UnicodeEncodeError, binascii.Error, json.JSONDecodeError, ValueError):
            signature = match.group("signature")
            if encoded_header.startswith("eyJ") and signature is not None and len(signature) >= 8:
                return True
            continue
        if type(header) is dict and type(header.get("alg")) is str and header["alg"]:
            return True
    return False


def contains_credential_value(value: str) -> bool:
    """Return whether *value* contains a known bounded credential shape.

    Inputs over the scanner's established 64 KiB bound fail closed. Consumers
    such as safe-label validation impose much smaller limits before calling.
    """
    if type(value) is not str:
        return True
    if len(value) > MAX_CREDENTIAL_SCAN_CHARS:
        return True
    return _contains_jwt_shape(value) or any(
        pattern.search(value) is not None for pattern in _CREDENTIAL_VALUE_PATTERNS
    )
