"""Shared lesson-19 display-label and identifier safety rules."""

from __future__ import annotations

import re

from leviathan_core.text.credential_patterns import contains_credential_value

_DISPLAY_LABEL_GRAMMAR = re.compile(
    r"[A-Za-z]{1,16}[0-9]{0,3}(?:[ -][A-Za-z]{1,16}[0-9]{0,3}){0,2}\Z",
    re.ASCII,
)
_IDENTIFIER_GRAMMAR = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z", re.ASCII)
_LONG_DIGIT_RUN = re.compile(r"[0-9]{9,}", re.ASCII)
_LETTER_THEN_DIGITS = re.compile(r"[A-Za-z]+[0-9]+\Z", re.ASCII)
_VERSION_TOKEN = re.compile(r"v[0-9]{1,3}\Z", re.ASCII | re.IGNORECASE)

# Keep this policy table in sync with apps/terminal/src/shared/safeLabel.ts.
LESSON_19_DENY_WORDS = frozenset(
    {
        "api",
        "apikey",
        "akia",
        "auth",
        "authorization",
        "bearer",
        "cert",
        "certificate",
        "cookie",
        "credential",
        "credentials",
        "ghp",
        "jwt",
        "key",
        "mnemonic",
        "password",
        "passwd",
        "pem",
        "private",
        "secret",
        "secrets",
        "session",
        "sk",
        "signature",
        "signing",
        "ssh",
        "token",
        "tokens",
        "wallet",
        "xox",
    }
)
LESSON_19_SECRET_PREFIXES = ("sk_", "ghp_", "gho_", "ghr_", "ghs_", "ghu_", "xox", "akia", "ya29.")
LESSON_19_COMPOUND_DENY_WORDS = frozenset(
    {
        "apikey",
        "apikeyprod",
        "api_key",
        "api_key_prod",
        "authcenter",
        "bearerplan",
        "mysecret",
        "mysecretkey",
        "my_secret",
        "password",
        "pass_word",
        "passwd",
        "pass_wd",
        "passwdvault",
    }
)


def _safe_text(
    value: str,
    *,
    reject_letter_digit_tokens: bool,
    strip_display_suffix_digits: bool = False,
) -> bool:
    if _LONG_DIGIT_RUN.search(value) is not None:
        return False

    normalized = value.casefold()
    segments = re.split(r"[ -]", normalized)
    segments = [segment for segment in segments if segment]
    denied_segments = (
        [re.sub(r"[0-9]{1,3}$", "", segment) for segment in segments]
        if strip_display_suffix_digits
        else segments
    )
    if any(segment in LESSON_19_DENY_WORDS for segment in denied_segments):
        return False
    if any(segment in LESSON_19_COMPOUND_DENY_WORDS for segment in denied_segments):
        return False
    if any(
        normalized.startswith(separator + prefix)
        for prefix in LESSON_19_SECRET_PREFIXES
        for separator in " .:/_-"
    ) or normalized.startswith(LESSON_19_SECRET_PREFIXES):
        return False
    if reject_letter_digit_tokens and any(
        _LETTER_THEN_DIGITS.fullmatch(segment) is not None
        and _VERSION_TOKEN.fullmatch(segment) is None
        for segment in segments
    ):
        return False

    return not contains_credential_value(value)


def is_safe_display_label(value: object) -> bool:
    """Return whether *value* is a bounded, non-sensitive display label."""
    return (
        type(value) is str
        and len(value) <= 40
        and _DISPLAY_LABEL_GRAMMAR.fullmatch(value) is not None
        and _safe_text(
            value,
            reject_letter_digit_tokens=False,
            strip_display_suffix_digits=True,
        )
    )


def is_safe_identifier(value: object) -> bool:
    """Return whether *value* is a bounded, non-sensitive ASCII identifier."""
    return (
        type(value) is str
        and _IDENTIFIER_GRAMMAR.fullmatch(value) is not None
        and _safe_text(value, reject_letter_digit_tokens=True)
        and not _contains_identifier_credential(value)
    )


def contains_deny_word(value: str) -> bool:
    """Return whether a separated segment is an existing lesson-19 deny word."""
    return any(
        segment.casefold() in LESSON_19_DENY_WORDS
        for segment in re.split(r"[_\-\s.:/]+", value)
        if segment
    )


def _contains_identifier_credential(value: str) -> bool:
    """Scan every identifier token start so underscores cannot hide secrets."""
    separators = "_-.:/"
    return any(
        contains_credential_value(value[index:])
        for index in range(len(value))
        if index == 0 or value[index - 1] in separators
    )
