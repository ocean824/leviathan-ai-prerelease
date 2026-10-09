"""Offline, nonsecret trading account binding validation.

This module never opens the vault or a provider session. Matching declared
account/session labels are not identity proof. A validated binding is metadata
evidence only and cannot authorize a broker action.
"""

from __future__ import annotations

import hashlib
import json
import re
import weakref
from collections.abc import Iterable
from dataclasses import InitVar, dataclass, field
from datetime import UTC, date, datetime, timezone
from typing import NoReturn, SupportsIndex

from leviathan_vault.client import CredentialRef, VaultStatus

_PROJECT = "leviathan-ai"
_ENVIRONMENTS = frozenset({"development", "live"})
_URI = re.compile(r"vault://leviathan-ai/(development|live)/([A-Z][A-Z0-9_]{2,79})\Z")
_BROKER = re.compile(r"[A-Z][A-Z0-9_.-]{1,31}\Z")
_PROTOCOL = re.compile(r"[A-Za-z][A-Za-z0-9._-]{1,63}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_VENUE = re.compile(r"[A-Z][A-Z0-9._-]{1,31}\Z")
_ISSUER = object()
_ISSUED: dict[int, tuple[weakref.ReferenceType[BindingValidationV1], str]] = {}


class TradingBindingError(ValueError):
    """A stable code with no input value, credential or account identifier."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> NoReturn:
    raise TradingBindingError(code)


def _text(value: object, pattern: re.Pattern[str], code: str) -> None:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail(code)


def _tuple_of_text(value: object, pattern: re.Pattern[str], code: str) -> None:
    if type(value) is not tuple or not value:
        _fail(code)
    if any(type(item) is not str or pattern.fullmatch(item) is None for item in value):
        _fail(code)
    if len(set(value)) != len(value):
        _fail("DUPLICATE_BINDING_SCOPE")


def _positive_int(value: object, code: str) -> None:
    if type(value) is not int or value < 1 or value.bit_length() > 63:
        _fail(code)


def _aware(value: object, code: str) -> None:
    # Built-in fixed-offset zones are immutable; arbitrary tzinfo objects are not.
    if type(value) is not datetime or type(value.tzinfo) is not timezone:
        _fail(code)


class _Frozen:
    def __copy__(self) -> NoReturn:
        _fail("FROZEN_BINDING")

    def __deepcopy__(self, memo: object) -> NoReturn:
        _fail("FROZEN_BINDING")

    def __reduce__(self) -> NoReturn:
        _fail("FROZEN_BINDING")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        _fail("FROZEN_BINDING")


def parse_credential_ref(uri: str, broker: str) -> CredentialRef:
    """Parse only the exact SEC-001 project/environment URI grammar."""
    _text(broker, _BROKER, "BROKER_INVALID")
    if type(uri) is not str or (match := _URI.fullmatch(uri)) is None:
        _fail("CREDENTIAL_REF_DENIED")
    return CredentialRef(
        provider=broker, name=match.group(2), scope=_PROJECT, environment=match.group(1)
    )


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class TradingAccountBindingV1(_Frozen):
    """Prepared metadata; capability flags never certify provider access."""

    project_id: str
    environment: str
    broker: str
    adapter_protocol: str
    adapter_version: str
    account_ref: str = field(repr=False)
    session_ref: str = field(repr=False)
    venue_allowlist: tuple[str, ...]
    instrument_allowlist: tuple[str, ...]
    instrument_mapping_revision: str
    instrument_mapping_date: date
    strategy_allowlist: tuple[str, ...]
    hard_risk_limit_revision: str
    session_mode: str
    credential_ref: str | None = field(default=None, repr=False)
    operator_session_required: bool = False
    can_read: bool = False
    can_cancel: bool = False
    can_submit: bool = False
    binding_revision: int = 1
    credential_revision: int = 1
    revoked: bool = False
    expires_at: datetime | None = None
    activation_actor: str | None = None
    activation_at: datetime | None = None
    activation_evidence_refs: tuple[str, ...] = ()
    provider_authentication: str = "NOT_TESTED"
    last_provider_auth_verified_at: datetime | None = None
    last_account_permission_verified_at: datetime | None = None

    def __post_init__(self) -> None:
        if (
            type(self.project_id) is not str
            or self.project_id != _PROJECT
            or type(self.environment) is not str
            or self.environment not in _ENVIRONMENTS
        ):
            _fail("BINDING_SCOPE_DENIED")
        _text(self.broker, _BROKER, "BROKER_INVALID")
        _text(self.adapter_protocol, _PROTOCOL, "ADAPTER_INVALID")
        _text(self.adapter_version, _TOKEN, "ADAPTER_INVALID")
        _text(self.account_ref, _TOKEN, "ACCOUNT_REF_INVALID")
        _text(self.session_ref, _TOKEN, "SESSION_REF_INVALID")
        _tuple_of_text(self.venue_allowlist, _VENUE, "VENUE_ALLOWLIST_INVALID")
        _tuple_of_text(self.instrument_allowlist, _TOKEN, "INSTRUMENT_ALLOWLIST_INVALID")
        _tuple_of_text(self.strategy_allowlist, _TOKEN, "STRATEGY_ALLOWLIST_INVALID")
        _text(self.instrument_mapping_revision, _TOKEN, "MAPPING_REVISION_INVALID")
        _text(self.hard_risk_limit_revision, _TOKEN, "RISK_REVISION_INVALID")
        if type(self.instrument_mapping_date) is not date:
            _fail("MAPPING_DATE_INVALID")
        if type(self.session_mode) is not str:
            _fail("SESSION_SCOPE_DENIED")
        if self.environment == "development" and self.session_mode not in ("paper", "demo"):
            _fail("SESSION_SCOPE_DENIED")
        if self.environment == "live" and self.session_mode != "live":
            _fail("SESSION_SCOPE_DENIED")
        for flag in (self.operator_session_required, self.can_read, self.can_cancel,
                     self.can_submit, self.revoked):
            if type(flag) is not bool:
                _fail("BOOLEAN_INVALID")
        _positive_int(self.binding_revision, "BINDING_REVISION_INVALID")
        _positive_int(self.credential_revision, "CREDENTIAL_REVISION_INVALID")
        if self.expires_at is not None:
            _aware(self.expires_at, "EXPIRY_INVALID")
        if self.operator_session_required:
            if self.credential_ref is not None:
                _fail("CREDENTIAL_REF_AMBIGUOUS")
        elif self.credential_ref is None:
            _fail("CREDENTIAL_REF_MISSING")
        else:
            parsed = parse_credential_ref(self.credential_ref, self.broker)
            if parsed.environment != self.environment:
                _fail("CREDENTIAL_ENVIRONMENT_DENIED")
        if (
            type(self.provider_authentication) is not str
            or self.provider_authentication != "NOT_TESTED"
            or self.last_provider_auth_verified_at is not None
            or self.last_account_permission_verified_at is not None
            or self.activation_actor is not None
            or self.activation_at is not None
            or type(self.activation_evidence_refs) is not tuple
            or self.activation_evidence_refs != ()
            or self.can_cancel
            or self.can_submit
        ):
            _fail("PROVIDER_VERIFICATION_REQUIRED")

    def __repr__(self) -> str:
        return "TradingAccountBindingV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class BindingRequestV1(_Frozen):
    environment: str
    broker: str
    account_ref: str = field(repr=False)
    session_ref: str = field(repr=False)
    venue: str
    instrument: str
    instrument_mapping_revision: str
    strategy_id: str
    hard_risk_limit_revision: str
    session_mode: str
    binding_revision: int
    credential_revision: int
    checked_at: datetime
    want_submit: bool = False

    def __post_init__(self) -> None:
        if type(self.environment) is not str or self.environment not in _ENVIRONMENTS:
            _fail("BINDING_SCOPE_DENIED")
        _text(self.broker, _BROKER, "BROKER_INVALID")
        _text(self.account_ref, _TOKEN, "ACCOUNT_REF_INVALID")
        _text(self.session_ref, _TOKEN, "SESSION_REF_INVALID")
        _text(self.venue, _VENUE, "VENUE_INVALID")
        _text(self.instrument, _TOKEN, "INSTRUMENT_INVALID")
        _text(self.instrument_mapping_revision, _TOKEN, "MAPPING_REVISION_INVALID")
        _text(self.strategy_id, _TOKEN, "STRATEGY_INVALID")
        _text(self.hard_risk_limit_revision, _TOKEN, "RISK_REVISION_INVALID")
        if type(self.session_mode) is not str or self.session_mode not in (
            "paper", "demo", "live"
        ):
            _fail("SESSION_SCOPE_DENIED")
        _positive_int(self.binding_revision, "BINDING_REVISION_INVALID")
        _positive_int(self.credential_revision, "CREDENTIAL_REVISION_INVALID")
        _aware(self.checked_at, "CHECK_TIME_INVALID")
        if type(self.want_submit) is not bool:
            _fail("BOOLEAN_INVALID")

    def __repr__(self) -> str:
        return "BindingRequestV1(<redacted>)"


@dataclass(frozen=True, slots=True, weakref_slot=True, repr=False, kw_only=True, init=False)
class BindingValidationV1(_Frozen):
    """Issued metadata-only result; never a provider or order capability."""

    binding_revision: int
    credential_revision: int
    _issuer: InitVar[object] = None

    def __init__(
        self,
        *,
        binding_revision: int,
        credential_revision: int,
        _issuer: object = None,
    ) -> None:
        existing = _ISSUED.get(id(self))
        if existing is not None and existing[0]() is self:
            _fail("FROZEN_BINDING")
        if _issuer is not _ISSUER:
            _fail("UNISSUED_VALIDATION")
        _positive_int(binding_revision, "BINDING_REVISION_INVALID")
        _positive_int(credential_revision, "CREDENTIAL_REVISION_INVALID")
        object.__setattr__(self, "binding_revision", binding_revision)
        object.__setattr__(self, "credential_revision", credential_revision)
        key = id(self)
        _ISSUED[key] = (weakref.ref(self), self._digest())
        weakref.finalize(self, _ISSUED.pop, key, None)

    def _digest(self) -> str:
        try:
            payload = json.dumps(
                [self.binding_revision, self.credential_revision],
                separators=(",", ":"),
                allow_nan=False,
            ).encode("ascii")
        except (TypeError, ValueError, AttributeError):
            return ""
        return hashlib.sha256(payload).hexdigest()

    @property
    def metadata_valid(self) -> bool:
        entry = _ISSUED.get(id(self))
        return entry is not None and entry[0]() is self and entry[1] == self._digest()

    @property
    def submit_capable(self) -> bool:
        return False

    @property
    def provider_authentication(self) -> str:
        return "NOT_TESTED"

    def __repr__(self) -> str:
        return "BindingValidationV1(<metadata-only>)"


def validate_binding(
    binding: TradingAccountBindingV1,
    request: BindingRequestV1,
    *,
    credential_status: VaultStatus | None = None,
) -> BindingValidationV1:
    """Check one exact scoped binding without reading a vault or provider."""
    if type(binding) is not TradingAccountBindingV1 or type(request) is not BindingRequestV1:
        _fail("BINDING_TYPE_INVALID")
    # Frozen dataclasses can still be changed through object.__setattr__.
    # Recheck their complete invariants at the trust boundary.
    binding.__post_init__()
    request.__post_init__()
    if binding.revoked:
        _fail("BINDING_REVOKED")
    if binding.expires_at is not None and request.checked_at >= binding.expires_at:
        _fail("BINDING_EXPIRED")
    # Mapping revisions use the UTC calendar, independent of the caller's offset.
    if binding.instrument_mapping_date > request.checked_at.astimezone(UTC).date():
        _fail("MAPPING_NOT_EFFECTIVE")
    if binding.environment != request.environment:
        _fail("BINDING_SCOPE_DENIED")
    if binding.broker != request.broker:
        _fail("BROKER_MISMATCH")
    if binding.account_ref != request.account_ref:
        _fail("ACCOUNT_MISMATCH")
    if binding.session_ref != request.session_ref or binding.session_mode != request.session_mode:
        _fail("SESSION_MISMATCH")
    if request.venue not in binding.venue_allowlist:
        _fail("VENUE_DENIED")
    if request.instrument not in binding.instrument_allowlist:
        _fail("INSTRUMENT_DENIED")
    if request.instrument_mapping_revision != binding.instrument_mapping_revision:
        _fail("MAPPING_REVISION_MISMATCH")
    if request.strategy_id not in binding.strategy_allowlist:
        _fail("STRATEGY_DENIED")
    if request.hard_risk_limit_revision != binding.hard_risk_limit_revision:
        _fail("RISK_REVISION_MISMATCH")
    if request.binding_revision != binding.binding_revision:
        _fail("BINDING_REVISION_MISMATCH")
    if request.credential_revision != binding.credential_revision:
        _fail("CREDENTIAL_ROTATED")
    if binding.operator_session_required:
        if credential_status is not None:
            _fail("CREDENTIAL_REF_AMBIGUOUS")
    else:
        if binding.credential_ref is None:
            _fail("CREDENTIAL_REF_MISSING")
        parsed = parse_credential_ref(binding.credential_ref, binding.broker)
        if (
            type(credential_status) is not VaultStatus
            or type(credential_status.name) is not str
            or type(credential_status.scope) is not str
            or type(credential_status.environment) is not str
            or type(credential_status.status) is not str
            or type(credential_status.provider_authentication) is not str
            or credential_status.name != parsed.name
            or credential_status.scope != parsed.scope
            or credential_status.environment != parsed.environment
            or credential_status.status != "ENCRYPTED_ROUNDTRIP_VERIFIED"
            or credential_status.provider_authentication != "NOT_TESTED"
        ):
            _fail("CREDENTIAL_STATUS_DENIED")
    if request.want_submit:
        _fail("PROVIDER_VERIFICATION_REQUIRED")
    return BindingValidationV1(
        binding_revision=binding.binding_revision,
        credential_revision=binding.credential_revision,
        _issuer=_ISSUER,
    )


def validate_binding_set(
    bindings: Iterable[TradingAccountBindingV1],
) -> tuple[TradingAccountBindingV1, ...]:
    """Deny duplicate accounts, sessions and credential refs without fallback."""
    if isinstance(bindings, (str, bytes)):
        _fail("BINDING_TYPE_INVALID")
    try:
        records = tuple(bindings)
    except TypeError:
        _fail("BINDING_TYPE_INVALID")
    accounts: set[tuple[str, str]] = set()
    sessions: set[tuple[str, str]] = set()
    credentials: set[str] = set()
    for binding in records:
        if type(binding) is not TradingAccountBindingV1:
            _fail("BINDING_TYPE_INVALID")
        binding.__post_init__()
        # The same broker account or session cannot appear in both environments.
        account = (binding.broker, binding.account_ref)
        session = (binding.broker, binding.session_ref)
        if account in accounts or session in sessions:
            _fail("DUPLICATE_BINDING_SCOPE")
        if binding.credential_ref is not None:
            if binding.credential_ref in credentials:
                _fail("DUPLICATE_CREDENTIAL_REF")
            credentials.add(binding.credential_ref)
        accounts.add(account)
        sessions.add(session)
    return records
