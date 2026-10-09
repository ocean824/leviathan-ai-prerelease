"""Immutable boundary values for archived session reads."""

from __future__ import annotations

import re
from dataclasses import InitVar, dataclass
from dataclasses import field as dataclass_field
from datetime import datetime
from decimal import Decimal
from typing import Literal, NoReturn, SupportsIndex
from uuid import UUID

from leviathan_core.numeric import NumericError, parse_decimal
from leviathan_core.seal import Issuer, SealError, require

EntityType = Literal["signal", "session", "instrument"]
MappingField = Literal["state", "session", "signal"]
_FIELDS = frozenset(("state", "session", "signal"))
_ENTITIES = frozenset(("signal", "session", "instrument"))
_LINK = re.compile(r'^</signals/([0-9a-f-]{36})>; rel="successor"$')
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ERROR_STATUS = {
    "INVALID_REQUEST": 400,
    "NOT_FOUND": 404,
    "LEGACY_ARCHIVED": 410,
    "UNMAPPABLE_STATE": 422,
    "UPSTREAM_UNAVAILABLE": 502,
}
_READ_RESULT_ISSUER = Issuer("lss001.read.v1")
_WRITE_RESULT_ISSUER = Issuer("lss001.write.v1")
_UTC_HEADER = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:Z|\+00:00)$"
)


class LegacyBoundaryError(ValueError):
    """A fixed-code boundary failure that never contains supplied values."""

    def __init__(self, code: str, field_paths: tuple[str, ...] = ()) -> None:
        self.code = code
        self.field_paths = field_paths
        super().__init__(code)


class _FrozenBoundary:
    __slots__ = ()

    def __copy__(self) -> NoReturn:
        raise LegacyBoundaryError("FROZEN_OBJECT")

    def __deepcopy__(self, memo: dict[int, object]) -> NoReturn:
        del memo
        raise LegacyBoundaryError("FROZEN_OBJECT")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise LegacyBoundaryError("FROZEN_OBJECT")

    def __setstate__(self, state: object) -> NoReturn:
        del state
        raise LegacyBoundaryError("FROZEN_OBJECT")


def _reject_issued_reinit(value: object, issuer: Issuer) -> None:
    try:
        require(value, issuer.tag)
    except SealError as exc:
        if exc.code == "SEAL_NOT_ISSUED":
            return
        raise LegacyBoundaryError("FROZEN_OBJECT") from None
    raise LegacyBoundaryError("FROZEN_OBJECT")


@dataclass(frozen=True, slots=True)
class LegacySuccessorIdV1(_FrozenBoundary):
    """A typed entity ID used with the kernel's fixed successor URL."""

    __setstate__ = _FrozenBoundary.__setstate__
    value: str

    def __post_init__(self) -> None:
        if (
            type(self.value) is not str
            or self.value != self.value.lower()
            or not _uuid4(self.value)
        ):
            raise LegacyBoundaryError("INVALID_SUCCESSOR", ("successor_id",))


def _text(value: object, field: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise LegacyBoundaryError("INVALID_FIELD", (field,))


def _optional_text(value: object, field: str) -> None:
    if value is not None:
        _text(value, field)


def _uuid4(value: str) -> bool:
    try:
        parsed = UUID(value)
    except ValueError:
        return False
    return parsed.version == 4 and str(parsed) == value.lower()


def _successor_url(successor_id: str) -> str:
    return f"/signals/{successor_id}"


def _link_value(successor_id: str) -> str:
    return f'<{_successor_url(successor_id)}>; rel="successor"'


def _read_headers(headers: tuple[tuple[str, str], ...], status_code: int) -> None:
    _pairs(headers, "headers")
    values = dict(headers)
    if len(values) != len(headers) or set(values) not in (
        {"Deprecation", "Sunset"},
        {"Deprecation", "Sunset", "Link"},
    ):
        raise LegacyBoundaryError("INVALID_RESULT", ("headers",))
    if values["Deprecation"] != "true" or not _UTC_HEADER.fullmatch(values["Sunset"]):
        raise LegacyBoundaryError("INVALID_RESULT", ("headers",))
    try:
        datetime.fromisoformat(values["Sunset"].replace("Z", "+00:00"))
    except ValueError:
        raise LegacyBoundaryError("INVALID_RESULT", ("headers",)) from None
    link = values.get("Link")
    if (status_code == 400) != (link is None):
        raise LegacyBoundaryError("INVALID_RESULT", ("headers",))
    if link is not None:
        match = _LINK.fullmatch(link)
        if match is None or not _uuid4(match.group(1)):
            raise LegacyBoundaryError("INVALID_RESULT", ("headers",))


def _ns(value: object, field: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise LegacyBoundaryError("INVALID_TIME", (field,))


def _pairs(value: object, field: str) -> None:
    if not isinstance(value, tuple):
        raise LegacyBoundaryError("INVALID_FIELD", (field,))
    for pair in value:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise LegacyBoundaryError("INVALID_FIELD", (field,))
        for item in pair:
            _text(item, field)


def _strings(value: object, field: str) -> None:
    if not isinstance(value, tuple):
        raise LegacyBoundaryError("INVALID_FIELD", (field,))
    for item in value:
        _text(item, field)


def _confidence(value: object) -> Decimal | None:
    if value is None:
        return None
    if type(value) is not Decimal:
        raise LegacyBoundaryError("INVALID_CONFIDENCE", ("confidence",))
    try:
        return parse_decimal(
            value,
            field="confidence",
            max_sig_digits=34,
            max_abs_adjusted=38,
            min_value=Decimal(0),
            max_value=Decimal(1),
        )
    except NumericError as exc:
        code = "PRECISION_EXCEEDED" if exc.code == "PRECISION_EXCEEDED" else "INVALID_CONFIDENCE"
        raise LegacyBoundaryError(code, ("confidence",)) from None


@dataclass(frozen=True, slots=True)
class LegacyReadRequestV1(_FrozenBoundary):
    __setstate__ = _FrozenBoundary.__setstate__
    tenant_id: str
    entity_type: str
    entity_id: str
    trace_id: str
    from_utc: str | None = None
    to_utc: str | None = None

    def __post_init__(self) -> None:
        # Keep malformed scalar input for the translator's typed 400 descriptor.
        # Reject containers, which could make a frozen request mutable by aliasing.
        for field in ("tenant_id", "entity_type", "entity_id", "trace_id", "from_utc", "to_utc"):
            if not isinstance(getattr(self, field), (str, int, bool, type(None))):
                raise LegacyBoundaryError("INVALID_REQUEST_TYPE", (field,))


@dataclass(frozen=True, slots=True)
class CanonicalSignalStateV1(_FrozenBoundary):
    """An already authenticated, tenant-scoped immutable source snapshot."""

    __setstate__ = _FrozenBoundary.__setstate__
    tenant_id: str
    entity_type: EntityType
    entity_id: str
    as_of_ns: int
    availability_ns: int
    source_version: str
    trace_id: str
    state: str | None = None
    session: str | None = None
    signal: str | None = None
    confidence: Decimal | None = None
    session_start_ns: int | None = None
    session_end_ns: int | None = None
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field in ("tenant_id", "entity_id", "source_version", "trace_id"):
            _text(getattr(self, field), field)
        if not _uuid4(self.entity_id):
            raise LegacyBoundaryError("INVALID_FIELD", ("entity_id",))
        if not isinstance(self.entity_type, str) or self.entity_type not in _ENTITIES:
            raise LegacyBoundaryError("INVALID_FIELD", ("entity_type",))
        for field in ("as_of_ns", "availability_ns"):
            _ns(getattr(self, field), field)
        for field in ("session_start_ns", "session_end_ns"):
            _ns(getattr(self, field), field, nullable=True)
        if (
            self.session_start_ns is not None
            and self.session_end_ns is not None
            and self.session_start_ns >= self.session_end_ns
        ):
            raise LegacyBoundaryError("INVALID_TIME", ("session_start_ns", "session_end_ns"))
        if not isinstance(self.evidence, (tuple, list)):
            raise LegacyBoundaryError("INVALID_FIELD", ("evidence",))
        evidence = tuple(self.evidence)
        _strings(evidence, "evidence")
        object.__setattr__(self, "evidence", evidence)
        for field in ("state", "session", "signal"):
            value = getattr(self, field)
            if value is not None:
                _text(value, field)
        object.__setattr__(self, "confidence", _confidence(self.confidence))


@dataclass(frozen=True, slots=True)
class LegacyEnumMappingV1(_FrozenBoundary):
    __setstate__ = _FrozenBoundary.__setstate__
    field: MappingField
    canonical: str
    legacy: str
    compatible: bool = False
    note: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.field, str) or self.field not in _FIELDS:
            raise LegacyBoundaryError("INVALID_MAPPING", ("field",))
        for field in ("canonical", "legacy"):
            _text(getattr(self, field), field)
        if type(self.compatible) is not bool:
            raise LegacyBoundaryError("INVALID_MAPPING", ("compatible",))
        if self.note is not None:
            _text(self.note, "note")
        if self.compatible and self.note is None:
            raise LegacyBoundaryError("INVALID_MAPPING", ("note",))


@dataclass(frozen=True, slots=True)
class LegacyMappingPolicyV1(_FrozenBoundary):
    __setstate__ = _FrozenBoundary.__setstate__
    mapping_version: str
    schema_sha256: str
    mappings: tuple[LegacyEnumMappingV1, ...]
    sunset_utc: str
    retention_start_ns: int
    hard_sunset: bool = False
    null_defaults: tuple[tuple[MappingField, str], ...] = ()

    def __post_init__(self) -> None:
        _text(self.mapping_version, "mapping_version")
        if not isinstance(self.schema_sha256, str) or not _SHA256.fullmatch(self.schema_sha256):
            raise LegacyBoundaryError("INVALID_MAPPING", ("schema_sha256",))
        if not isinstance(self.sunset_utc, str) or not _UTC_HEADER.fullmatch(self.sunset_utc):
            raise LegacyBoundaryError("INVALID_MAPPING", ("sunset_utc",))
        try:
            datetime.fromisoformat(self.sunset_utc.replace("Z", "+00:00"))
        except ValueError as exc:
            raise LegacyBoundaryError("INVALID_MAPPING", ("sunset_utc",)) from exc
        _ns(self.retention_start_ns, "retention_start_ns")
        if type(self.hard_sunset) is not bool:
            raise LegacyBoundaryError("INVALID_MAPPING", ("hard_sunset",))
        if not isinstance(self.mappings, (tuple, list)):
            raise LegacyBoundaryError("INVALID_MAPPING", ("mappings",))
        mappings = tuple(self.mappings)
        if any(not isinstance(item, LegacyEnumMappingV1) for item in mappings):
            raise LegacyBoundaryError("INVALID_MAPPING", ("mappings",))
        mapping_keys = [(item.field, item.canonical) for item in mappings]
        if len(set(mapping_keys)) != len(mapping_keys):
            raise LegacyBoundaryError("INVALID_MAPPING", ("mappings",))
        object.__setattr__(self, "mappings", mappings)
        _pairs(self.null_defaults, "null_defaults")
        if any(field not in _FIELDS for field, _ in self.null_defaults):
            raise LegacyBoundaryError("INVALID_MAPPING", ("null_defaults",))
        null_fields = [field for field, _ in self.null_defaults]
        if len(set(null_fields)) != len(null_fields):
            raise LegacyBoundaryError("INVALID_MAPPING", ("null_defaults",))


@dataclass(frozen=True, slots=True)
class LegacySignalPayloadV1(_FrozenBoundary):
    __setstate__ = _FrozenBoundary.__setstate__
    entity_type: EntityType
    entity_id: str
    state: str | None
    session: str | None
    signal: str | None
    confidence: Decimal | None
    session_start_ns: int | None
    session_end_ns: int | None
    evidence: tuple[str, ...]
    as_of_ns: int
    source_version: str
    mapping_version: str
    schema_sha256: str
    trace_id: str
    degraded: bool
    mapping_notes: tuple[str, ...]
    clipped: bool
    availability_ns: int

    def __post_init__(self) -> None:
        if not isinstance(self.entity_type, str) or self.entity_type not in _ENTITIES:
            raise LegacyBoundaryError("INVALID_FIELD", ("entity_type",))
        for field in (
            "entity_id",
            "source_version",
            "mapping_version",
            "schema_sha256",
            "trace_id",
        ):
            _text(getattr(self, field), field)
        if not _uuid4(self.entity_id):
            raise LegacyBoundaryError("INVALID_FIELD", ("entity_id",))
        if not _SHA256.fullmatch(self.schema_sha256):
            raise LegacyBoundaryError("INVALID_FIELD", ("schema_sha256",))
        for field in ("state", "session", "signal"):
            _optional_text(getattr(self, field), field)
        for field in ("session_start_ns", "session_end_ns"):
            _ns(getattr(self, field), field, nullable=True)
        if (
            self.session_start_ns is not None
            and self.session_end_ns is not None
            and self.session_start_ns > self.session_end_ns
        ):
            raise LegacyBoundaryError("INVALID_TIME", ("session_start_ns", "session_end_ns"))
        _strings(self.evidence, "evidence")
        _strings(self.mapping_notes, "mapping_notes")
        if type(self.degraded) is not bool or type(self.clipped) is not bool:
            raise LegacyBoundaryError("INVALID_FIELD", ("degraded", "clipped"))
        if self.degraded != bool(self.mapping_notes):
            raise LegacyBoundaryError("INVALID_FIELD", ("degraded", "mapping_notes"))
        _ns(self.as_of_ns, "as_of_ns")
        _ns(self.availability_ns, "availability_ns")
        if self.availability_ns < self.as_of_ns:
            raise LegacyBoundaryError("INVALID_TIME", ("availability_ns",))
        object.__setattr__(self, "confidence", _confidence(self.confidence))


@dataclass(frozen=True, slots=True)
class LegacyReadErrorV1(_FrozenBoundary):
    __setstate__ = _FrozenBoundary.__setstate__
    code: str
    trace_id: str
    field_paths: tuple[str, ...] = ()
    remediation: str | None = None

    def __post_init__(self) -> None:
        for field in ("code", "trace_id"):
            _text(getattr(self, field), field)
        if self.code not in _ERROR_STATUS:
            raise LegacyBoundaryError("INVALID_RESULT", ("code",))
        _optional_text(self.remediation, "remediation")
        _strings(self.field_paths, "field_paths")


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class LegacyReadResultV1(_FrozenBoundary):
    status_code: int
    headers: tuple[tuple[str, str], ...]
    payload: LegacySignalPayloadV1 | None = None
    error: LegacyReadErrorV1 | None = None
    schema_sha256: str | None = None
    availability_ns: int | None = None
    _issuer: InitVar[object] = None
    _seal: bool = dataclass_field(init=False, repr=False, compare=False)

    def __setstate__(self, state: object) -> NoReturn:
        del state
        raise LegacyBoundaryError("FROZEN_OBJECT")

    def __init__(
        self,
        status_code: int,
        headers: tuple[tuple[str, str], ...],
        payload: LegacySignalPayloadV1 | None = None,
        error: LegacyReadErrorV1 | None = None,
        schema_sha256: str | None = None,
        availability_ns: int | None = None,
        _issuer: object = None,
    ) -> None:
        if _issuer is not _READ_RESULT_ISSUER:
            raise LegacyBoundaryError("INVALID_RESULT_ISSUER")
        _reject_issued_reinit(self, _READ_RESULT_ISSUER)
        for name, value in (
            ("status_code", status_code),
            ("headers", headers),
            ("payload", payload),
            ("error", error),
            ("schema_sha256", schema_sha256),
            ("availability_ns", availability_ns),
        ):
            object.__setattr__(self, name, value)
        self.__post_init__(_issuer)

    def __post_init__(self, _issuer: object) -> None:
        if _issuer is not _READ_RESULT_ISSUER:
            raise LegacyBoundaryError("INVALID_RESULT_ISSUER")
        object.__setattr__(self, "_seal", True)
        _ns(self.status_code, "status_code")
        if self.status_code not in (200, 400, 404, 410, 422, 502):
            raise LegacyBoundaryError("INVALID_RESULT", ("status_code",))
        _read_headers(self.headers, self.status_code)
        if self.payload is not None and not isinstance(self.payload, LegacySignalPayloadV1):
            raise LegacyBoundaryError("INVALID_FIELD", ("payload",))
        if self.error is not None and not isinstance(self.error, LegacyReadErrorV1):
            raise LegacyBoundaryError("INVALID_FIELD", ("error",))
        if self.schema_sha256 is not None and (
            not isinstance(self.schema_sha256, str) or not _SHA256.fullmatch(self.schema_sha256)
        ):
            raise LegacyBoundaryError("INVALID_FIELD", ("schema_sha256",))
        _ns(self.availability_ns, "availability_ns", nullable=True)
        if self.status_code == 200:
            if (
                self.payload is None
                or self.error is not None
                or self.schema_sha256 != self.payload.schema_sha256
                or self.availability_ns != self.payload.availability_ns
                or dict(self.headers).get("Link") != _link_value(self.payload.entity_id.lower())
            ):
                raise LegacyBoundaryError("INVALID_RESULT")
        elif (
            self.payload is not None
            or self.error is None
            or _ERROR_STATUS[self.error.code] != self.status_code
            or self.schema_sha256 is not None
            or (self.status_code == 502) != (self.availability_ns is not None)
            or (self.status_code == 410) != (self.error.remediation == "migrate_to_successor")
        ):
            raise LegacyBoundaryError("INVALID_RESULT")


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ArchivedWriteDecisionV1(_FrozenBoundary):
    status_code: int
    code: str
    successor_id: LegacySuccessorIdV1
    headers: tuple[tuple[str, str], ...]
    _issuer: InitVar[object] = None
    _seal: bool = dataclass_field(init=False, repr=False, compare=False)

    def __setstate__(self, state: object) -> NoReturn:
        del state
        raise LegacyBoundaryError("FROZEN_OBJECT")

    def __init__(
        self,
        status_code: int,
        code: str,
        successor_id: LegacySuccessorIdV1,
        headers: tuple[tuple[str, str], ...],
        _issuer: object = None,
    ) -> None:
        if _issuer is not _WRITE_RESULT_ISSUER:
            raise LegacyBoundaryError("INVALID_RESULT_ISSUER")
        _reject_issued_reinit(self, _WRITE_RESULT_ISSUER)
        for name, value in (
            ("status_code", status_code),
            ("code", code),
            ("successor_id", successor_id),
            ("headers", headers),
        ):
            object.__setattr__(self, name, value)
        self.__post_init__(_issuer)

    @property
    def successor(self) -> str:
        return _successor_url(self.successor_id.value)

    def __post_init__(self, _issuer: object) -> None:
        if _issuer is not _WRITE_RESULT_ISSUER:
            raise LegacyBoundaryError("INVALID_RESULT_ISSUER")
        object.__setattr__(self, "_seal", True)
        _ns(self.status_code, "status_code")
        _text(self.code, "code")
        if type(self.successor_id) is not LegacySuccessorIdV1:
            raise LegacyBoundaryError("INVALID_SUCCESSOR", ("successor_id",))
        if self.headers != (("Link", _link_value(self.successor_id.value)),):
            raise LegacyBoundaryError("INVALID_RESULT", ("headers",))
        if self.status_code != 410 or self.code != "LEGACY_ARCHIVED":
            raise LegacyBoundaryError("INVALID_RESULT")
