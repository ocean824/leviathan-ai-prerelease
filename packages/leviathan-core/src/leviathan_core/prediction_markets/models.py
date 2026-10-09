"""Offline prediction-market records and issued research results."""

from __future__ import annotations

import hashlib
import re
from dataclasses import InitVar, dataclass, fields
from decimal import Decimal
from fractions import Fraction
from typing import Any, NoReturn, SupportsIndex

from leviathan_core.numeric import NumericError, canonical_json, parse_decimal, parse_int
from leviathan_core.seal import Issuer, require
from leviathan_core.seal._registry import _is_registered_identity

MAX_UTC_NS = 253_402_300_799_999_999_999
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_VENUES = frozenset({"KALSHI", "POLYMARKET"})
_STATUSES = frozenset({"ACTIVE", "PAUSED", "RESOLVING", "RESOLVED", "DEPRECATED"})
_CURRENCIES = frozenset({"USD", "USDC"})
_ACCESS = frozenset({"PUBLIC", "AUTHENTICATED"})
_PRIOR_ISSUER = Issuer("pred001.prior.v1")
_MAPPING_ISSUER = Issuer("pred001.mapping.v1")
_RESOLUTION_ISSUER = Issuer("pred001.resolution.v1")


class PredictionError(ValueError):
    """Typed, content-free public failure."""

    __slots__ = ("code", "field")

    def __init__(self, code: str, field: str = "record") -> None:
        self.code = code
        self.field = field
        super().__init__(code, field)

    def __str__(self) -> str:
        return f"{self.code}:{self.field}"


class FrozenRecord:
    """Copy and pickle are not alternate validation paths."""

    __slots__ = ()

    def __copy__(self) -> NoReturn:
        raise PredictionError("FROZEN_RECORD")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise PredictionError("FROZEN_RECORD")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise PredictionError("FROZEN_RECORD")

    def __setstate__(self, state: object) -> NoReturn:
        raise PredictionError("FROZEN_RECORD")


def _token(value: object, field: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise PredictionError("INVALID_TOKEN", field)
    return value


def _text(value: object, field: str) -> str:
    if type(value) is not str or len(value) > 256:
        raise PredictionError("INVALID_TEXT", field)
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise PredictionError("INVALID_TEXT", field) from None
    return value


def _enum(value: object, allowed: frozenset[str], field: str) -> str:
    if type(value) is not str or value not in allowed:
        raise PredictionError("INVALID_ENUM", field)
    return value


def _ns(value: object, field: str) -> int:
    try:
        return parse_int(value, field=field, min_value=0, max_value=MAX_UTC_NS)
    except NumericError as exc:
        raise PredictionError(exc.code, field) from None


def _decimal(value: object, field: str, low: str = "0", high: str | None = None) -> Decimal:
    try:
        return parse_decimal(value, field=field, min_value=low, max_value=high)
    except NumericError as exc:
        raise PredictionError(exc.code, field) from None


def _digest_or_none(value: object, field: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise PredictionError("INVALID_DIGEST", field)
    return value


def _tags(value: object) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > 32:
        raise PredictionError("INVALID_TAGS", "tags")
    tags = tuple(_token(item, "tags") for item in value)
    if len(set(tags)) != len(tags):
        raise PredictionError("DUPLICATE_TAG", "tags")
    return tuple(sorted(tags))  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class PredictionSourceRecordV1(FrozenRecord):
    venue: str
    source_id: str
    contract_id: str
    outcome_id: str
    raw_quote_digest: str | None
    access_class: str
    entitlement_ref: str | None
    account_ref: str | None
    event_ns: int
    received_ns: int
    available_ns: int
    market_status: str
    resolution_version: str | None
    currency: str
    bid: Decimal
    ask: Decimal
    depth_1pct: Decimal | None
    depth_2pct: Decimal | None
    fee_rate: Decimal
    volatility: Decimal
    source_reliability: Decimal
    title: str = ""
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _enum(self.venue, _VENUES, "venue")
        for field in ("source_id", "contract_id", "outcome_id"):
            _token(getattr(self, field), field)
        _digest_or_none(self.raw_quote_digest, "raw_quote_digest")
        _enum(self.access_class, _ACCESS, "access_class")
        _token(self.entitlement_ref, "entitlement_ref", optional=True)
        _token(self.account_ref, "account_ref", optional=True)
        if self.access_class == "PUBLIC" and (self.entitlement_ref or self.account_ref):
            raise PredictionError("ACCESS_PROVENANCE_CONFLICT", "access_class")
        if self.access_class == "AUTHENTICATED" and not (self.entitlement_ref and self.account_ref):
            raise PredictionError("ACCESS_PROVENANCE_MISSING", "access_class")
        for field in ("event_ns", "received_ns", "available_ns"):
            _ns(getattr(self, field), field)
        if self.event_ns > self.received_ns or self.received_ns > self.available_ns:
            raise PredictionError("TIME_ORDER_INVALID", "available_ns")
        _enum(self.market_status, _STATUSES, "market_status")
        _token(self.resolution_version, "resolution_version", optional=True)
        _enum(self.currency, _CURRENCIES, "currency")
        for field in ("bid", "ask", "fee_rate", "volatility", "source_reliability"):
            object.__setattr__(self, field, _decimal(getattr(self, field), field, high="1"))
        if self.bid > self.ask:
            raise PredictionError("CROSSED_QUOTE", "bid")
        for field in ("depth_1pct", "depth_2pct"):
            value = getattr(self, field)
            if value is not None:
                object.__setattr__(self, field, _decimal(value, field))
        if (
            self.depth_1pct is not None
            and self.depth_2pct is not None
            and self.depth_1pct > self.depth_2pct
        ):
            raise PredictionError("DEPTH_ORDER_INVALID", "depth_1pct")
        _text(self.title, "title")
        object.__setattr__(self, "tags", _tags(self.tags))


@dataclass(frozen=True, slots=True)
class FXRateV1(FrozenRecord):
    from_currency: str
    to_currency: str
    rate: Decimal
    observed_ns: int
    available_ns: int
    source_id: str
    version: str

    def __post_init__(self) -> None:
        _enum(self.from_currency, _CURRENCIES, "from_currency")
        _enum(self.to_currency, _CURRENCIES, "to_currency")
        if self.from_currency == self.to_currency:
            raise PredictionError("FX_PAIR_INVALID", "from_currency")
        object.__setattr__(self, "rate", _decimal(self.rate, "rate"))
        if self.rate == 0:
            raise PredictionError("OUT_OF_RANGE", "rate")
        _ns(self.observed_ns, "observed_ns")
        _ns(self.available_ns, "available_ns")
        if self.observed_ns > self.available_ns:
            raise PredictionError("TIME_ORDER_INVALID", "available_ns")
        _token(self.source_id, "source_id")
        _token(self.version, "version")


def _fx_identity(rate: FXRateV1) -> str:
    """Bind the full selected observation, not a delimiter-joined source/version."""
    content = {field.name: getattr(rate, field.name) for field in fields(rate)}
    return hashlib.sha256(canonical_json(content)).hexdigest()


@dataclass(frozen=True, slots=True)
class OutcomeProbabilityV1(FrozenRecord):
    outcome_id: str
    probability: Decimal

    def __post_init__(self) -> None:
        _token(self.outcome_id, "outcome_id")
        object.__setattr__(self, "probability", _decimal(self.probability, "probability", high="1"))


@dataclass(frozen=True, slots=True)
class SourceReferenceV1(FrozenRecord):
    """The exact visible quote identity selected for one outcome."""

    outcome_id: str
    source_id: str
    raw_quote_digest: str | None
    access_class: str
    entitlement_ref: str | None
    account_ref: str | None
    event_ns: int
    available_ns: int
    currency: str
    conversion_ref: FXRateV1 | None

    def __post_init__(self) -> None:
        _token(self.outcome_id, "outcome_id")
        _token(self.source_id, "source_id")
        _digest_or_none(self.raw_quote_digest, "raw_quote_digest")
        _enum(self.access_class, _ACCESS, "access_class")
        _token(self.entitlement_ref, "entitlement_ref", optional=True)
        _token(self.account_ref, "account_ref", optional=True)
        if self.access_class == "PUBLIC" and (self.entitlement_ref or self.account_ref):
            raise PredictionError("ACCESS_PROVENANCE_CONFLICT", "access_class")
        if self.access_class == "AUTHENTICATED" and not (self.entitlement_ref and self.account_ref):
            raise PredictionError("ACCESS_PROVENANCE_MISSING", "access_class")
        _ns(self.event_ns, "event_ns")
        _ns(self.available_ns, "available_ns")
        if self.event_ns > self.available_ns:
            raise PredictionError("TIME_ORDER_INVALID", "available_ns")
        _enum(self.currency, _CURRENCIES, "currency")
        if self.conversion_ref is not None:
            if type(self.conversion_ref) is not FXRateV1:
                raise PredictionError("FX_PROVENANCE_INVALID", "conversion_ref")
            if (
                self.conversion_ref.from_currency != self.currency
                or self.conversion_ref.to_currency != "USD"
                or self.conversion_ref.available_ns > self.event_ns
            ):
                raise PredictionError("FX_PROVENANCE_INVALID", "conversion_ref")


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolutionEventV1(FrozenRecord):
    """Integrity-issued recorded evidence; this offline seam never proves trust."""

    venue: str
    contract_id: str
    winning_outcome_id: str | None
    version: str
    event_ns: int
    available_ns: int
    disputed: bool
    verification_ref: str
    verification_status: str = "UNVERIFIED"
    _issuer: InitVar[Issuer | None] = None

    def __post_init__(self, _issuer: Issuer | None) -> None:
        if _issuer is not _RESOLUTION_ISSUER:
            raise PredictionError("UNVERIFIED_RESOLUTION", "resolution")
        _enum(self.venue, _VENUES, "venue")
        _token(self.contract_id, "contract_id")
        _token(self.winning_outcome_id, "winning_outcome_id", optional=True)
        _token(self.version, "version")
        _token(self.verification_ref, "verification_ref")
        _enum(self.verification_status, frozenset({"UNVERIFIED"}), "verification_status")
        _ns(self.event_ns, "event_ns")
        _ns(self.available_ns, "available_ns")
        if self.event_ns > self.available_ns:
            raise PredictionError("TIME_ORDER_INVALID", "available_ns")
        if type(self.disputed) is not bool:
            raise PredictionError("INVALID_BOOLEAN", "disputed")
        if not self.disputed and self.winning_outcome_id is None:
            raise PredictionError("RESOLUTION_WINNER_MISSING", "winning_outcome_id")
        _RESOLUTION_ISSUER.issue(self)


def _issue_recorded_resolution(**fields: Any) -> ResolutionEventV1:
    """Internal synthetic fixture seam; it never grants verified status."""
    return ResolutionEventV1(**fields, _issuer=_RESOLUTION_ISSUER)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class NormalizedPriorV1(FrozenRecord):
    venue: str
    contract_id: str
    outcomes: tuple[OutcomeProbabilityV1, ...]
    source_refs: tuple[SourceReferenceV1, ...]
    confidence: Decimal
    source_ids: tuple[str, ...]
    raw_quote_digests: tuple[str, ...]
    access_classes: tuple[str, ...]
    quote_age_ns: int
    conversion_versions: tuple[str, ...]
    resolution_identity: str | None
    calibration_id: str
    calibration_revision: str
    mapping_revision: str
    quality_flags: tuple[str, ...]
    market_status: str
    asof_ns: int
    result_version: str
    hedge_eligible: bool = False
    _issuer: InitVar[Issuer | None] = None

    def __post_init__(self, _issuer: Issuer | None) -> None:
        if _issuer is not _PRIOR_ISSUER:
            raise PredictionError("UNISSUED_RESULT", "prior")
        _enum(self.venue, _VENUES, "venue")
        _token(self.contract_id, "contract_id")
        if type(self.outcomes) is not tuple or len(self.outcomes) < 2:
            raise PredictionError("OUTCOME_VECTOR_INVALID", "outcomes")
        if any(type(item) is not OutcomeProbabilityV1 for item in self.outcomes):
            raise PredictionError("OUTCOME_VECTOR_INVALID", "outcomes")
        ids = tuple(item.outcome_id for item in self.outcomes)
        if ids != tuple(sorted(set(ids))):
            raise PredictionError("OUTCOME_VECTOR_INVALID", "outcomes")
        if type(self.source_refs) is not tuple or any(
            type(item) is not SourceReferenceV1 for item in self.source_refs
        ):
            raise PredictionError("SOURCE_PROVENANCE_INVALID", "source_refs")
        if tuple(item.outcome_id for item in self.source_refs) != ids:
            raise PredictionError("SOURCE_PROVENANCE_INVALID", "source_refs")
        if abs(
            sum((Fraction(item.probability) for item in self.outcomes), Fraction(0)) - 1
        ) > Fraction(1, 1_000_000):
            raise PredictionError("PROBABILITY_SUM_INVALID", "outcomes")
        object.__setattr__(self, "confidence", _decimal(self.confidence, "confidence", high="1"))
        for name in (
            "source_ids",
            "raw_quote_digests",
            "access_classes",
            "conversion_versions",
            "quality_flags",
        ):
            value = getattr(self, name)
            if type(value) is not tuple:
                raise PredictionError("NONCANONICAL_VECTOR", name)
            for item in value:
                if name == "raw_quote_digests":
                    _digest_or_none(item, name)
                elif name == "conversion_versions":
                    if type(item) is not str or _DIGEST.fullmatch(item) is None:
                        raise PredictionError("INVALID_DIGEST", name)
                elif name == "access_classes":
                    _enum(item, _ACCESS, name)
                else:
                    _token(item, name)
            if value != tuple(sorted(set(value))):
                raise PredictionError("NONCANONICAL_VECTOR", name)
        _ns(self.quote_age_ns, "quote_age_ns")
        _ns(self.asof_ns, "asof_ns")
        if self.source_ids != tuple(sorted({item.source_id for item in self.source_refs})):
            raise PredictionError("SOURCE_PROVENANCE_INVALID", "source_ids")
        if self.raw_quote_digests != tuple(
            sorted(
                {
                    item.raw_quote_digest
                    for item in self.source_refs
                    if item.raw_quote_digest is not None
                }
            )
        ):
            raise PredictionError("SOURCE_PROVENANCE_INVALID", "raw_quote_digests")
        if self.access_classes != tuple(sorted({item.access_class for item in self.source_refs})):
            raise PredictionError("SOURCE_PROVENANCE_INVALID", "access_classes")
        if self.conversion_versions != tuple(
            sorted(
                {
                    _fx_identity(item.conversion_ref)
                    for item in self.source_refs
                    if item.conversion_ref is not None
                }
            )
        ):
            raise PredictionError("SOURCE_PROVENANCE_INVALID", "conversion_versions")
        if self.quote_age_ns != max(self.asof_ns - item.event_ns for item in self.source_refs):
            raise PredictionError("SOURCE_PROVENANCE_INVALID", "quote_age_ns")
        _enum(self.market_status, _STATUSES, "market_status")
        _digest_or_none(self.resolution_identity, "resolution_identity")
        _enum(self.calibration_id, frozenset({"IDENTITY"}), "calibration_id")
        if self.calibration_revision != "identity-v1":
            raise PredictionError("CALIBRATION_VERSION_UNSUPPORTED", "calibration_revision")
        _token(self.calibration_revision, "calibration_revision")
        _token(self.mapping_revision, "mapping_revision")
        if type(self.hedge_eligible) is not bool or self.hedge_eligible:
            raise PredictionError("HEDGE_NOT_AUTHORIZED", "hedge_eligible")
        if self.result_version != _content_version(self, "result_version"):
            raise PredictionError("RESULT_CONTENT_MISMATCH", "result_version")
        _PRIOR_ISSUER.issue(self)


@dataclass(frozen=True, slots=True)
class PredictionMarketIdentityV1(FrozenRecord):
    venue: str
    contract_id: str
    title: str
    tags: tuple[str, ...]
    metadata_available_ns: int

    def __post_init__(self) -> None:
        _enum(self.venue, _VENUES, "venue")
        _token(self.contract_id, "contract_id")
        _text(self.title, "title")
        object.__setattr__(self, "tags", _tags(self.tags))
        _ns(self.metadata_available_ns, "metadata_available_ns")


@dataclass(frozen=True, slots=True)
class MappingRuleV1(FrozenRecord):
    rule_id: str
    venue: str
    contract_id: str | None
    match_kind: str
    match_value: str
    internal_event_id: str
    horizon: str
    revision: str
    available_ns: int
    manual_group: str | None = None

    def __post_init__(self) -> None:
        _token(self.rule_id, "rule_id")
        _enum(self.venue, _VENUES, "venue")
        _token(self.contract_id, "contract_id", optional=True)
        _enum(self.match_kind, frozenset({"MANUAL", "EXACT_TAG", "PATTERN"}), "match_kind")
        for field in ("match_value", "internal_event_id", "horizon", "revision"):
            _token(getattr(self, field), field)
        _ns(self.available_ns, "available_ns")
        _token(self.manual_group, "manual_group", optional=True)
        if self.match_kind == "MANUAL" and self.contract_id is None:
            raise PredictionError("MANUAL_CONTRACT_MISSING", "contract_id")
        if self.match_kind == "MANUAL" and self.match_value != self.contract_id:
            raise PredictionError("MANUAL_CONTRACT_MISMATCH", "match_value")
        if self.manual_group is not None and self.match_kind != "MANUAL":
            raise PredictionError("GROUP_KIND_INVALID", "manual_group")


@dataclass(frozen=True, slots=True)
class MappingAuditIntentV1(FrozenRecord):
    reason: str
    candidate_rule_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _token(self.reason, "reason")
        if type(self.candidate_rule_ids) is not tuple or self.candidate_rule_ids != tuple(
            sorted(set(self.candidate_rule_ids))
        ):
            raise PredictionError("AUDIT_INTENT_INVALID", "candidate_rule_ids")
        for item in self.candidate_rule_ids:
            _token(item, "candidate_rule_ids")


@dataclass(frozen=True, slots=True, weakref_slot=True)
class MappingDecisionV1(FrozenRecord):
    venue: str
    contract_id: str
    status: str
    targets: tuple[str, ...]
    target_horizons: tuple[tuple[str, str], ...]
    matched_rule_ids: tuple[str, ...]
    priority: str | None
    mapping_revision: str
    audit_intents: tuple[MappingAuditIntentV1, ...]
    asof_ns: int
    result_version: str
    _issuer: InitVar[Issuer | None] = None

    def __post_init__(self, _issuer: Issuer | None) -> None:
        if _issuer is not _MAPPING_ISSUER:
            raise PredictionError("UNISSUED_RESULT", "mapping")
        _enum(self.venue, _VENUES, "venue")
        _token(self.contract_id, "contract_id")
        _enum(self.status, frozenset({"MAPPED", "UNMAPPED", "CONFLICT"}), "status")
        for name in ("targets", "matched_rule_ids"):
            value = getattr(self, name)
            if type(value) is not tuple:
                raise PredictionError("NONCANONICAL_VECTOR", name)
            for item in value:
                _token(item, name)
            if value != tuple(sorted(set(value))):
                raise PredictionError("NONCANONICAL_VECTOR", name)
        if self.status != "MAPPED" and self.targets:
            raise PredictionError("MAPPING_STATUS_INVALID", "targets")
        if self.status == "MAPPED" and not self.targets:
            raise PredictionError("MAPPING_STATUS_INVALID", "targets")
        if type(self.target_horizons) is not tuple:
            raise PredictionError("MAPPING_STATUS_INVALID", "target_horizons")
        for pair in self.target_horizons:
            if type(pair) is not tuple or len(pair) != 2:
                raise PredictionError("MAPPING_STATUS_INVALID", "target_horizons")
            _token(pair[0], "target_horizons")
            _token(pair[1], "target_horizons")
        if self.target_horizons != tuple(sorted(set(self.target_horizons))):
            raise PredictionError("MAPPING_STATUS_INVALID", "target_horizons")
        if tuple(sorted({pair[0] for pair in self.target_horizons})) != self.targets:
            raise PredictionError("MAPPING_STATUS_INVALID", "target_horizons")
        if self.priority is not None:
            _enum(self.priority, frozenset({"MANUAL", "EXACT_TAG", "PATTERN"}), "priority")
        _token(self.mapping_revision, "mapping_revision")
        if type(self.audit_intents) is not tuple or any(
            type(item) is not MappingAuditIntentV1 for item in self.audit_intents
        ):
            raise PredictionError("AUDIT_INTENT_INVALID", "audit_intents")
        _ns(self.asof_ns, "asof_ns")
        if self.result_version != _content_version(self, "result_version"):
            raise PredictionError("RESULT_CONTENT_MISMATCH", "result_version")
        _MAPPING_ISSUER.issue(self)


def _content_version(obj: NormalizedPriorV1 | MappingDecisionV1, excluded: str) -> str:
    content = {
        field.name: _plain(getattr(obj, field.name))
        for field in fields(obj)
        if field.name != excluded
    }
    return hashlib.sha256(canonical_json(content)).hexdigest()


def _issue_prior(**fields: Any) -> NormalizedPriorV1:
    draft = {**fields, "result_version": ""}
    # A temporary object cannot be built without issuance, so hash a simple value map.
    content = {key: value for key, value in draft.items() if key != "result_version"}
    version = hashlib.sha256(
        canonical_json({key: _plain(value) for key, value in content.items()})
    ).hexdigest()
    return NormalizedPriorV1(**fields, result_version=version, _issuer=_PRIOR_ISSUER)


def _issue_mapping(**fields: Any) -> MappingDecisionV1:
    content = {key: value for key, value in fields.items() if key != "result_version"}
    version = hashlib.sha256(
        canonical_json({key: _plain(value) for key, value in content.items()})
    ).hexdigest()
    return MappingDecisionV1(**fields, result_version=version, _issuer=_MAPPING_ISSUER)


def _plain(value: object) -> object:
    if isinstance(value, (OutcomeProbabilityV1, SourceReferenceV1, FXRateV1, MappingAuditIntentV1)):
        return {field.name: _plain(getattr(value, field.name)) for field in fields(value)}
    if type(value) is tuple:
        return tuple(_plain(item) for item in value)
    return value


def require_prior(prior: NormalizedPriorV1) -> NormalizedPriorV1:
    return require(prior, _PRIOR_ISSUER.tag)


def require_mapping(decision: MappingDecisionV1) -> MappingDecisionV1:
    return require(decision, _MAPPING_ISSUER.tag)


def _guard_issued_init(cls: type[Any], code: str, field: str) -> None:
    """Check registry identity before a generated dataclass initializer writes."""
    original = cls.__init__

    def guarded(self: object, *args: Any, **kwargs: Any) -> None:
        if _is_registered_identity(self):
            raise PredictionError(code, field)
        original(self, *args, **kwargs)

    cls.__init__ = guarded


_guard_issued_init(ResolutionEventV1, "UNVERIFIED_RESOLUTION", "resolution")
_guard_issued_init(NormalizedPriorV1, "UNISSUED_RESULT", "prior")
_guard_issued_init(MappingDecisionV1, "UNISSUED_RESULT", "mapping")
