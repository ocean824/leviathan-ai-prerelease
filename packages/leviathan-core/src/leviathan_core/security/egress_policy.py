"""Pure, default-deny venue egress evaluation and audited release guard."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from leviathan_core.seal import Issuer, SealedModel, require
from leviathan_core.security import (
    ActionV1,
    AuthorizationContextV1,
    AuthorizationPolicyV1,
    EffectV1,
    ResourceV1,
    TrustedPrincipalV1,
    authorize,
)

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
AUDIT_APPEND_TIMEOUT_NS = 250_000_000
_ALLOWED_EGRESS_OPERATIONS = frozenset({"DATA_EGRESS", "MARKET_DATA"})
_EGRESS_TAG = "sec008.egress_decision.v1"
_RELEASE_TAG = "sec008.egress_release.v1"
_AUDIT_RECORD_TAG = "sec008.egress_audit_record.v1"
_EGRESS_ISSUER = Issuer(_EGRESS_TAG)
_RELEASE_ISSUER = Issuer(_RELEASE_TAG)
_AUDIT_RECORD_ISSUER = Issuer(_AUDIT_RECORD_TAG)


class EgressOperationV1(StrEnum):
    DATA_EGRESS = "DATA_EGRESS"
    MARKET_DATA = "MARKET_DATA"
    LIVE_ORDER = "LIVE_ORDER"


class EgressReasonCodeV1(StrEnum):
    AUTHORIZED = "AUTHORIZED"
    NOT_AUTHORIZED = "NOT_AUTHORIZED"


class EgressPolicyError(ValueError):
    """Content-free error for malformed trusted egress configuration."""

    def __init__(self, code: str = "INVALID_EGRESS_POLICY") -> None:
        self.code = (
            code
            if code
            in {
                "INVALID_EGRESS_POLICY",
                "INVALID_EGRESS_REQUEST",
                "LIVE_ENDPOINT_CONFLICT",
            }
            else "INVALID_EGRESS_POLICY"
        )
        super().__init__(self.code)


def _identifier(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _hostname(value: object) -> bool:
    if type(value) is not str or not value or value != value.lower() or "*" in value:
        return False
    labels = value.split(".")
    return len(labels) >= 2 and all(_HOST_LABEL.fullmatch(label) is not None for label in labels)


def _addresses(values: object) -> bool:
    if type(values) is not tuple or not values:
        return False
    try:
        parsed = tuple(ipaddress.ip_address(value) for value in values)
    except (TypeError, ValueError):
        return False
    return all(
        type(value) is str and str(address) == value
        for value, address in zip(values, parsed, strict=True)
    ) and len(set(values)) == len(values)


def _sha256(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(data.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class OrgProjectBindingV1:
    """Trusted registry binding used before any egress policy evaluation."""

    org_id: str
    project_id: str

    def __post_init__(self) -> None:
        if not _identifier(self.org_id) or not _identifier(self.project_id):
            raise EgressPolicyError()


@dataclass(frozen=True, slots=True)
class EgressRuleV1:
    """Exact destination allowlist entry with pinned synthetic DNS addresses."""

    org_id: str
    service_role: str
    venue: str
    env: str
    host: str
    port: int
    resolved_addresses: tuple[str, ...]
    allowed_operations: tuple[EgressOperationV1, ...] = (
        EgressOperationV1.DATA_EGRESS,
        EgressOperationV1.MARKET_DATA,
    )
    live_money: bool = False
    scheme: str = "https"

    def __post_init__(self) -> None:
        if (
            not all(
                _identifier(value)
                for value in (self.org_id, self.service_role, self.venue, self.env)
            )
            or not _hostname(self.host)
            or type(self.port) is not int
            or not 1 <= self.port <= 65535
            or not _addresses(self.resolved_addresses)
            or type(self.allowed_operations) is not tuple
            or not self.allowed_operations
            or any(
                type(operation) is not EgressOperationV1
                or operation.value not in _ALLOWED_EGRESS_OPERATIONS
                for operation in self.allowed_operations
            )
            or len(set(self.allowed_operations)) != len(self.allowed_operations)
            or type(self.live_money) is not bool
            or type(self.scheme) is not str
            or self.scheme not in {"https", "wss"}
        ):
            raise EgressPolicyError()


@dataclass(frozen=True, slots=True)
class EgressRequestV1:
    """Synthetic request facts; resolution is supplied by a later trusted resolver."""

    org_id: str
    service_role: str
    venue: str
    host: str
    port: int
    resolved_addresses: tuple[str, ...]
    operation: EgressOperationV1 = EgressOperationV1.DATA_EGRESS
    redirect_chain: tuple[str, ...] = ()
    scheme: str = "https"

    def __post_init__(self) -> None:
        if (
            not all(_identifier(value) for value in (self.org_id, self.service_role, self.venue))
            or not _hostname(self.host)
            or type(self.port) is not int
            or not 1 <= self.port <= 65535
            or not _addresses(self.resolved_addresses)
            or type(self.operation) is not EgressOperationV1
            or type(self.redirect_chain) is not tuple
            or any(not _hostname(host) for host in self.redirect_chain)
            or type(self.scheme) is not str
            or self.scheme not in {"https", "wss"}
        ):
            raise EgressPolicyError("INVALID_EGRESS_REQUEST")


class EgressDecisionV1(SealedModel):
    decision: EffectV1
    reason_code: EgressReasonCodeV1
    request_digest: str
    decision_digest: str

    @property
    def allowed(self) -> bool:
        return self.decision is EffectV1.ALLOW


class EgressReleaseV1(SealedModel):
    allowed: bool
    reason_code: EgressReasonCodeV1
    payload: str | None
    request_digest: str
    destination_scheme: str
    destination_host: str
    destination_port: int
    expires_at_ns: int


@dataclass(frozen=True, slots=True, init=False, weakref_slot=True)
class EgressAuditRecordV1:
    """Sealed audit intent bound to organization, identity, request and decision."""

    org_id: str
    principal: TrustedPrincipalV1
    operation: str
    request_digest: str
    decision_digest: str
    decision: EffectV1

    def __new__(cls, *args: object, **kwargs: object) -> EgressAuditRecordV1:
        raise TypeError("egress audit records are issued by the policy guard")


class Sec005AuditPort(Protocol):
    """Adapter with a hard bound: append must honor its monotonic deadline."""

    def append(self, record: EgressAuditRecordV1, *, deadline_monotonic_ns: int) -> None:
        """Commit before release, returning or raising no later than the deadline."""


def require_egress_decision(value: EgressDecisionV1) -> EgressDecisionV1:
    return require(value, _EGRESS_TAG)


def require_egress_release(value: EgressReleaseV1) -> EgressReleaseV1:
    return require(value, _RELEASE_TAG)


def egress_release_is_usable(
    value: EgressReleaseV1,
    *,
    request_digest: str,
    scheme: str,
    host: str,
    port: int,
    now: datetime,
) -> bool:
    """Fail closed unless a sealed release matches its request, destination and TTL."""

    try:
        require_egress_release(value)
        now_ns = _timestamp_ns(now)
        return (
            value.allowed
            and now_ns is not None
            and value.expires_at_ns > now_ns
            and value.request_digest == request_digest
            and value.destination_scheme == scheme
            and value.destination_host == host
            and value.destination_port == port
        )
    except Exception:
        return False


def require_egress_audit_record(value: EgressAuditRecordV1) -> EgressAuditRecordV1:
    return require(value, _AUDIT_RECORD_TAG)


def _issue_egress_audit_record(
    *,
    org_id: str,
    principal: TrustedPrincipalV1,
    operation: str,
    request_digest: str,
    decision_digest: str,
    decision: EffectV1,
) -> EgressAuditRecordV1:
    """Issue a sealed, content-minimal audit record for the injected audit port."""

    if (
        not _identifier(org_id)
        or type(principal) is not TrustedPrincipalV1
        or operation not in {"DATA_ACCESS", "EGRESS"}
        or not all(
            type(value) is str and _DIGEST.fullmatch(value) is not None
            for value in (request_digest, decision_digest)
        )
        or type(decision) is not EffectV1
    ):
        raise EgressPolicyError()
    record = object.__new__(EgressAuditRecordV1)
    for name, value in (
        ("org_id", org_id),
        ("principal", principal),
        ("operation", operation),
        ("request_digest", request_digest),
        ("decision_digest", decision_digest),
        ("decision", decision),
    ):
        object.__setattr__(record, name, value)
    return _AUDIT_RECORD_ISSUER.issue(record)


def _append_audit_record(
    audit: Sec005AuditPort | None,
    record: EgressAuditRecordV1,
    *,
    timeout_ns: int = AUDIT_APPEND_TIMEOUT_NS,
) -> bool:
    """Best-effort denial audit and fail-closed allow audit."""

    if audit is None or type(timeout_ns) is not int or timeout_ns <= 0:
        return False
    try:
        require_egress_audit_record(record)
        started_ns = time.monotonic_ns()
        deadline_ns = started_ns + timeout_ns
        audit.append(record, deadline_monotonic_ns=deadline_ns)
        return time.monotonic_ns() <= deadline_ns
    except Exception:
        return False


def _decision(effect: EffectV1, request_digest: str) -> EgressDecisionV1:
    reason = (
        EgressReasonCodeV1.AUTHORIZED
        if effect is EffectV1.ALLOW
        else EgressReasonCodeV1.NOT_AUTHORIZED
    )
    decision_digest = _sha256((effect.value, reason.value, request_digest))
    value = EgressDecisionV1(
        decision=effect,
        reason_code=reason,
        request_digest=request_digest,
        decision_digest=decision_digest,
    )
    return _EGRESS_ISSUER.issue(value)


def _timestamp_ns(value: object) -> int | None:
    if type(value) is not datetime or value.tzinfo is not UTC:
        return None
    delta = value - datetime(1970, 1, 1, tzinfo=UTC)
    return (
        delta.days * 86_400_000_000_000 + delta.seconds * 1_000_000_000 + delta.microseconds * 1_000
    )


class EgressPolicyV1:
    """Pure deny-by-default evaluator over injected policy and trusted bindings."""

    def __init__(
        self,
        *,
        policy: AuthorizationPolicyV1 | None,
        org_projects: tuple[OrgProjectBindingV1, ...],
        rules: tuple[EgressRuleV1, ...],
        clock: Callable[[], datetime],
    ) -> None:
        self._policy = policy
        self._clock = clock
        if type(rules) is tuple and all(type(item) is EgressRuleV1 for item in rules):
            live_endpoints = {
                (item.scheme, item.host, item.port) for item in rules if item.live_money
            }
            if any(
                not item.live_money and (item.scheme, item.host, item.port) in live_endpoints
                for item in rules
            ):
                raise EgressPolicyError("LIVE_ENDPOINT_CONFLICT")
        self._valid = (
            type(org_projects) is tuple
            and all(type(item) is OrgProjectBindingV1 for item in org_projects)
            and len({item.org_id for item in org_projects}) == len(org_projects)
            and type(rules) is tuple
            and all(type(item) is EgressRuleV1 for item in rules)
            and len(
                {
                    (r.org_id, r.service_role, r.venue, r.env, r.scheme, r.host, r.port)
                    for r in rules
                }
            )
            == len(rules)
            and callable(clock)
            and (policy is None or type(policy) is AuthorizationPolicyV1)
        )
        self._org_projects = (
            {item.org_id: item.project_id for item in org_projects} if self._valid else {}
        )
        self._rules = rules if self._valid else ()

    def current_time(self) -> datetime | None:
        try:
            now = self._clock()
        except Exception:
            return None
        return now if type(now) is datetime and now.tzinfo is UTC else None

    def evaluate(self, principal: TrustedPrincipalV1, request: EgressRequestV1) -> EgressDecisionV1:
        try:
            request_digest = (
                _sha256(
                    (
                        request.org_id,
                        request.service_role,
                        request.venue,
                        request.scheme,
                        request.host,
                        request.port,
                        tuple(sorted(request.resolved_addresses)),
                        request.operation.value,
                        request.redirect_chain,
                    )
                )
                if type(request) is EgressRequestV1
                else _sha256("invalid-request")
            )
        except Exception:
            request_digest = _sha256("invalid-request")
        denied = _decision(EffectV1.DENY, request_digest)
        if (
            not self._valid
            or self._policy is None
            or type(principal) is not TrustedPrincipalV1
            or type(request) is not EgressRequestV1
        ):
            return denied

        try:
            request.__post_init__()
        except Exception:
            return denied

        # Ownership is checked before dynamic policy evaluation; unknown and
        # cross-project organizations have the same closed public result.
        project_id = self._org_projects.get(request.org_id)
        if project_id is None or project_id != principal.project_id:
            return denied
        if any(
            item.live_money
            and (item.scheme, item.host, item.port) == (request.scheme, request.host, request.port)
            for item in self._rules
        ):
            return denied
        if (
            request.operation is EgressOperationV1.LIVE_ORDER
            or request.redirect_chain
            or request.service_role not in principal.roles
            or request.venue != principal.venue
            or request.operation.value not in _ALLOWED_EGRESS_OPERATIONS
        ):
            return denied
        rule = next(
            (
                item
                for item in self._rules
                if item.org_id == request.org_id
                and item.service_role == request.service_role
                and item.venue == request.venue
                and item.env == principal.env
                and item.scheme == request.scheme
                and item.host == request.host
                and item.port == request.port
                and frozenset(item.resolved_addresses) == frozenset(request.resolved_addresses)
                and request.operation in item.allowed_operations
                and not item.live_money
            ),
            None,
        )
        if rule is None:
            return denied
        now = self.current_time()
        if now is None:
            return denied
        try:
            allowed = authorize(
                principal,
                ActionV1("egress:connect"),
                ResourceV1(
                    f"egress:{request.host}:{request.port}",
                    principal.project_id,
                    principal.env,
                    request.venue,
                    principal.portfolio,
                    principal.strategy,
                ),
                AuthorizationContextV1(
                    principal.project_id,
                    principal.env,
                    now,
                    request.venue,
                    principal.portfolio,
                    principal.strategy,
                ),
                self._policy,
            ).allowed
        except Exception:
            allowed = False
        return _decision(EffectV1.ALLOW, request_digest) if allowed else denied


class EgressGuard:
    """Audit-before-release guard; never exposes payload on denial or audit failure."""

    def __init__(
        self,
        *,
        policy: EgressPolicyV1 | None,
        audit: Sec005AuditPort | None,
        ttl_seconds: int = 30,
        audit_timeout_ns: int = AUDIT_APPEND_TIMEOUT_NS,
    ) -> None:
        self._policy = policy if type(policy) is EgressPolicyV1 else None
        self._audit = audit
        self._ttl_seconds = (
            ttl_seconds if type(ttl_seconds) is int and 1 <= ttl_seconds <= 300 else 0
        )
        self._audit_timeout_ns = (
            audit_timeout_ns
            if type(audit_timeout_ns) is int and 0 < audit_timeout_ns <= 2_500_000_000
            else 0
        )

    def release(
        self,
        principal: TrustedPrincipalV1,
        request: EgressRequestV1,
        payload: str,
    ) -> EgressReleaseV1:
        try:
            decision = (
                self._policy.evaluate(principal, request)
                if self._policy is not None
                else _decision(EffectV1.DENY, _sha256("missing-policy"))
            )
        except Exception:
            decision = _decision(EffectV1.DENY, _sha256("evaluation-failed"))
        now = self._policy.current_time() if self._policy is not None else None
        now_ns = _timestamp_ns(now)
        expires_at_ns = 0
        if decision.allowed:
            if now_ns is None or self._ttl_seconds == 0:
                decision = _decision(EffectV1.DENY, decision.request_digest)
            else:
                expires_at_ns = now_ns + self._ttl_seconds * 1_000_000_000
        audit_succeeded = False
        if type(principal) is TrustedPrincipalV1 and type(request) is EgressRequestV1:
            try:
                record = _issue_egress_audit_record(
                    org_id=request.org_id,
                    principal=principal,
                    operation="EGRESS",
                    request_digest=decision.request_digest,
                    decision_digest=decision.decision_digest,
                    decision=decision.decision,
                )
                audit_succeeded = _append_audit_record(
                    self._audit, record, timeout_ns=self._audit_timeout_ns
                )
            except Exception:
                audit_succeeded = False
        after_audit = self._policy.current_time() if self._policy is not None else None
        after_audit_ns = _timestamp_ns(after_audit)
        allowed = (
            decision.allowed
            and audit_succeeded
            and type(payload) is str
            and after_audit_ns is not None
            and expires_at_ns > after_audit_ns
        )
        result = EgressReleaseV1(
            allowed=allowed,
            reason_code=(
                EgressReasonCodeV1.AUTHORIZED if allowed else EgressReasonCodeV1.NOT_AUTHORIZED
            ),
            payload=payload if allowed else None,
            request_digest=decision.request_digest,
            destination_scheme=request.scheme if type(request) is EgressRequestV1 else "",
            destination_host=request.host if type(request) is EgressRequestV1 else "",
            destination_port=request.port if type(request) is EgressRequestV1 else 0,
            expires_at_ns=expires_at_ns if allowed else 0,
        )
        return _RELEASE_ISSUER.issue(result)


__all__ = [
    "EgressAuditRecordV1",
    "EgressDecisionV1",
    "EgressGuard",
    "EgressOperationV1",
    "EgressPolicyError",
    "EgressPolicyV1",
    "EgressReasonCodeV1",
    "EgressReleaseV1",
    "EgressRequestV1",
    "EgressRuleV1",
    "OrgProjectBindingV1",
    "Sec005AuditPort",
    "egress_release_is_usable",
    "require_egress_audit_record",
    "require_egress_decision",
    "require_egress_release",
]
