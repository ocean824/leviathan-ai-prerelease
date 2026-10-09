"""Independent OBS-004 telemetry and health contract acceptance."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from infra.cloud.telemetry.catalog import (
    METRIC_CATALOG_V1,
    MetricCollectorV1,
    MetricError,
    MetricKind,
    MetricLabelsV1,
    MetricName,
    OrderOutcome,
    RiskDenialReason,
)
from infra.cloud.telemetry.health import (
    DependencyName,
    HealthError,
    HealthKernelV1,
    ProbeResultV1,
    ProbeStatus,
    livez,
)

from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
    VerifiedPrincipalV1,
)

_NOW_NS = 1_800_000_000_000_000_000
_NOW = datetime.fromtimestamp(_NOW_NS / 1_000_000_000, tz=UTC)
_ISSUER = "https://issuer.synthetic.invalid"
_AUDIENCE = "leviathan-api"
_PROJECT = "leviathan-ai"
_ENV = "staging"
_KID = "obs004-synthetic-key"
_KEY_DATA = json.loads(
    (
        Path(__file__).parents[2]
        / "packages"
        / "leviathan-core"
        / "tests"
        / "security"
        / "fixtures"
        / "sec003_synthetic_rsa.json"
    ).read_text(encoding="utf-8")
)
_PUBLIC_N = int(_KEY_DATA["modulus_hex"], 16)
_PUBLIC_E = int(_KEY_DATA["public_exponent_hex"], 16)
_PRIVATE_D = int(_KEY_DATA["private_exponent_hex"], 16)
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _labels(**changes: str) -> MetricLabelsV1:
    values = {
        "service": "leviathan",
        "component": "engine",
        "env": "test",
        "region": "local",
        "instance": "node-a",
    }
    values.update(changes)
    return MetricLabelsV1(**values)


class _StaticProbe:
    def __init__(self, result: ProbeResultV1) -> None:
        self.result = result

    def check(self, now_ns: int) -> ProbeResultV1:
        return self.result


class _Policy:
    def __init__(self, allowed: bool = True) -> None:
        self.allowed = allowed
        self.actions: list[str] = []

    def allows(self, principal: VerifiedPrincipalV1, action: str) -> bool:
        self.actions.append(action)
        return self.allowed


class _KeySet:
    def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
        if (issuer, kid) == (_ISSUER, _KID):
            return RSAPublicKeyV1(_PUBLIC_N, _PUBLIC_E)
        return None


class _Revocations:
    def is_revoked(self, issuer: str, jti: str) -> bool:
        return False


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _segment(value: object) -> str:
    return _b64(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _verified_principal(
    *, role: str = "Operator", scopes: tuple[str, ...] = ("ops.health.read",)
) -> VerifiedPrincipalV1:
    now_seconds = int(_NOW.timestamp())
    claims = {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "org": "obs004-synthetic-org",
        "sub": "obs004-synthetic-operator",
        "role": role,
        "scope": list(scopes),
        "env": _ENV,
        "jti": f"obs004-{role}-{len(scopes)}",
        "iat": now_seconds,
        "nbf": now_seconds,
        "exp": now_seconds + 300,
    }
    header = {"alg": "RS256", "kid": _KID, "typ": "JWT"}
    signing_input = f"{_segment(header)}.{_segment(claims)}".encode("ascii")
    digest_info = _SHA256_DIGEST_INFO + hashlib.sha256(signing_input).digest()
    size = (_PUBLIC_N.bit_length() + 7) // 8
    padding_length = size - len(digest_info) - 3
    encoded = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded, "big"), _PRIVATE_D, _PUBLIC_N).to_bytes(size, "big")
    token = f"{signing_input.decode('ascii')}.{_b64(signature)}"
    verifier = PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            issuer=_ISSUER,
            audience=_AUDIENCE,
            org_id="obs004-synthetic-org",
            project_id=_PROJECT,
            env=_ENV,
        ),
        key_set=_KeySet(),
        revocations=_Revocations(),
        clock=lambda: _NOW,
    )
    return verifier.verify(token)


def _healthy_probes(
    now_ns: int = _NOW_NS,
    *,
    stream_lag: Decimal = Decimal("0.299"),
    time_sync: Decimal = Decimal("0.019"),
) -> dict[DependencyName, _StaticProbe]:
    values = {
        DependencyName.STREAMS: stream_lag,
        DependencyName.TIME_SYNC: time_sync,
    }
    return {
        dependency: _StaticProbe(ProbeResultV1(ProbeStatus.HEALTHY, now_ns, values.get(dependency)))
        for dependency in DependencyName
    }


def _kernel(
    *,
    probes: dict[DependencyName, object] | None = None,
    policy: _Policy | None = None,
    now_ns: int = _NOW_NS,
    **options: object,
) -> HealthKernelV1:
    return HealthKernelV1(
        probes=_healthy_probes(now_ns) if probes is None else probes,  # type: ignore[arg-type]
        policy=policy or _Policy(),
        utc_ns=lambda: now_ns,
        **options,
    )


def test_metric_catalog_is_closed_with_names_kinds_and_units() -> None:
    expected = {
        MetricName.DECISION_LATENCY: (MetricKind.HISTOGRAM, "seconds"),
        MetricName.ORDER_ACK_LATENCY: (MetricKind.HISTOGRAM, "seconds"),
        MetricName.PIPELINE_LAG: (MetricKind.HISTOGRAM, "seconds"),
        MetricName.STREAM_FRESHNESS_LAG: (MetricKind.GAUGE, "seconds"),
        MetricName.TIME_SYNC_OFFSET: (MetricKind.GAUGE, "seconds"),
        MetricName.HALT_ENGAGED: (MetricKind.GAUGE, "boolean"),
        MetricName.ORDERS_TOTAL: (MetricKind.COUNTER, "count"),
        MetricName.RISK_DENIALS_TOTAL: (MetricKind.COUNTER, "count"),
        MetricName.LABEL_OVERFLOW_TOTAL: (MetricKind.COUNTER, "count"),
    }
    assert {
        definition.name: (definition.kind, definition.unit) for definition in METRIC_CATALOG_V1
    } == expected
    assert set(MetricName) == set(expected)

    collector = MetricCollectorV1()
    with pytest.raises(MetricError) as unknown_metric:
        collector.observe("unregistered_metric", Decimal("0.1"), _labels())  # type: ignore[arg-type]
    assert str(unknown_metric.value) == unknown_metric.value.code
    assert unknown_metric.value.args == (unknown_metric.value.code,)


def test_latency_histograms_measure_monotonic_seconds_and_publish_percentiles() -> None:
    ticks = iter(
        (
            1_000_000_000,
            1_100_000_000,
            2_000_000_000,
            2_400_000_000,
            3_000_000_000,
            3_100_000_000,
            4_000_000_000,
            4_400_000_000,
        )
    )
    collector = MetricCollectorV1(monotonic_ns=lambda: next(ticks))
    labels = _labels()
    for metric in (MetricName.DECISION_LATENCY, MetricName.ORDER_ACK_LATENCY):
        with collector.measure(metric, labels):
            pass
        with collector.measure(metric, labels):
            pass

    series = {item.name: item for item in collector.snapshot()}
    for metric in (MetricName.DECISION_LATENCY, MetricName.ORDER_ACK_LATENCY):
        assert series[metric].value == (
            Decimal("0.1"),
            Decimal("0.4"),
            Decimal("0.4"),
        )
        assert series[metric].count == 2


@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("service", ""),
        ("component", "x\nother"),
        ("env", "café"),
        ("region", "r" * 65),
        ("instance", "token=synthetic"),
        ("strategy", "bad value"),
        ("symbol", "x" * 65),
        ("venue", "secret=synthetic"),
    ],
)
def test_metric_label_schema_rejects_invalid_values(label: str, value: str) -> None:
    with pytest.raises(MetricError) as invalid:
        _labels(**{label: value})
    assert invalid.value.code == "METRIC_LABEL_INVALID"


def test_required_and_optional_label_fields_are_explicit() -> None:
    with pytest.raises(TypeError):
        MetricLabelsV1(
            service="leviathan",
            component="engine",
            env="test",
            region="local",
        )  # type: ignore[call-arg]
    labels = _labels(strategy="alpha", symbol="ES", venue="XCME")
    assert labels.as_dict() == {
        "service": "leviathan",
        "component": "engine",
        "env": "test",
        "region": "local",
        "instance": "node-a",
        "strategy": "alpha",
        "symbol": "ES",
        "venue": "XCME",
    }


def test_closed_counter_labels_and_boolean_halt_gauge() -> None:
    collector = MetricCollectorV1()
    labels = _labels()
    assert {outcome.value for outcome in OrderOutcome} == {
        "accepted",
        "rejected",
        "unknown",
        "cancelled",
        "filled",
    }
    assert {reason.value for reason in RiskDenialReason} == {
        "halt",
        "limit",
        "stale_data",
        "policy",
        "unknown",
    }
    for outcome in OrderOutcome:
        assert collector.increment(MetricName.ORDERS_TOTAL, labels, outcome=outcome)
    for reason in RiskDenialReason:
        assert collector.increment(MetricName.RISK_DENIALS_TOTAL, labels, reason=reason)

    for value in (False, True, 0, 1):
        assert collector.set_gauge(MetricName.HALT_ENGAGED, value, labels)
    with pytest.raises(MetricError) as invalid_outcome:
        collector.increment(
            MetricName.ORDERS_TOTAL,
            labels,
            outcome="partial",  # type: ignore[arg-type]
        )
    assert invalid_outcome.value.code == "METRIC_LABEL_INVALID"
    with pytest.raises(MetricError) as invalid_reason:
        collector.increment(
            MetricName.RISK_DENIALS_TOTAL,
            labels,
            reason="operator",  # type: ignore[arg-type]
        )
    assert invalid_reason.value.code == "METRIC_LABEL_INVALID"
    with pytest.raises(MetricError) as non_boolean_halt:
        collector.set_gauge(MetricName.HALT_ENGAGED, 2, labels)
    assert non_boolean_halt.value.code == "METRIC_VALUE_INVALID"
    assert collector.set_gauge(MetricName.TIME_SYNC_OFFSET, Decimal("-0.01"), labels)

    series = collector.snapshot()
    assert {
        dict(item.labels)["outcome"] for item in series if item.name is MetricName.ORDERS_TOTAL
    } == {outcome.value for outcome in OrderOutcome}
    assert {
        dict(item.labels)["reason"] for item in series if item.name is MetricName.RISK_DENIALS_TOTAL
    } == {reason.value for reason in RiskDenialReason}


def test_optional_label_cardinality_uses_overflow_bucket_and_counter() -> None:
    collector = MetricCollectorV1()
    values = tuple(f"SYM-{index:03d}" for index in range(101))
    for symbol in values:
        assert collector.set_gauge(
            MetricName.STREAM_FRESHNESS_LAG, Decimal("0.1"), _labels(symbol=symbol)
        )

    series = collector.snapshot()
    data_series = [item for item in series if item.name is MetricName.STREAM_FRESHNESS_LAG]
    symbols = {dict(item.labels)["symbol"] for item in data_series}
    assert len(data_series) == 101
    assert "__overflow__" in symbols
    assert values[-1] not in symbols
    assert len(symbols - {"__overflow__"}) == 100
    (overflow,) = [item for item in series if item.name is MetricName.LABEL_OVERFLOW_TOTAL]
    assert overflow.value == 1
    assert collector.overflow_count == 1


def test_series_and_sample_limits_bound_collector_state() -> None:
    collector = MetricCollectorV1()
    for index in range(1001):
        assert collector.set_gauge(
            MetricName.STREAM_FRESHNESS_LAG,
            0,
            _labels(instance=f"node-{index:04d}", symbol="ES"),
        )
    metric_series = [
        item for item in collector.snapshot() if item.name is MetricName.STREAM_FRESHNESS_LAG
    ]
    overflow_series = [
        item for item in metric_series if dict(item.labels).get("symbol") == "__overflow__"
    ]
    assert len(metric_series) == 1000
    assert len(overflow_series) == 1
    assert collector.overflow_count == 2
    (overflow,) = [
        item for item in collector.snapshot() if item.name is MetricName.LABEL_OVERFLOW_TOTAL
    ]
    assert overflow.value == 2

    samples = MetricCollectorV1(max_samples_per_series=2)
    for value in (1, 2, 3):
        assert samples.observe(MetricName.DECISION_LATENCY, value, _labels())
    (summary,) = samples.snapshot()
    assert summary.count == 3
    assert summary.value == (Decimal(2), Decimal(3), Decimal(3))


def test_metric_numbers_have_bounded_decimal_shapes_and_counter_increments() -> None:
    collector = MetricCollectorV1()
    labels = _labels()
    for value in (Decimal("1e-18"), Decimal("1e38"), Decimal("9" * 38)):
        assert collector.observe(MetricName.DECISION_LATENCY, value, labels)

    for value in (
        Decimal("1e-19"),
        Decimal("1e39"),
        Decimal("9" * 39),
        Decimal("NaN"),
        Decimal("Infinity"),
    ):
        with pytest.raises(MetricError) as invalid:
            collector.observe(MetricName.DECISION_LATENCY, value, labels)
        assert invalid.value.code == "METRIC_VALUE_INVALID"

    assert collector.increment(
        MetricName.ORDERS_TOTAL, labels, value=1_000_000_000, outcome=OrderOutcome.ACCEPTED
    )
    with pytest.raises(MetricError) as oversized_counter:
        collector.increment(
            MetricName.ORDERS_TOTAL,
            labels,
            value=1_000_000_001,
            outcome=OrderOutcome.ACCEPTED,
        )
    assert oversized_counter.value.code == "METRIC_VALUE_INVALID"

    with pytest.raises(MetricError) as excessive_sample_limit:
        MetricCollectorV1(max_samples_per_series=1025)
    assert excessive_sample_limit.value.code == "METRIC_CONFIG_INVALID"


def test_float_observation_uses_shortest_decimal_representation() -> None:
    collector = MetricCollectorV1()
    assert collector.observe(MetricName.DECISION_LATENCY, 0.1, _labels())

    (sample,) = collector.snapshot()
    assert sample.value == (Decimal("0.1"), Decimal("0.1"), Decimal("0.1"))


def test_livez_is_dependency_free_and_readiness_requires_all_seven_dependencies() -> None:
    assert livez().status_code == 200
    assert dict(livez().statuses) == {}

    kernel = _kernel()
    try:
        assert kernel.livez().status_code == 200
        ready = kernel.readyz()
        assert ready.status_code == 200
        assert set(ready.statuses) == set(DependencyName)
        assert set(ready.statuses.values()) == {ProbeStatus.HEALTHY}
    finally:
        kernel.close()

    incomplete = _healthy_probes()
    del incomplete[DependencyName.CACHE]
    kernel = _kernel(probes=incomplete)
    try:
        ready = kernel.readyz()
        assert ready.status_code == 503
        assert ready.statuses[DependencyName.CACHE] is ProbeStatus.UNKNOWN
    finally:
        kernel.close()


@pytest.mark.parametrize(
    ("dependency", "value"),
    [
        (DependencyName.STREAMS, Decimal("0.300")),
        (DependencyName.TIME_SYNC, Decimal("0.020")),
    ],
)
def test_stream_and_time_sync_thresholds_are_strict(
    dependency: DependencyName, value: Decimal
) -> None:
    probes = _healthy_probes()
    probes[dependency] = _StaticProbe(ProbeResultV1(ProbeStatus.HEALTHY, _NOW_NS, value))
    kernel = _kernel(probes=probes)
    try:
        response = kernel.readyz()
        assert response.status_code == 503
        assert response.statuses[dependency] is ProbeStatus.UNHEALTHY
    finally:
        kernel.close()


def test_probe_degraded_unhealthy_unknown_stale_and_future_fail_readiness() -> None:
    for status in (ProbeStatus.DEGRADED, ProbeStatus.UNHEALTHY, ProbeStatus.UNKNOWN):
        probes = _healthy_probes()
        probes[DependencyName.DB] = _StaticProbe(ProbeResultV1(status, _NOW_NS))
        kernel = _kernel(probes=probes)
        try:
            response = kernel.readyz()
            assert response.status_code == 503
            assert response.statuses[DependencyName.DB] is status
        finally:
            kernel.close()

    for observed_ns in (_NOW_NS - 5_000_000_001, _NOW_NS + 1):
        probes = _healthy_probes()
        probes[DependencyName.DB] = _StaticProbe(ProbeResultV1(ProbeStatus.HEALTHY, observed_ns))
        kernel = _kernel(probes=probes)
        try:
            response = kernel.readyz()
            assert response.status_code == 503
            assert response.statuses[DependencyName.DB] is ProbeStatus.UNHEALTHY
        finally:
            kernel.close()


def test_probe_exceptions_timeouts_and_unknown_dependencies_fail_closed() -> None:
    class BrokenProbe:
        def check(self, now_ns: int) -> ProbeResultV1:
            raise RuntimeError("synthetic dependency secret must not escape")

    class SlowProbe:
        def check(self, now_ns: int) -> ProbeResultV1:
            time.sleep(0.03)
            return ProbeResultV1(ProbeStatus.HEALTHY, _NOW_NS)

    probes: dict[DependencyName, object] = _healthy_probes()
    probes[DependencyName.DB] = BrokenProbe()
    probes[DependencyName.CACHE] = SlowProbe()
    kernel = _kernel(probes=probes, probe_timeout_ns=1_000_000)
    try:
        response = kernel.readyz()
        assert response.status_code == 503
        assert response.statuses[DependencyName.DB] is ProbeStatus.UNHEALTHY
        assert response.statuses[DependencyName.CACHE] is ProbeStatus.UNHEALTHY
        assert all(type(status) is ProbeStatus for status in response.statuses.values())
        assert "synthetic dependency secret" not in repr(response.statuses)
    finally:
        kernel.close()

    with pytest.raises(HealthError) as unknown_name:
        HealthKernelV1(
            probes={"UNREGISTERED": _StaticProbe(ProbeResultV1(ProbeStatus.HEALTHY, _NOW_NS))},  # type: ignore[dict-item]
            policy=_Policy(),
        )
    assert unknown_name.value.code == "HEALTH_CONFIG_INVALID"


def test_timed_out_inflight_probe_stays_unhealthy_on_reused_future() -> None:
    class SlowProbe:
        def check(self, now_ns: int) -> ProbeResultV1:
            time.sleep(0.08)
            return ProbeResultV1(ProbeStatus.HEALTHY, _NOW_NS)

    probes: dict[DependencyName, object] = _healthy_probes()
    probes[DependencyName.DB] = SlowProbe()
    kernel = _kernel(probes=probes, probe_timeout_ns=50_000_000)
    try:
        first = kernel.readyz()
        second = kernel.readyz()
        assert first.status_code == second.status_code == 503
        assert first.statuses[DependencyName.DB] is ProbeStatus.UNHEALTHY
        assert second.statuses[DependencyName.DB] is ProbeStatus.UNHEALTHY
    finally:
        kernel.close()


def test_healthz_requires_verified_principal_scope_role_and_policy() -> None:
    policy = _Policy()
    kernel = _kernel(policy=policy)
    try:
        for role in ("Operator", "DevOps"):
            response = kernel.healthz(_verified_principal(role=role))
            assert response.status_code == 200
            assert set(response.__dataclass_fields__) == {"status_code", "statuses"}
            assert set(response.statuses) == set(DependencyName)
            assert all(type(status) is ProbeStatus for status in response.statuses.values())
        assert policy.actions == ["ops.health.read", "ops.health.read"]
    finally:
        kernel.close()

    authorized_policy_kernel = _kernel(policy=_Policy())
    try:
        unauthorized_candidates = (
            object(),
            {"role": "Operator", "scope": ["ops.health.read"]},
            _verified_principal(role="Researcher"),
            _verified_principal(scopes=("metrics.read",)),
        )
        errors = []
        for candidate in unauthorized_candidates:
            with pytest.raises(HealthError) as denied:
                authorized_policy_kernel.healthz(candidate)  # type: ignore[arg-type]
            errors.append(denied.value)
        assert {error.code for error in errors} == {"HEALTH_ACCESS_DENIED"}
        assert {error.args for error in errors} == {("HEALTH_ACCESS_DENIED",)}
        assert all("obs004-synthetic" not in str(error) for error in errors)
    finally:
        authorized_policy_kernel.close()

    denied_policy_kernel = _kernel(policy=_Policy(allowed=False))
    try:
        with pytest.raises(HealthError) as policy_denied:
            denied_policy_kernel.healthz(_verified_principal())
        assert policy_denied.value.code == "HEALTH_ACCESS_DENIED"
        assert policy_denied.value.args == ("HEALTH_ACCESS_DENIED",)
    finally:
        denied_policy_kernel.close()
