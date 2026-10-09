"""Independent acceptance for the public BT-002 prepared-stream verifier."""

from __future__ import annotations

import pickle
from copy import copy, deepcopy
from dataclasses import replace
from decimal import Decimal

import pytest

from leviathan_core.backtest_lab.clock import (
    PreparedEventStreamV1,
    PreparedStreamManifestV1,
    StreamTamperedError,
    prepare_events,
    verify_prepared_stream,
)
from leviathan_core.backtest_lab.events import (
    AdjustmentPolicyV1,
    DatasetManifestV1,
    MarketEventV1,
    SessionWindowV1,
    StreamSpecV1,
    UniverseMemberV1,
)
from leviathan_core.seal import SealError, require


def _dataset() -> DatasetManifestV1:
    return DatasetManifestV1(
        dataset_id="verifier-dataset",
        dataset_version="dataset-v1",
        universe_version="universe-v1",
        symbol_mapping_version="symbols-v1",
        calendar_id="synthetic-calendar",
        calendar_version="calendar-2026a",
        adjustment_version="raw-v1",
        as_of_ns=100,
        start_ns=0,
        end_ns=100,
        source_checksums=(("synthetic-feed", "a" * 64),),
        universe=(UniverseMemberV1("SYNTH", "XTEST", 0),),
        sessions=(
            SessionWindowV1("XTEST", "1970-01-01", 0, 30),
            SessionWindowV1("XTEST", "1970-01-02", 40, 100),
        ),
        streams=(StreamSpecV1("ticks", "synthetic-feed", "XTEST", 0),),
        max_identity_cache=16,
    )


def _event(source_id: str, event_ns: int, price: Decimal) -> MarketEventV1:
    return MarketEventV1(
        dataset_id="verifier-dataset",
        dataset_version="dataset-v1",
        universe_version="universe-v1",
        source="synthetic-feed",
        source_id=source_id,
        correction_key="original",
        stream_id="ticks",
        event_ns=event_ns,
        available_ns=event_ns,
        instrument="SYNTH",
        venue="XTEST",
        sequence=1 if event_ns < 30 else 2,
        kind="trade",
        price=price,
        size=Decimal("1"),
    )


def _stream(
    *, first_price: Decimal = Decimal("10")
) -> tuple[DatasetManifestV1, PreparedEventStreamV1]:
    dataset = _dataset()
    stream = prepare_events(
        dataset,
        (
            _event("morning", 10, first_price),
            _event("afternoon", 50, Decimal("12")),
        ),
        AdjustmentPolicyV1(mode="raw", version="raw-v1"),
    )
    return dataset, stream


def test_verifier_returns_calendar_coverage_and_stable_plan_digest() -> None:
    dataset, stream = _stream()
    prepared = tuple(stream)
    assert len(prepared) == 2

    verified = verify_prepared_stream(stream)

    assert type(verified) is PreparedStreamManifestV1
    assert verified.calendar_id == dataset.calendar_id
    assert verified.calendar_version == dataset.calendar_version
    assert verified.sessions == dataset.sessions
    assert verified.coverage == stream.coverage
    assert verified.coverage.complete is True
    assert verified.observed_position == 2
    assert len(verified.digest) == 64
    assert verified.digest == verified.digest.lower()
    assert all(character in "0123456789abcdef" for character in verified.digest)
    assert require(verified, "bt002.prepared_stream_manifest.v1") is verified


def test_verification_is_read_only_and_reports_the_current_position() -> None:
    _, stream = _stream()
    first = next(stream)
    assert first.raw.source_id == "morning"
    before_count = stream.event_count
    before_stream_digest = stream.stream_digest
    before_coverage = stream.coverage

    partial = verify_prepared_stream(stream)

    assert partial.observed_position == 1
    assert partial.coverage == before_coverage
    assert partial.coverage.complete is False
    assert stream.event_count == before_count
    assert stream.stream_digest == before_stream_digest
    assert stream.coverage == before_coverage

    remainder = tuple(stream)
    assert [event.raw.source_id for event in remainder] == ["afternoon"]
    complete = verify_prepared_stream(stream)
    assert complete.observed_position == 2
    assert complete.coverage == stream.coverage
    assert complete.coverage.complete is True
    assert complete.digest == partial.digest


def test_prepared_digest_binds_ordered_projection_content() -> None:
    _, baseline_stream = _stream()
    _, changed_stream = _stream(first_price=Decimal("10.01"))
    tuple(baseline_stream)
    tuple(changed_stream)

    baseline = verify_prepared_stream(baseline_stream)
    changed = verify_prepared_stream(changed_stream)

    assert baseline.calendar_id == changed.calendar_id
    assert baseline.calendar_version == changed.calendar_version
    assert baseline.digest != changed.digest


def test_tampered_stream_fails_with_content_free_error() -> None:
    dataset, stream = _stream()
    tuple(stream)
    object.__setattr__(stream, "_manifest", replace(dataset, calendar_id="tampered-calendar"))

    with pytest.raises(StreamTamperedError) as tampered:
        verify_prepared_stream(stream)

    assert str(tampered.value) == "STREAM_TAMPERED"
    assert tampered.value.args == ("STREAM_TAMPERED",)


def test_verified_manifest_is_immutable() -> None:
    _, stream = _stream()
    tuple(stream)
    verified = verify_prepared_stream(stream)

    with pytest.raises(SealError) as mutation:
        verified.calendar_id = "other-calendar"  # type: ignore[misc]
    assert mutation.value.code == "SEAL_FORBIDDEN_OPERATION"
    for operation in (copy, deepcopy, pickle.dumps):
        with pytest.raises(SealError) as forbidden:
            operation(verified)
        assert forbidden.value.code == "SEAL_FORBIDDEN_OPERATION"
    with pytest.raises(SealError):
        verified.model_copy(update={"calendar_id": "other-calendar"})
    with pytest.raises(SealError) as model_construct:
        PreparedStreamManifestV1.model_construct(
            calendar_id=verified.calendar_id,
            calendar_version=verified.calendar_version,
            sessions=verified.sessions,
            coverage=verified.coverage,
            digest=verified.digest,
            observed_position=verified.observed_position,
        )
    assert model_construct.value.code == "SEAL_FORBIDDEN_OPERATION"

    unissued = PreparedStreamManifestV1(
        calendar_id=verified.calendar_id,
        calendar_version=verified.calendar_version,
        sessions=verified.sessions,
        coverage=verified.coverage,
        digest=verified.digest,
        observed_position=verified.observed_position,
    )
    with pytest.raises(SealError) as not_issued:
        require(unissued, "bt002.prepared_stream_manifest.v1")
    assert not_issued.value.code == "SEAL_NOT_ISSUED"

    object.__setattr__(verified, "calendar_id", "tampered-calendar")
    with pytest.raises(SealError) as tampered:
        require(verified, "bt002.prepared_stream_manifest.v1")
    assert tampered.value.code == "SEAL_TAMPERED"
