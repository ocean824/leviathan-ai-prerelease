from __future__ import annotations

import json
import os
from collections.abc import Mapping
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

FROZEN = Path(
    os.environ.get(
        "PUBLIC_DATA_ACCEPTANCE_SOURCE_ROOT",
        str(Path(__file__).resolve().parents[3]),
    )
).resolve()
NOW = datetime(2026, 10, 9, 12, tzinfo=UTC)


class _FakeResponse:
    status = 200
    headers: Mapping[str, str] = {}

    def __init__(self, body: bytes) -> None:
        self.body = body


class _FakeTransport:
    def __init__(self, *responses: bytes) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, Mapping[str, str], bytes | None]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_s: float,
        max_bytes: int,
    ) -> _FakeResponse:
        del timeout_s, max_bytes
        self.calls.append((method, url, headers, body))
        return _FakeResponse(self.responses.pop(0))


def test_cycle2_imports_resolve_to_the_frozen_snapshot() -> None:
    import leviathan_api.public_source_factor_adapters as factors
    import leviathan_api.public_sources_intel as intel
    import leviathan_market_data.public_sources as public_sources
    import leviathan_market_data.public_sources.registry as registry
    import leviathan_market_data.public_sources.sources as sources

    for module in (factors, intel, public_sources, registry, sources):
        assert Path(module.__file__).resolve().is_relative_to(FROZEN), module.__file__


def test_binance_is_excluded_without_client_or_runtime_enablement() -> None:
    from leviathan_api.market_data_runtime_config import PublicSourcesConfigV1
    from leviathan_market_data.public_sources import PUBLIC_SOURCES, PublicSourcesClient

    entry = next(row for row in PUBLIC_SOURCES if row.source_id == "crypto.binance_usdm")
    assert entry.tos_classification == "EXCLUDED"
    assert entry.us_eligibility == "ineligible"
    assert entry.us_eligibility_note
    assert not any("binance" in name.casefold() for name in dir(PublicSourcesClient))
    assert not any("binance" in field.casefold() for field in PublicSourcesConfigV1.model_fields)
    runtime_text = (FROZEN / "apps/api/src/leviathan_api/market_data_runtime.py").read_text(
        encoding="utf-8"
    )
    assert "binance" not in runtime_text.casefold()


def test_coinbase_eligibility_terms_and_public_funding_provenance() -> None:
    from leviathan_market_data.public_sources import (
        PUBLIC_SOURCES,
        PublicEvidenceV1,
        PublicSourcesClient,
    )

    entry = next(row for row in PUBLIC_SOURCES if row.source_id == "coinbase.derivatives_us")
    assert entry.tos_classification == "ALLOWED"
    assert entry.us_eligibility == "eligible"
    assert entry.us_eligibility_note and "US customers" in entry.us_eligibility_note
    assert entry.tos_url == "https://www.coinbase.com/legal/futures-account-agreement"

    transport = _FakeTransport(
        b'[{"symbol":"BIPZ30","funding_rate":"0.0001","event_time":"2026-10-09T11:00:00Z"}]'
    )
    client = PublicSourcesClient(
        transport=transport,
        sec_user_agent="Leviathan acceptance contact@example.test",
        coinbase_derivatives_enabled=True,
        now=lambda: NOW,
    )
    records = client.fetch_coinbase_derivatives_funding(
        symbol="BIPZ30", trading_session_date=date(2026, 10, 9)
    )
    assert len(records) == 1
    record = records[0]
    assert type(record) is PublicEvidenceV1
    assert record.source_tier == 1
    assert record.source_id == "coinbase.derivatives_us"
    assert record.fetched_at == NOW
    assert record.as_of == datetime(2026, 10, 9, 11, tzinfo=UTC)
    assert record.knowable_at == NOW
    assert record.redistribution is False
    assert len(record.record_digest) == 64
    assert "api.exchange.fairx.net/rest/funding-rate" in transport.calls[0][1]
    assert "Authorization" not in transport.calls[0][2]


def test_public_open_interest_record_keeps_provenance_and_coinbase_exposes_oi() -> None:
    from leviathan_market_data.public_sources import (
        PublicEvidenceV1,
        PublicSourceError,
        PublicSourcesClient,
        parse_cftc_cot,
    )

    cftc = parse_cftc_cot(
        json.dumps(
            [
                {
                    "report_date_as_yyyy_mm_dd": "2026-10-06",
                    "market_and_exchange_names": "Synthetic",
                    "cftc_contract_market_code": "001",
                    "open_interest_all": "1000",
                    "comm_positions_long_all": "400",
                    "comm_positions_short_all": "350",
                }
            ]
        ).encode("utf-8"),
        fetched_at=NOW,
    )[0]
    assert type(cftc) is PublicEvidenceV1
    assert cftc.source_id == "cftc.cot.legacy"
    assert cftc.source_tier == 1
    assert cftc.as_of == datetime(2026, 10, 6, tzinfo=UTC)
    assert cftc.knowable_at == NOW
    assert dict(cftc.values)["open_interest"] == "1000"
    assert cftc.redistribution is False
    assert len(cftc.record_digest) == 64

    client = PublicSourcesClient(
        transport=_FakeTransport(),
        sec_user_agent="Leviathan acceptance contact@example.test",
        coinbase_derivatives_enabled=True,
        now=lambda: NOW,
    )
    assert hasattr(client, "fetch_coinbase_derivatives_open_interest")
    with pytest.raises(PublicSourceError, match="COINBASE_DERIVATIVES_DISABLED"):
        PublicSourcesClient(
            transport=_FakeTransport(),
            sec_user_agent="Leviathan acceptance contact@example.test",
            now=lambda: NOW,
        ).fetch_coinbase_derivatives_funding(
            symbol="BIPZ30", trading_session_date=date(2026, 10, 9)
        )


def _sample_values(source_id: str) -> tuple[tuple[str, str], ...]:
    values = {
        "sec.edgar.form4": (
            ("cik", "0000000001"),
            ("transaction_code", "P"),
            ("shares", "100"),
            ("price", "10"),
        ),
        "finra.regsho.daily": (("symbol", "XYZ"), ("short_volume", "100"), ("total_volume", "400")),
        "finra.short_interest": (
            ("symbol", "XYZ"),
            ("currentShortPositionQuantity", "150"),
            ("previousShortPositionQuantity", "100"),
        ),
        "cftc.cot.legacy": (
            ("contract_code", "001"),
            ("commercial_long", "400"),
            ("commercial_short", "350"),
            ("open_interest", "1000"),
        ),
        "coinbase.derivatives_us": (("symbol", "BIPZ30"), ("funding_rate", "0.0001")),
    }
    return values.get(source_id, ())


def test_each_public_factor_adapter_issues_intel_score_or_abstention_with_context_refs() -> None:
    from leviathan_api.public_source_factor_adapters import (
        _RULES,
        PublicSourceFactorAdapterV1,
    )
    from leviathan_api.public_sources_intel import issue_public_as_of_context
    from leviathan_core.intel.models import (
        AsOfContextV1,
        EvidenceRefV1,
        FactorAbstentionV1,
        FactorScoreV1,
        unix_ns,
    )
    from leviathan_market_data.public_sources import OFFICIAL_PUBLIC_SOURCES, PublicEvidenceV1

    adapter = PublicSourceFactorAdapterV1()
    mapped = tuple(sorted(_RULES))
    metadata = {row.source_id: row for row in OFFICIAL_PUBLIC_SOURCES}
    for source_id in mapped:
        row = metadata[source_id]
        record = PublicEvidenceV1(
            source_tier=row.tier,
            source_id=source_id,
            record_id=f"acceptance-{source_id}",
            fetched_at=NOW,
            as_of=datetime(2026, 10, 8, tzinfo=UTC),
            knowable_at=NOW,
            factor_tags=(_RULES[source_id].factor_tag,),
            values=_sample_values(source_id),
            redistribution=False,
        )
        context = issue_public_as_of_context(
            (record,), decision_as_of_ns=unix_ns(NOW), freshness="fresh"
        )
        assert type(context) is AsOfContextV1
        outcome = adapter.evaluate_record(record, decision_as_of_ns=unix_ns(NOW), freshness="fresh")
        assert isinstance(outcome, (FactorScoreV1, FactorAbstentionV1)), source_id
        assert isinstance(context.evidence_refs[0], EvidenceRefV1), source_id
        ref = outcome.evidence_refs[0]
        assert ref.source == source_id
        assert ref.record_digest == record.record_digest
        assert ref.source_record_key == record.record_id
        assert ref.source_event_ns == unix_ns(record.as_of)
        assert ref.as_of_ns == unix_ns(record.knowable_at)
        assert outcome.source_event_ns == unix_ns(record.as_of)
        assert record.redistribution is False


def test_stale_and_unknown_availability_abstain_and_future_evidence_is_rejected() -> None:
    from leviathan_api.public_source_factor_adapters import PublicSourceFactorAdapterV1
    from leviathan_core.intel.models import FactorAbstentionV1
    from leviathan_market_data.public_sources import PublicEvidenceV1, PublicSourceError

    adapter = PublicSourceFactorAdapterV1()
    common = dict(
        source_tier=1,
        source_id="finra.regsho.daily",
        record_id="availability-case",
        fetched_at=NOW,
        as_of=datetime(2026, 10, 8, tzinfo=UTC),
        factor_tags=("short_activity",),
        values=(("symbol", "XYZ"), ("short_volume", "100"), ("total_volume", "400")),
        redistribution=False,
    )
    for knowable_at, freshness, reason in (
        (NOW, "stale", "STALE_EVIDENCE"),
        (None, "fresh", "UNKNOWN_FRESHNESS"),
    ):
        record = PublicEvidenceV1(**common, knowable_at=knowable_at)
        from leviathan_core.intel.models import unix_ns

        result = adapter.evaluate_record(
            record, decision_as_of_ns=unix_ns(NOW), freshness=freshness
        )
        assert isinstance(result, FactorAbstentionV1)
        assert result.reason == reason
    future = PublicEvidenceV1(
        **(
            common
            | {
                "fetched_at": datetime(2026, 10, 10, tzinfo=UTC),
                "as_of": datetime(2026, 10, 10, tzinfo=UTC),
            }
        ),
        knowable_at=datetime(2026, 10, 10, tzinfo=UTC),
    )
    with pytest.raises(PublicSourceError, match="FUTURE_DATED_EVIDENCE"):
        from leviathan_core.intel.models import unix_ns

        adapter.evaluate_record(future, decision_as_of_ns=unix_ns(NOW), freshness="fresh")


def test_api_anything_records_and_registry_compose_without_replacing_official_sources() -> None:

    from leviathan_market_data.public_sources import (
        API_ANYTHING_PUBLIC_SOURCES,
        OFFICIAL_PUBLIC_SOURCES,
        PUBLIC_SOURCES,
    )
    from leviathan_market_data.public_sources.api_anything_client import (
        SidecarReply,
        parse_operation_result,
    )
    from leviathan_market_data.public_sources.api_anything_registry import intel_evidence_payload

    official_ids = tuple(row.source_id for row in OFFICIAL_PUBLIC_SOURCES)
    api_ids = tuple(row.source_id for row in API_ANYTHING_PUBLIC_SOURCES)
    root_ids = tuple(row.source_id for row in PUBLIC_SOURCES)
    assert root_ids == official_ids + api_ids
    assert len(root_ids) == len(set(root_ids))
    assert all(PUBLIC_SOURCES[index] == row for index, row in enumerate(OFFICIAL_PUBLIC_SOURCES))

    fixture = FROZEN / "packages/leviathan-market-data/tests/fixtures/api_anything_fear_greed.json"
    result = parse_operation_result(
        SidecarReply.model_validate_json(fixture.read_text(encoding="utf-8"))
    )
    record = result.records[0]
    payload = intel_evidence_payload(record)
    assert record.source_id == "api_anything.cnn.fear_greed"
    assert record.source_id in root_ids
    assert payload["record_digest"] == record.record_digest
    assert payload["record_id"] == record.record_id
    assert payload["redistribution"] is False
