from __future__ import annotations

import json
import os
import sys
from dataclasses import FrozenInstanceError, is_dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[3]
API_SRC = ROOT / "apps" / "api" / "src"
MARKET_DATA_SRC = Path(
    os.environ.get("PUBLIC_DATA_TEST_SRC", str(ROOT / "packages" / "leviathan-market-data" / "src"))
)
if str(API_SRC) not in sys.path:
    sys.path.insert(0, str(API_SRC))
if str(MARKET_DATA_SRC) not in sys.path:
    sys.path.insert(0, str(MARKET_DATA_SRC))

from leviathan_api.market_data_runtime_config import (  # noqa: E402
    MarketDataConfigError,
    load_market_data_runtime_config,
)
from leviathan_market_data.public_sources import (  # noqa: E402
    PublicEvidenceV1,
    PublicSourceError,
    PublicSourcesClient,
    parse_cftc_cot,
    parse_finra_regsho,
    parse_finra_weekly,
    parse_sec_form4,
    parse_treasury_curve,
)
from leviathan_market_data.public_sources import sources as source_module  # noqa: E402

FIXTURES = ROOT / "packages" / "leviathan-market-data" / "tests" / "fixtures" / "public_sources"
NOW = datetime(2026, 10, 9, 12, tzinfo=UTC)


def _fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _all_fixture_records() -> tuple[PublicEvidenceV1, ...]:
    return (
        *parse_sec_form4(
            _fixture("sec-form4.xml"),
            cik="0000000001",
            accession="0000000001-26-000001",
            filed_at=datetime(2026, 10, 9, 10, tzinfo=UTC),
            fetched_at=NOW,
        ),
        *parse_finra_regsho(
            _fixture("finra-regsho.txt"), trade_date=date(2026, 10, 8), fetched_at=NOW
        ),
        *parse_finra_weekly(_fixture("finra-weekly.json"), fetched_at=NOW),
        *parse_cftc_cot(_fixture("cftc-cot.json"), fetched_at=NOW),
        *parse_treasury_curve(_fixture("treasury-curve.xml"), fetched_at=NOW),
    )


def test_all_official_fixture_adapters_emit_frozen_typed_provenance_records() -> None:
    records = _all_fixture_records()
    assert len(records) == 5
    assert {record.source_id for record in records} == {
        "sec.edgar.form4",
        "finra.regsho.daily",
        "finra.otc.weekly",
        "cftc.cot.legacy",
        "treasury.yield_curve",
    }
    for record in records:
        assert isinstance(record, PublicEvidenceV1)
        assert is_dataclass(record)
        assert record.__dataclass_params__.frozen is True
        assert record.source_tier in {1, 2, 3}
        assert record.source_id and record.record_id
        assert isinstance(record.fetched_at, datetime)
        assert isinstance(record.as_of, datetime)
        assert isinstance(record.knowable_at, datetime)
        assert all(
            stamp.tzinfo is not None
            for stamp in (record.fetched_at, record.as_of, record.knowable_at)
        )
        with pytest.raises(FrozenInstanceError):
            record.source_id = "mutated"  # type: ignore[misc]


def test_knowable_at_uses_publication_or_observation_time_not_as_of() -> None:
    by_source = {record.source_id: record for record in _all_fixture_records()}
    assert by_source["sec.edgar.form4"].as_of.date() == date(2026, 10, 8)
    assert by_source["sec.edgar.form4"].knowable_at == datetime(2026, 10, 9, 10, tzinfo=UTC)
    assert by_source["finra.regsho.daily"].knowable_at == NOW
    assert by_source["finra.regsho.daily"].knowable_at != by_source["finra.regsho.daily"].as_of
    assert by_source["finra.otc.weekly"].as_of.date() == date(2026, 9, 21)
    assert by_source["finra.otc.weekly"].knowable_at.date() == date(2026, 10, 5)
    assert by_source["cftc.cot.legacy"].knowable_at == NOW
    assert by_source["treasury.yield_curve"].knowable_at == NOW


@pytest.mark.parametrize("future_field", ["as_of", "knowable_at"])
def test_future_dated_evidence_is_a_hard_error(future_field: str) -> None:
    fields = {
        "source_tier": 1,
        "source_id": "treasury.yield_curve",
        "record_id": "future",
        "fetched_at": NOW,
        "as_of": NOW,
        "knowable_at": NOW,
        "factor_tags": ("rates",),
        "values": (),
    }
    fields[future_field] = NOW.replace(day=10)
    with pytest.raises(PublicSourceError, match="FUTURE_DATED_EVIDENCE"):
        PublicEvidenceV1(**fields)  # type: ignore[arg-type]


def test_revised_finra_weekly_reports_remain_distinct_versions() -> None:
    row = json.loads(_fixture("finra-weekly.json"))[0]
    first = {**row, "lastUpdateDate": "2026-10-05", "totalWeeklyShareQuantity": 500}
    revised = {**row, "lastUpdateDate": "2026-10-07", "totalWeeklyShareQuantity": 540}
    versions = parse_finra_weekly(json.dumps([first, revised]), fetched_at=NOW)
    assert len(versions) == 2
    assert versions[0].record_id != versions[1].record_id
    assert dict(versions[0].values)["shares"] != dict(versions[1].values)["shares"]
    assert dict(versions[0].values)["last_update_date"] == "2026-10-05"
    assert dict(versions[1].values)["last_update_date"] == "2026-10-07"


class _RecordingTransport:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.calls: list[tuple[str, str, dict[str, str], bytes | None, float, int]] = []

    def request(self, method, url, *, headers, body, timeout_s, max_bytes):
        self.calls.append((method, url, dict(headers), body, timeout_s, max_bytes))
        return type("FakeResponse", (), {"status": 200, "body": self.body, "headers": {}})()


def test_sec_user_agent_is_taken_from_settings_and_request_rate_never_exceeds_ten_per_second() -> (
    None
):
    example = ROOT / "apps" / "api" / "config" / "local-paper-market-data.example.toml"
    config = load_market_data_runtime_config(example)
    configured_ua = config.public_sources.sec_user_agent
    assert configured_ua == "LeviathanAI/0.1 contact@example.invalid"
    transport = _RecordingTransport(_fixture("sec-form4.xml"))
    client = PublicSourcesClient(transport=transport, sec_user_agent=configured_ua or "")

    clock = {"now": 0.0}

    def monotonic() -> float:
        return clock["now"]

    def sleep(seconds: float) -> None:
        clock["now"] += seconds

    with (
        patch.object(source_module.time, "monotonic", monotonic),
        patch.object(source_module.time, "sleep", sleep),
    ):
        for _ in range(3):
            client.fetch_sec_form4(
                xml_url="https://www.sec.gov/Archives/edgar/data/1/x/form4.xml",
                cik="1",
                accession="x",
                filed_at=NOW,
            )
    assert [call[2]["User-Agent"] for call in transport.calls] == [configured_ua] * 3
    assert all(call[4] <= 15 and call[5] <= 8_000_000 for call in transport.calls)
    assert clock["now"] >= 0.2  # three requests require at least two 100 ms gaps
    with pytest.raises(PublicSourceError, match="SEC_RATE_MUST_BE_TEN_PER_SECOND"):
        PublicSourcesClient(sec_user_agent=configured_ua or "", sec_rate_per_second=11)


def test_missing_sec_user_agent_fails_closed_in_settings_and_client(tmp_path: Path) -> None:
    example = (
        ROOT / "apps" / "api" / "config" / "local-paper-market-data.example.toml"
    ).read_text()
    enabled_without_ua = example.replace(
        "[public_sources]\nenabled = false", "[public_sources]\nenabled = true"
    ).replace('sec_user_agent = "LeviathanAI/0.1 contact@example.invalid"\n', "")
    temp = tmp_path / "missing-ua.toml"
    temp.write_text(enabled_without_ua, encoding="utf-8")
    try:
        with pytest.raises(MarketDataConfigError, match="INVALID_CONFIG"):
            load_market_data_runtime_config(temp)
    finally:
        temp.unlink(missing_ok=True)
    with pytest.raises(PublicSourceError, match="SEC_USER_AGENT_REQUIRED"):
        PublicSourcesClient(sec_user_agent="")


def test_finra_secret_is_not_a_settings_field_and_absent_token_fails_closed(tmp_path: Path) -> None:
    example = (
        ROOT / "apps" / "api" / "config" / "local-paper-market-data.example.toml"
    ).read_text()
    assert "finra_bearer_token" not in example.lower()
    bad_settings = example + '\nfinra_bearer_token = "synthetic-never-a-real-secret"\n'
    temp = tmp_path / "forbidden-finra-token.toml"
    temp.write_text(bad_settings, encoding="utf-8")
    try:
        with pytest.raises(MarketDataConfigError):
            load_market_data_runtime_config(temp)
    finally:
        temp.unlink(missing_ok=True)
    transport = _RecordingTransport(_fixture("finra-weekly.json"))
    client = PublicSourcesClient(transport=transport, sec_user_agent="Test contact@example.test")
    with pytest.raises(PublicSourceError, match="FINRA_CREDENTIAL_REQUIRED"):
        client.fetch_finra_weekly(report_type="ATS_W_SMBL", week_start=date(2026, 9, 21))
    assert transport.calls == []


def test_finra_token_has_no_vault_resolver_integration_in_public_source_runtime() -> None:
    source = (
        ROOT
        / "packages"
        / "leviathan-market-data"
        / "src"
        / "leviathan_market_data"
        / "public_sources"
        / "sources.py"
    ).read_text()
    runtime = (
        ROOT / "apps" / "api" / "src" / "leviathan_api" / "market_data_runtime_config.py"
    ).read_text()
    assert "vault_ref_resolver" in source or "vault_resolver" in source
    assert "finra" in runtime.lower() and "vault" in runtime.lower()


@pytest.mark.parametrize(
    ("parser", "bad_payload", "kwargs", "code"),
    [
        (
            parse_sec_form4,
            b"<not-xml",
            {"cik": "1", "accession": "x", "filed_at": NOW, "fetched_at": NOW},
            "MALFORMED_XML",
        ),
        (
            parse_finra_regsho,
            b"Date|Symbol\n2026-10-08|XYRA\n",
            {"trade_date": date(2026, 10, 8), "fetched_at": NOW},
            "SCHEMA_MISSING_COLUMN",
        ),
        (parse_finra_weekly, b"{}", {"fetched_at": NOW}, "MALFORMED_RECORD"),
        (parse_cftc_cot, b"{}", {"fetched_at": NOW}, "MALFORMED_RECORD"),
        (
            parse_treasury_curve,
            b"<feed><entry><content/></entry></feed>",
            {"fetched_at": NOW},
            "SCHEMA_MISSING_COLUMN",
        ),
    ],
)
def test_malformed_or_out_of_schema_payloads_raise_typed_errors_without_partial_records(
    parser, bad_payload, kwargs, code
) -> None:
    with pytest.raises(PublicSourceError) as raised:
        parser(bad_payload, **kwargs)
    assert raised.value.code == code


def test_valid_prefix_followed_by_malformed_finra_row_does_not_return_partial_records() -> None:
    payload = (
        b"Date|Symbol|ShortVolume|ShortExemptVolume|TotalVolume\n"
        b"2026-10-08|XYRA|10|0|20\n"
        b"2026-10-08|BAD|NaN|0|20\n"
    )
    with pytest.raises(PublicSourceError, match="MALFORMED_RECORD"):
        parse_finra_regsho(payload, trade_date=date(2026, 10, 8), fetched_at=NOW)


def test_adapter_import_origin_points_to_frozen_writer_snapshot() -> None:
    source_file = Path(source_module.__file__).resolve()
    assert source_file.is_relative_to(ROOT)
    assert (
        source_file
        == (
            ROOT
            / "packages"
            / "leviathan-market-data"
            / "src"
            / "leviathan_market_data"
            / "public_sources"
            / "sources.py"
        ).resolve()
    )
