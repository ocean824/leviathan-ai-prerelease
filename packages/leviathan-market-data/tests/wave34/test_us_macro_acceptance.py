"""Independent, offline acceptance checks for DATA-007 U.S. macro providers."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

import pytest

from leviathan_market_data.providers.wave34 import bea, bls, eia, fred_alfred


class FakeResponse:
    def __init__(self, body: bytes, status_code: int = 200) -> None:
        self.body = body
        self.status_code = status_code


class FakeTransport:
    def __init__(self, body: bytes = b"{}", *, error: Exception | None = None) -> None:
        self.body = body
        self.error = error
        self.calls: list[tuple[str, dict[str, str], dict[str, str], dict[str, Any]]] = []

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str],
        params: dict[str, str],
        connect_timeout_s: float,
        read_timeout_s: float,
        total_timeout_s: float,
        allow_redirects: bool,
    ) -> FakeResponse:
        self.calls.append(
            (
                url,
                dict(headers),
                dict(params),
                {
                    "method": "GET",
                    "connect_timeout_s": connect_timeout_s,
                    "read_timeout_s": read_timeout_s,
                    "total_timeout_s": total_timeout_s,
                    "allow_redirects": allow_redirects,
                },
            )
        )
        if self.error is not None:
            raise self.error
        return FakeResponse(self.body)

    def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        json: dict[str, str],
        connect_timeout_s: float,
        read_timeout_s: float,
        total_timeout_s: float,
        allow_redirects: bool,
    ) -> FakeResponse:
        self.calls.append(
            (
                url,
                dict(headers),
                dict(json),
                {
                    "method": "POST",
                    "connect_timeout_s": connect_timeout_s,
                    "read_timeout_s": read_timeout_s,
                    "total_timeout_s": total_timeout_s,
                    "allow_redirects": allow_redirects,
                },
            )
        )
        if self.error is not None:
            raise self.error
        return FakeResponse(self.body)


INGEST_NS = 1_800_000_000_000_000_000


def _fred_payload(value: str, vintage: str) -> dict[str, object]:
    return {
        "units": "Dollars per unit",
        "observations": [
            {
                "date": "2024-01-01",
                "realtime_start": vintage,
                "value": value,
                "release_date": "2024-02-15",
            }
        ],
    }


def _bls_payload(value: str) -> dict[str, object]:
    return {
        "Results": {
            "series": [
                {
                    "seriesID": "CUUR0000SA0",
                    "unit": "Index 1982-84=100",
                    "data": [
                        {
                            "year": "2024",
                            "period": "M01",
                            "value": value,
                            "release_date": "2024-02-13",
                        }
                    ],
                }
            ]
        }
    }


def _bea_payload(value: str) -> dict[str, object]:
    return {
        "BEAAPI": {
            "Results": {
                "Data": [
                    {
                        "TimePeriod": "2024Q1",
                        "DataValue": value,
                        "UNIT_MULT": 0,
                        "CL_UNIT": "Millions of dollars",
                        "LineNumber": "1",
                        "ReleaseDate": "2024-04-25",
                    }
                ]
            }
        }
    }


def _eia_payload(value: str | None) -> dict[str, object]:
    return {
        "response": {
            "data": [
                {
                    "period": "2024-01",
                    "value": value,
                    "units": "million barrels per day",
                    "release_date": "2024-02-07",
                    "vintage_date": "2024-02-08",
                    "series": "PET.RWTC.D",
                }
            ]
        }
    }


def _parse_all(*, fred: object, bls_value: str, bea_value: str, eia_value: str | None):
    f = fred_alfred.parse_fred_observations(
        fred,
        series_id="DGS10",
        dataset_id="macro.rates",
        mapping_version="macro-map-v1",
        ingest_time_ns=INGEST_NS,
    )
    b = bls.parse_bls_series(
        _bls_payload(bls_value),
        series_id="CUUR0000SA0",
        dataset_id="macro.cpi",
        mapping_version="macro-map-v1",
        ingest_time_ns=INGEST_NS,
    )
    a = bea.parse_bea_data(
        _bea_payload(bea_value),
        dataset_id="macro.gdp",
        mapping_version="macro-map-v1",
        ingest_time_ns=INGEST_NS,
    )
    e = eia.parse_eia_data(
        _eia_payload(eia_value),
        dataset_id="macro.crude",
        mapping_version="macro-map-v1",
        ingest_time_ns=INGEST_NS,
    )
    return f[0], b[0], a[0], e[0]


def test_registration_surface_declares_closed_provider_and_credential_ids() -> None:
    expected = (
        (fred_alfred, "fred", frozenset({"MACRO_SERIES", "VINTAGES"}), ("fred_api_key",)),
        (bls, "bls", frozenset({"MACRO_SERIES"}), ()),
        (bea, "bea", frozenset({"MACRO_SERIES"}), ("bea_api_key",)),
        (eia, "eia", frozenset({"MACRO_SERIES"}), ("eia_api_key",)),
    )
    for module, provider_id, capabilities, credential_names in expected:
        assert provider_id == module.PROVIDER_ID
        assert capabilities == module.CAPABILITIES
        assert credential_names == module.CREDENTIAL_NAMES
        assert callable(module.build_adapter)
        assert module.__doc__ is not None
        assert "Before activation, verify" in module.__doc__
    assert "fred.stlouisfed.org" in fred_alfred.__doc__
    assert "bls.gov" in bls.__doc__
    assert "apps.bea.gov" in bea.__doc__
    assert "eia.gov" in eia.__doc__


def test_fred_preserves_each_vintage_as_a_distinct_revision() -> None:
    first, revised = fred_alfred.parse_fred_observations(
        {
            "units": "Dollars per unit",
            "observations": [
                {
                    "date": "2024-01-01",
                    "realtime_start": "2024-02-15",
                    "realtime_end": "2024-03-14",
                    "value": "4.20",
                    "release_date": "2024-02-15",
                },
                {
                    "date": "2024-01-01",
                    "realtime_start": "2024-03-15",
                    "realtime_end": "9999-12-31",
                    "value": "4.25",
                    "release_date": "2024-02-15",
                },
            ],
        },
        series_id="DGS10",
        dataset_id="macro.rates",
        mapping_version="macro-map-v1",
        ingest_time_ns=INGEST_NS,
    )

    assert first.observation_date == revised.observation_date == date(2024, 1, 1)
    assert first.release_date == revised.release_date == date(2024, 2, 15)
    assert first.vintage_date == date(2024, 2, 15)
    assert revised.vintage_date == date(2024, 3, 15)
    assert first.source_revision == "2024-02-15"
    assert revised.source_revision == "2024-03-15"
    assert first.observation_id != revised.observation_id
    assert first.value == Decimal("4.20")
    assert revised.value == Decimal("4.25")


def test_fred_as_of_vintage_is_sent_as_a_closed_single_vintage_request() -> None:
    vintage = date(2024, 2, 15)
    transport = FakeTransport(json.dumps(_fred_payload("4.20", "2024-02-15")).encode())
    adapter = fred_alfred.build_adapter(
        resolve_secret=lambda name: "synthetic-fred-key",
        transport=transport,
    )

    result = adapter.fetch_series(
        series_id="DGS10",
        dataset_id="macro.rates",
        mapping_version="macro-map-v1",
        ingest_time_ns=INGEST_NS,
        vintage_date=vintage,
    )

    assert len(transport.calls) == 1
    params = transport.calls[0][2]
    assert params["realtime_start"] == params["realtime_end"] == vintage.isoformat()
    assert result[0].source_revision == vintage.isoformat()
    assert result[0].vintage_date == vintage


def test_observation_release_and_ingest_times_remain_distinct_and_units_survive() -> None:
    f, b, a, e = _parse_all(
        fred=_fred_payload("1.0", "2024-02-15"),
        bls_value="312.4",
        bea_value="28000",
        eia_value="13.2",
    )
    assert (f.observation_date, f.release_date, f.ingest_time_ns) == (
        date(2024, 1, 1),
        date(2024, 2, 15),
        INGEST_NS,
    )
    assert (b.observation_date, b.release_date, b.ingest_time_ns) == (
        date(2024, 1, 1),
        date(2024, 2, 13),
        INGEST_NS,
    )
    assert (a.observation_date, a.release_date, a.ingest_time_ns) == (
        date(2024, 1, 1),
        date(2024, 4, 25),
        INGEST_NS,
    )
    assert (e.observation_date, e.release_date, e.vintage_date, e.ingest_time_ns) == (
        date(2024, 1, 1),
        date(2024, 2, 7),
        date(2024, 2, 8),
        INGEST_NS,
    )
    assert f.unit == "Dollars per unit"
    assert b.unit == "Index 1982-84=100"
    assert a.unit == "Millions of dollars"
    assert e.unit == "million barrels per day"
    expected_observation_time_ns = int(datetime(2024, 1, 1, tzinfo=UTC).timestamp() * 1_000_000_000)
    for record in (f, b, a, e):
        assert record.source_id in {"fred", "bls", "bea", "eia"}
        assert record.dataset_id
        assert record.mapping_version == "macro-map-v1"
        assert len(record.provenance_digest) == 64
        assert record.event_time_ns == expected_observation_time_ns
        assert record.ingest_time_ns == INGEST_NS
        assert record.event_time_ns != record.ingest_time_ns


def test_caller_release_and_vintage_metadata_override_row_fields() -> None:
    release = date(2024, 5, 1)
    vintage = date(2024, 5, 2)
    b = bls.parse_bls_series(
        _bls_payload("312.4"),
        series_id="CUUR0000SA0",
        dataset_id="macro.cpi",
        mapping_version="macro-map-v1",
        ingest_time_ns=INGEST_NS,
        release_date=release,
    )[0]
    a = bea.parse_bea_data(
        _bea_payload("28000"),
        dataset_id="macro.gdp",
        mapping_version="macro-map-v1",
        ingest_time_ns=INGEST_NS,
        release_date=release,
        vintage_date=vintage,
    )[0]
    e = eia.parse_eia_data(
        _eia_payload("13.2"),
        dataset_id="macro.crude",
        mapping_version="macro-map-v1",
        ingest_time_ns=INGEST_NS,
        release_date=release,
        vintage_date=vintage,
    )[0]
    assert b.release_date == release
    assert a.release_date == e.release_date == release
    assert a.vintage_date == e.vintage_date == vintage


def test_provider_missing_markers_stay_null_not_zero() -> None:
    f, b, a, e = _parse_all(
        fred=_fred_payload(".", "2024-02-15"),
        bls_value="-",
        bea_value="(D)",
        eia_value=None,
    )
    assert [record.value for record in (f, b, a, e)] == [None, None, None, None]


@pytest.mark.parametrize(
    ("parser", "payload", "kwargs"),
    [
        (
            fred_alfred.parse_fred_observations,
            {
                "observations": [
                    {"date": "2024-01-01", "value": "1"},
                    {"date": "2024-02-01", "value": "2"},
                ]
            },
            {"series_id": "DGS10"},
        ),
        (
            bls.parse_bls_series,
            {
                "Results": {
                    "series": [
                        {
                            "seriesID": "X",
                            "data": [
                                {"year": "2024", "period": "M01", "value": "1"},
                                {"year": "2024", "period": "M02", "value": "2"},
                            ],
                        }
                    ]
                }
            },
            {"series_id": "X"},
        ),
        (
            bea.parse_bea_data,
            {
                "BEAAPI": {
                    "Results": {
                        "Data": [
                            {"TimePeriod": "2024Q1", "DataValue": "1"},
                            {"TimePeriod": "2024Q2", "DataValue": "2"},
                        ]
                    }
                }
            },
            {},
        ),
        (
            eia.parse_eia_data,
            {
                "response": {
                    "data": [
                        {"period": "2024-01", "value": "1"},
                        {"period": "2024-02", "value": "2"},
                    ]
                }
            },
            {},
        ),
    ],
)
def test_record_limit_rejects_oversized_page_without_truncation(parser, payload, kwargs) -> None:
    with pytest.raises(ValueError) as caught:
        parser(
            payload,
            **kwargs,
            dataset_id="macro.test",
            mapping_version="macro-map-v1",
            ingest_time_ns=INGEST_NS,
            limit=1,
        )
    assert caught.value.code == "CAP_EXCEEDED"


@pytest.mark.parametrize(
    ("module", "fetch_name", "fetch_kwargs", "payload"),
    [
        (
            fred_alfred,
            "fetch_series",
            {"series_id": "DGS10", "dataset_id": "macro.rates"},
            {
                "observations": [
                    {"date": "2024-01-01", "value": "1"},
                    {"date": "2024-02-01", "value": "2"},
                ]
            },
        ),
        (
            bls,
            "fetch_series",
            {"series_id": "X", "dataset_id": "macro.test"},
            {
                "Results": {
                    "series": [
                        {
                            "seriesID": "X",
                            "data": [
                                {"year": "2024", "period": "M01", "value": "1"},
                                {"year": "2024", "period": "M02", "value": "2"},
                            ],
                        }
                    ]
                }
            },
        ),
        (
            bea,
            "fetch_data",
            {"dataset_id": "T10101", "params": {"TableName": "T10101"}},
            {
                "BEAAPI": {
                    "Results": {
                        "Data": [
                            {"TimePeriod": "2024Q1", "DataValue": "1"},
                            {"TimePeriod": "2024Q2", "DataValue": "2"},
                        ]
                    }
                }
            },
        ),
        (
            eia,
            "fetch_data",
            {"route": "petroleum/sum/sndw", "dataset_id": "macro.crude", "params": {}},
            {
                "response": {
                    "data": [
                        {"period": "2024-01", "value": "1"},
                        {"period": "2024-02", "value": "2"},
                    ]
                }
            },
        ),
    ],
)
def test_fetch_is_bounded_to_one_page_and_rejects_over_cap_response(
    module, fetch_name: str, fetch_kwargs: dict[str, Any], payload: dict[str, object]
) -> None:
    transport = FakeTransport(json.dumps(payload).encode())
    adapter = module.build_adapter(
        resolve_secret=lambda name: f"synthetic-{name}", transport=transport
    )
    with pytest.raises(ValueError) as caught:
        getattr(adapter, fetch_name)(
            **fetch_kwargs,
            mapping_version="macro-map-v1",
            ingest_time_ns=INGEST_NS,
            limit=1,
        )
    assert caught.value.code == "CAP_EXCEEDED"
    assert len(transport.calls) == 1


def test_keyless_bls_does_not_resolve_a_secret_and_fetches_once() -> None:
    transport = FakeTransport(json.dumps(_bls_payload("312.4")).encode())

    def fail_secret_lookup(name: str) -> str:
        raise AssertionError(f"keyless BLS attempted secret lookup: {name}")

    adapter = bls.build_adapter(resolve_secret=fail_secret_lookup, transport=transport)
    assert adapter.configured is True
    results = adapter.fetch_series(
        series_id="CUUR0000SA0",
        dataset_id="macro.cpi",
        mapping_version="macro-map-v1",
        ingest_time_ns=INGEST_NS,
    )
    assert len(results) == 1
    assert len(transport.calls) == 1
    assert transport.calls[0][3]["method"] == "GET"


@pytest.mark.parametrize(
    ("module", "fetch_name", "fetch_kwargs"),
    [
        (
            fred_alfred,
            "fetch_series",
            {"series_id": "DGS10", "dataset_id": "macro.rates"},
        ),
        (
            bea,
            "fetch_data",
            {"dataset_id": "T10101", "params": {"TableName": "T10101"}},
        ),
        (
            eia,
            "fetch_data",
            {"route": "petroleum/sum/sndw", "dataset_id": "macro.crude", "params": {}},
        ),
    ],
)
def test_keyed_adapters_without_credentials_fail_before_transport(
    module, fetch_name: str, fetch_kwargs: dict[str, Any]
) -> None:
    transport = FakeTransport()

    def unconfigured(name: str) -> str:
        raise LookupError("synthetic test vault has no configured credential")

    adapter = module.build_adapter(resolve_secret=unconfigured, transport=transport)
    assert adapter.configured is False
    fetch = getattr(adapter, fetch_name)
    with pytest.raises(ValueError) as caught:
        fetch(**fetch_kwargs, mapping_version="macro-map-v1", ingest_time_ns=INGEST_NS)
    assert caught.value.code == "CREDENTIAL_UNAVAILABLE"
    assert len(transport.calls) == 0


@pytest.mark.parametrize(
    ("module", "fetch_name", "fetch_kwargs", "payload"),
    [
        (
            fred_alfred,
            "fetch_series",
            {"series_id": "DGS10", "dataset_id": "macro.rates"},
            json.dumps(_fred_payload("1.0", "2024-02-15")).encode(),
        ),
        (
            bea,
            "fetch_data",
            {"dataset_id": "T10101", "params": {"TableName": "T10101"}},
            json.dumps(_bea_payload("28000")).encode(),
        ),
        (
            eia,
            "fetch_data",
            {"route": "petroleum/sum/sndw", "dataset_id": "macro.crude", "params": {}},
            json.dumps(_eia_payload("13.2")).encode(),
        ),
    ],
)
def test_keyed_adapter_errors_redact_synthetic_secret(
    module,
    fetch_name: str,
    fetch_kwargs: dict[str, Any],
    payload: bytes,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "synthetic-secret-do-not-leak"
    transport = FakeTransport(payload, error=RuntimeError(f"provider echoed {secret}"))
    adapter = module.build_adapter(resolve_secret=lambda _name: secret, transport=transport)
    fetch = getattr(adapter, fetch_name)

    with pytest.raises(ValueError) as caught:
        fetch(**fetch_kwargs, mapping_version="macro-map-v1", ingest_time_ns=INGEST_NS)

    assert caught.value.code == "HTTP_STATUS"
    assert secret not in str(caught.value)
    assert secret not in repr(caught.value)
    assert secret not in repr(adapter)
    assert secret not in caplog.text
    assert len(transport.calls) == 1


def test_fred_parser_accepts_bytes_text_and_mapping_with_stable_provenance() -> None:
    payload = _fred_payload("4.20", "2024-02-15")
    common = {
        "series_id": "DGS10",
        "dataset_id": "macro.rates",
        "mapping_version": "macro-map-v1",
        "ingest_time_ns": INGEST_NS,
    }
    records = [
        fred_alfred.parse_fred_observations(payload, **common)[0],
        fred_alfred.parse_fred_observations(json.dumps(payload), **common)[0],
        fred_alfred.parse_fred_observations(json.dumps(payload).encode(), **common)[0],
    ]
    assert (
        records[0].provenance_digest == records[1].provenance_digest == records[2].provenance_digest
    )
