from __future__ import annotations

from collections.abc import Mapping
from datetime import date
from decimal import Decimal

import pytest

from leviathan_market_data.providers.wave34.bea import (
    BEAAdapterError,
    parse_bea_data,
)
from leviathan_market_data.providers.wave34.bea import (
    build_adapter as build_bea,
)
from leviathan_market_data.providers.wave34.bls import (
    BLSAdapterError,
    parse_bls_series,
)
from leviathan_market_data.providers.wave34.bls import (
    build_adapter as build_bls,
)
from leviathan_market_data.providers.wave34.eia import (
    EIAAdapterError,
    parse_eia_data,
)
from leviathan_market_data.providers.wave34.eia import (
    build_adapter as build_eia,
)
from leviathan_market_data.providers.wave34.fred_alfred import (
    FREDAdapterError,
    parse_fred_observations,
)
from leviathan_market_data.providers.wave34.fred_alfred import (
    build_adapter as build_fred,
)


class FakeResponse:
    status_code = 200

    def __init__(self, body: bytes) -> None:
        self.body = body


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, object]]] = []

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Mapping[str, str],
        connect_timeout_s: float,
        read_timeout_s: float,
        total_timeout_s: float,
        allow_redirects: bool,
    ) -> FakeResponse:
        del headers, connect_timeout_s, read_timeout_s, total_timeout_s, allow_redirects
        self.calls.append((url, params))
        if "api.bls.gov" in url:
            return FakeResponse(
                b'{"Results":{"series":[{"seriesID":"LNS","unit":"Persons",'
                b'"data":[{"year":"2024","period":"M01","value":"5"}]}]}}'
            )
        return FakeResponse(b"{}")

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        json: Mapping[str, object],
        connect_timeout_s: float,
        read_timeout_s: float,
        total_timeout_s: float,
        allow_redirects: bool,
    ) -> FakeResponse:
        del headers, connect_timeout_s, read_timeout_s, total_timeout_s, allow_redirects
        self.calls.append((url, json))
        return FakeResponse(
            b'{"Results":{"series":[{"seriesID":"LNS","unit":"Persons",'
            b'"data":[{"year":"2024","period":"M01","value":"5"}]}]}}'
        )


def test_fred_keeps_observation_release_and_vintage_dates_separate() -> None:
    result = parse_fred_observations(
        {
            "observations": [
                {
                    "date": "2024-01-01",
                    "value": "1.250",
                    "units": "Index",
                    "realtime_start": "2024-02-15",
                    "release_date": "2024-02-14",
                }
            ]
        },
        series_id="SERIES",
        dataset_id="cpi",
        mapping_version="map-1",
        ingest_time_ns=10,
    )[0]
    assert result.value == Decimal("1.250")
    assert result.observation_date == date(2024, 1, 1)
    assert result.release_date == date(2024, 2, 14)
    assert result.vintage_date == date(2024, 2, 15)
    assert result.source_revision == "2024-02-15"


def test_fred_null_is_preserved_and_page_cap_is_enforced() -> None:
    result = parse_fred_observations(
        {"observations": [{"date": "2024-01-01", "value": "."}]},
        series_id="S",
        dataset_id="d",
        mapping_version="m",
        ingest_time_ns=0,
    )[0]
    assert result.value is None
    with pytest.raises(FREDAdapterError, match="CAP_EXCEEDED"):
        parse_fred_observations(
            {
                "observations": [
                    {"date": "2024-01-01", "value": "1"},
                    {"date": "2024-02-01", "value": "2"},
                ]
            },
            series_id="S",
            dataset_id="d",
            mapping_version="m",
            ingest_time_ns=0,
            limit=1,
        )


def test_bls_keyless_parser_preserves_unit_and_null() -> None:
    result = parse_bls_series(
        {
            "Results": {
                "series": [
                    {
                        "seriesID": "LNS",
                        "unit": "Persons",
                        "data": [
                            {"year": "2024", "period": "M01", "value": "-"},
                        ],
                    }
                ]
            }
        },
        series_id="LNS",
        dataset_id="labor",
        mapping_version="m",
        ingest_time_ns=1,
    )[0]
    assert result.value is None
    assert result.unit == "Persons"
    assert result.observation_date == date(2024, 1, 1)
    assert result.release_date is None


def test_bls_keyless_adapter_uses_injected_transport() -> None:
    transport = FakeTransport()
    adapter = build_bls(resolve_secret=lambda _name: "must-not-be-used", transport=transport)
    records = adapter.fetch_series(
        series_id="LNS",
        dataset_id="labor",
        mapping_version="m",
        ingest_time_ns=1,
        release_date=date(2024, 2, 2),
    )
    assert adapter.configured
    assert records[0].value == Decimal("5")
    assert records[0].release_date == date(2024, 2, 2)
    assert transport.calls[0][0] == "https://api.bls.gov/publicAPI/v1/timeseries/data/"
    assert transport.calls[0][1]["seriesid"] == "LNS"


def test_bea_applies_unit_multiplier_without_losing_unit() -> None:
    result = parse_bea_data(
        {
            "BEAAPI": {
                "Results": {
                    "Data": [
                        {
                            "TimePeriod": "2024Q1",
                            "DataValue": "1.25",
                            "UNIT_MULT": "6",
                            "CL_UNIT": "Dollars",
                        }
                    ]
                }
            }
        },
        dataset_id="NIPA",
        mapping_version="m",
        ingest_time_ns=1,
    )[0]
    assert result.value == Decimal("1250000.00")
    assert result.unit == "Dollars"
    assert result.observation_date == date(2024, 1, 1)


def test_eia_keeps_null_unit_and_explicit_release_date() -> None:
    result = parse_eia_data(
        {
            "response": {
                "data": [
                    {
                        "period": "2024-01",
                        "value": None,
                        "units": "MWh",
                        "release_date": "2024-02-01",
                    }
                ]
            }
        },
        dataset_id="electricity",
        mapping_version="m",
        ingest_time_ns=1,
    )[0]
    assert result.value is None
    assert result.unit == "MWh"
    assert result.observation_date == date(2024, 1, 1)
    assert result.release_date == date(2024, 2, 1)


@pytest.mark.parametrize(
    ("parser", "payload", "kwargs", "error"),
    [
        (
            parse_fred_observations,
            {
                "observations": [
                    {"date": "2024-01-01", "value": "1"},
                    {"date": "2024-02-01", "value": "2"},
                ]
            },
            {
                "series_id": "S",
                "dataset_id": "d",
                "mapping_version": "m",
                "ingest_time_ns": 0,
                "limit": 1,
            },
            FREDAdapterError,
        ),
        (
            parse_bls_series,
            {
                "Results": {
                    "series": [
                        {
                            "seriesID": "S",
                            "data": [
                                {"year": "2024", "period": "M01", "value": "1"},
                                {"year": "2024", "period": "M02", "value": "2"},
                            ],
                        }
                    ]
                }
            },
            {
                "series_id": "S",
                "dataset_id": "d",
                "mapping_version": "m",
                "ingest_time_ns": 0,
                "limit": 1,
            },
            BLSAdapterError,
        ),
        (
            parse_bea_data,
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
            {"dataset_id": "d", "mapping_version": "m", "ingest_time_ns": 0, "limit": 1},
            BEAAdapterError,
        ),
        (
            parse_eia_data,
            {
                "response": {
                    "data": [
                        {"period": "2024-01", "value": "1"},
                        {"period": "2024-02", "value": "2"},
                    ]
                }
            },
            {"dataset_id": "d", "mapping_version": "m", "ingest_time_ns": 0, "limit": 1},
            EIAAdapterError,
        ),
    ],
)
def test_provider_caps_reject_oversized_pages(parser, payload, kwargs, error) -> None:
    with pytest.raises(error, match="CAP_EXCEEDED"):
        parser(payload, **kwargs)


def test_missing_credentials_make_zero_transport_calls() -> None:
    transport = FakeTransport()

    def resolver(_name: str) -> str:
        raise KeyError("missing")

    fred = build_fred(resolve_secret=resolver, transport=transport)
    bea = build_bea(resolve_secret=resolver, transport=transport)
    eia = build_eia(resolve_secret=resolver, transport=transport)
    bls = build_bls(resolve_secret=resolver, transport=transport)
    assert not fred.configured and not bea.configured and not eia.configured
    assert bls.configured
    with pytest.raises(FREDAdapterError, match="CREDENTIAL_UNAVAILABLE"):
        fred.fetch_series(series_id="S", dataset_id="d", mapping_version="m", ingest_time_ns=0)
    with pytest.raises(BEAAdapterError, match="CREDENTIAL_UNAVAILABLE"):
        bea.fetch_data(dataset_id="d", params={}, mapping_version="m", ingest_time_ns=0)
    with pytest.raises(EIAAdapterError, match="CREDENTIAL_UNAVAILABLE"):
        eia.fetch_data(
            route="electricity", dataset_id="d", params={}, mapping_version="m", ingest_time_ns=0
        )
    assert transport.calls == []
