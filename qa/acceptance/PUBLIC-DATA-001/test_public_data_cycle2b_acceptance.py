from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar
from urllib.parse import parse_qs, urlparse

import pytest

FROZEN = Path(
    os.environ.get(
        "PUBLIC_DATA_ACCEPTANCE_SOURCE_ROOT",
        str(Path(__file__).resolve().parents[3]),
    )
).resolve()
NOW = datetime(2026, 10, 9, 12, tzinfo=UTC)


class _Response:
    status = 200
    headers: ClassVar[dict[str, str]] = {}

    def __init__(self, body: bytes) -> None:
        self.body = body


class _Transport:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None,
        timeout_s: float,
        max_bytes: int,
    ) -> _Response:
        del timeout_s, max_bytes
        self.calls.append((method, url, headers, body))
        return _Response(self.body)


def test_coinbase_oi_import_origin_is_frozen_snapshot() -> None:
    import leviathan_market_data.public_sources as public_sources
    import leviathan_market_data.public_sources.sources as sources

    assert Path(public_sources.__file__).resolve().is_relative_to(FROZEN)
    assert Path(sources.__file__).resolve().is_relative_to(FROZEN)


def test_coinbase_us_open_interest_is_filtered_and_has_complete_provenance() -> None:
    from leviathan_market_data.public_sources import PublicEvidenceV1, PublicSourcesClient

    fixture_path = FROZEN.joinpath(
        "packages",
        "leviathan-market-data",
        "tests",
        "fixtures",
        "public_sources",
        "coinbase-futures-open-interest.json",
    )
    fixture = fixture_path.read_bytes()
    transport = _Transport(fixture)
    client = PublicSourcesClient(
        transport=transport,
        sec_user_agent="Leviathan acceptance contact@example.test",
        coinbase_derivatives_enabled=True,
        now=lambda: NOW,
    )

    records = client.fetch_coinbase_derivatives_open_interest()

    assert len(records) == 2
    assert {dict(record.values)["product_id"] for record in records} == {
        "BIP-USD",
        "BTC-DEC26-CDE",
    }
    for record in records:
        assert type(record) is PublicEvidenceV1
        assert record.source_tier == 1
        assert record.source_id == "coinbase.derivatives_us"
        assert record.fetched_at == NOW
        assert record.as_of == NOW
        assert record.knowable_at == NOW
        assert record.redistribution is False
        assert len(record.record_digest) == 64
        values = dict(record.values)
        assert values["product_type"] == "FUTURE"
        assert values["open_interest_scope"] == "contract_units"
        assert values["open_interest"] in {"179300", "121786"}

    assert len(transport.calls) == 1
    method, url, headers, body = transport.calls[0]
    assert method == "GET"
    assert body is None
    assert headers["Accept"] == "application/json"
    query = parse_qs(urlparse(url).query)
    assert query["product_type"] == ["FUTURE"]
    assert query["user_country_code"] == ["US"]
    assert query["get_all_products"] == ["true"]


@pytest.mark.parametrize(
    ("open_interest", "expected_error"),
    [(None, "SCHEMA_MISSING_COLUMN"), ("not-a-number", "SCHEMA_INVALID_VALUE")],
)
def test_coinbase_missing_or_malformed_oi_fails_with_typed_error(
    open_interest: str | None, expected_error: str
) -> None:
    from leviathan_market_data.public_sources import (
        PublicSourceError,
        PublicSourcesClient,
    )

    product: dict[str, object] = {
        "product_id": "BIP-USD",
        "product_type": "FUTURE",
        "future_product_details": {"contract_code": "BIP"},
    }
    if open_interest is not None:
        product["future_product_details"] = {
            "contract_code": "BIP",
            "open_interest": open_interest,
        }
    body = json.dumps(
        {"products": [product], "pagination": {"has_next": False, "has_prev": False}}
    ).encode()
    client = PublicSourcesClient(
        transport=_Transport(body),
        sec_user_agent="Leviathan acceptance contact@example.test",
        coinbase_derivatives_enabled=True,
        now=lambda: NOW,
    )

    with pytest.raises(PublicSourceError, match=expected_error):
        client.fetch_coinbase_derivatives_open_interest()
