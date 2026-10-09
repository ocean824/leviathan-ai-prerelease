"""Offline-first FRED/ALFRED observations.

Schema and API references: https://fred.stlouisfed.org/docs/api/fred/series_observations.html
API overview and authentication: https://fred.stlouisfed.org/docs/api/fred/
Before activation, verify the actual release timestamp, response layout and market mapping
against an official recorded release and the caller's mapping version.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Protocol

from leviathan_core.numeric import NumericError, parse_decimal

PROVIDER_ID = "fred"
CAPABILITIES = frozenset({"MACRO_SERIES", "VINTAGES"})
CREDENTIAL_NAMES = ("fred_api_key",)
MAX_RECORDS = 5000
MAX_BYTES = 2_000_000


class FREDAdapterError(ValueError):
    """Content-free provider error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class FREDObservationV1:
    source_id: str
    dataset_id: str
    observation_id: str
    event_time_ns: int
    ingest_time_ns: int
    value: Decimal | None
    unit: str
    mapping_version: str
    provenance_digest: str
    source_revision: str | None
    observation_date: date
    release_date: date | None
    vintage_date: date | None


class HTTPResponse(Protocol):
    status_code: int
    body: bytes


class Transport(Protocol):
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
    ) -> HTTPResponse: ...


def _date(value: object, *, required: bool) -> date | None:
    if value is None or value == "":
        if required:
            raise FREDAdapterError("MALFORMED_RECORD")
        return None
    try:
        if type(value) is not str:
            raise ValueError
        return date.fromisoformat(value)
    except ValueError:
        raise FREDAdapterError("MALFORMED_RECORD") from None


def _ns(value: date) -> int:
    return (value.toordinal() - date(1970, 1, 1).toordinal()) * 86_400_000_000_000


def _decimal(value: object) -> Decimal | None:
    if value in (None, "", "."):
        return None
    try:
        return parse_decimal(value, field="value")
    except NumericError as exc:
        code = "PRECISION_EXCEEDED" if exc.code == "PRECISION_EXCEEDED" else "INVALID_VALUE"
        raise FREDAdapterError(code) from None
    except (InvalidOperation, ValueError):
        raise FREDAdapterError("INVALID_VALUE") from None


def _payload(payload: bytes | str | Mapping[str, object]) -> Mapping[str, object]:
    try:
        if isinstance(payload, bytes):
            if len(payload) > MAX_BYTES:
                raise FREDAdapterError("OVERSIZE")
            doc = json.loads(payload)
        elif isinstance(payload, str):
            if len(payload.encode("utf-8")) > MAX_BYTES:
                raise FREDAdapterError("OVERSIZE")
            doc = json.loads(payload)
        else:
            doc = payload
        if not isinstance(doc, Mapping):
            raise ValueError
        return doc
    except FREDAdapterError:
        raise
    except Exception:
        raise FREDAdapterError("MALFORMED_RECORD") from None


def parse_fred_observations(
    payload: bytes | str | Mapping[str, object],
    *,
    series_id: str,
    dataset_id: str,
    mapping_version: str,
    ingest_time_ns: int,
    vintage_date: date | None = None,
    release_date: date | None = None,
    limit: int = MAX_RECORDS,
) -> tuple[FREDObservationV1, ...]:
    doc = _payload(payload)
    if (
        type(series_id) is not str
        or not series_id
        or type(dataset_id) is not str
        or not dataset_id
        or type(mapping_version) is not str
        or not mapping_version
        or type(ingest_time_ns) is not int
        or ingest_time_ns < 0
        or (release_date is not None and type(release_date) is not date)
        or (vintage_date is not None and type(vintage_date) is not date)
        or type(limit) is not int
        or not 1 <= limit <= MAX_RECORDS
    ):
        raise FREDAdapterError("INVALID_REQUEST")
    rows = doc.get("observations")
    if not isinstance(rows, list):
        raise FREDAdapterError("SCHEMA_MISSING_COLUMN")
    if len(rows) > limit:
        raise FREDAdapterError("CAP_EXCEEDED")
    output: list[FREDObservationV1] = []
    for row in rows:
        if not isinstance(row, Mapping) or "date" not in row or "value" not in row:
            raise FREDAdapterError("SCHEMA_MISSING_COLUMN")
        observation_date = _date(row.get("date"), required=True)
        assert observation_date is not None
        vintage = vintage_date or _date(row.get("realtime_start"), required=False)
        revision = vintage.isoformat() if vintage else None
        unit = row.get("units", doc.get("units", "unspecified"))
        if type(unit) is not str or not unit:
            raise FREDAdapterError("MALFORMED_RECORD")
        value = _decimal(row.get("value"))
        identity = f"{series_id}:{observation_date.isoformat()}:{revision or 'latest'}"
        canonical = json.dumps(dict(row), sort_keys=True, separators=(",", ":"), default=str)
        output.append(
            FREDObservationV1(
                PROVIDER_ID,
                dataset_id,
                identity,
                _ns(observation_date),
                ingest_time_ns,
                value,
                unit,
                mapping_version,
                hashlib.sha256(canonical.encode()).hexdigest(),
                revision,
                observation_date,
                release_date or _date(row.get("release_date"), required=False),
                vintage,
            )
        )
    return tuple(output)


class FREDAdapter:
    def __init__(self, *, api_key: str | None, transport: Transport) -> None:
        self._api_key = api_key
        self._transport = transport

    @property
    def configured(self) -> bool:
        return self._api_key is not None

    def fetch_series(
        self,
        *,
        series_id: str,
        dataset_id: str,
        mapping_version: str,
        ingest_time_ns: int,
        vintage_date: date | None = None,
        release_date: date | None = None,
        limit: int = MAX_RECORDS,
    ) -> tuple[FREDObservationV1, ...]:
        if not self.configured:
            raise FREDAdapterError("CREDENTIAL_UNAVAILABLE")
        if (
            type(series_id) is not str
            or not series_id
            or type(dataset_id) is not str
            or not dataset_id
            or type(mapping_version) is not str
            or not mapping_version
            or type(ingest_time_ns) is not int
            or ingest_time_ns < 0
            or type(limit) is not int
            or not 1 <= limit <= MAX_RECORDS
            or (release_date is not None and type(release_date) is not date)
            or (vintage_date is not None and type(vintage_date) is not date)
        ):
            raise FREDAdapterError("INVALID_REQUEST")
        params = {
            "series_id": series_id,
            "file_type": "json",
            "limit": str(limit),
            "sort_order": "asc",
            "api_key": self._api_key or "",
        }
        if vintage_date:
            params["realtime_start"] = params["realtime_end"] = vintage_date.isoformat()
        try:
            response = self._transport.get(
                "https://api.stlouisfed.org/fred/series/observations",
                headers={},
                params=params,
                connect_timeout_s=3.0,
                read_timeout_s=5.0,
                total_timeout_s=10.0,
                allow_redirects=False,
            )
        except Exception:
            raise FREDAdapterError("HTTP_STATUS") from None
        if not 200 <= response.status_code < 300:
            raise FREDAdapterError("HTTP_STATUS")
        return parse_fred_observations(
            response.body,
            series_id=series_id,
            dataset_id=dataset_id,
            mapping_version=mapping_version,
            ingest_time_ns=ingest_time_ns,
            vintage_date=vintage_date,
            release_date=release_date,
            limit=limit,
        )


def build_adapter(*, resolve_secret: Callable[[str], str], transport: Transport) -> FREDAdapter:
    try:
        secret: str | None = resolve_secret("fred_api_key")
        if type(secret) is not str or not secret:
            secret = None
    except Exception:
        secret = None
    return FREDAdapter(api_key=secret, transport=transport)
