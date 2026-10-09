"""Offline-first Bureau of Labor Statistics public v1 adapter.

Official schema/signature: https://www.bls.gov/developers/api_signature.htm
Official API limits and version guidance: https://www.bls.gov/developers/api_FAQs.htm
Before activation, verify the actual release timestamp, response layout and market mapping
against an official recorded release and the caller's mapping version.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Protocol

from leviathan_core.numeric import NumericError, parse_decimal

PROVIDER_ID = "bls"
CAPABILITIES = frozenset({"MACRO_SERIES"})
CREDENTIAL_NAMES: tuple[str, ...] = ()
MAX_RECORDS = 500
MAX_BYTES = 2_000_000


class BLSAdapterError(ValueError):
    """Content-free provider error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class BLSObservationV1:
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


def _decimal(value: object) -> Decimal | None:
    if value in (None, "", "-"):
        return None
    if type(value) is not str:
        raise BLSAdapterError("INVALID_VALUE")
    try:
        return parse_decimal(value, field="value")
    except NumericError as exc:
        code = "PRECISION_EXCEEDED" if exc.code == "PRECISION_EXCEEDED" else "INVALID_VALUE"
        raise BLSAdapterError(code) from None
    except (InvalidOperation, ValueError):
        raise BLSAdapterError("INVALID_VALUE") from None


def _observation_date(year: object, period: object) -> date:
    if type(year) is not str or not re.fullmatch(r"\d{4}", year):
        raise BLSAdapterError("MALFORMED_RECORD")
    if type(period) is not str:
        raise BLSAdapterError("MALFORMED_RECORD")
    if period == "M13":
        return date(int(year), 1, 1)
    match = re.fullmatch(r"M(\d{2})", period)
    if match and 1 <= int(match.group(1)) <= 12:
        return date(int(year), int(match.group(1)), 1)
    if period == "A01":
        return date(int(year), 1, 1)
    raise BLSAdapterError("MALFORMED_RECORD")


def _date(value: object) -> date | None:
    if value is None or value == "":
        return None
    if type(value) is not str:
        raise BLSAdapterError("MALFORMED_RECORD")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise BLSAdapterError("MALFORMED_RECORD") from None


def _ns(value: date) -> int:
    return (value.toordinal() - date(1970, 1, 1).toordinal()) * 86_400_000_000_000


def parse_bls_series(
    payload: bytes | str | Mapping[str, object],
    *,
    series_id: str,
    dataset_id: str,
    mapping_version: str,
    ingest_time_ns: int,
    release_date: date | None = None,
    limit: int = MAX_RECORDS,
) -> tuple[BLSObservationV1, ...]:
    try:
        if isinstance(payload, bytes):
            if len(payload) > MAX_BYTES:
                raise BLSAdapterError("OVERSIZE")
            doc = json.loads(payload)
        elif isinstance(payload, str):
            if len(payload.encode()) > MAX_BYTES:
                raise BLSAdapterError("OVERSIZE")
            doc = json.loads(payload)
        else:
            doc = payload
    except BLSAdapterError:
        raise
    except Exception:
        raise BLSAdapterError("MALFORMED_RECORD") from None
    if (
        not isinstance(doc, Mapping)
        or type(series_id) is not str
        or not series_id
        or type(dataset_id) is not str
        or not dataset_id
        or type(mapping_version) is not str
        or not mapping_version
        or type(ingest_time_ns) is not int
        or ingest_time_ns < 0
        or (release_date is not None and type(release_date) is not date)
        or type(limit) is not int
        or not 1 <= limit <= MAX_RECORDS
    ):
        raise BLSAdapterError("INVALID_REQUEST")
    try:
        results = doc["Results"]
        series = results["series"]
        selected = next(item for item in series if item.get("seriesID") == series_id)
        rows = selected["data"]
    except Exception:
        raise BLSAdapterError("SCHEMA_MISSING_COLUMN") from None
    if not isinstance(rows, list):
        raise BLSAdapterError("MALFORMED_RECORD")
    if len(rows) > limit:
        raise BLSAdapterError("CAP_EXCEEDED")
    output: list[BLSObservationV1] = []
    for row in rows:
        if not isinstance(row, Mapping) or not {"year", "period", "value"} <= row.keys():
            raise BLSAdapterError("SCHEMA_MISSING_COLUMN")
        obs_date = _observation_date(row["year"], row["period"])
        value = _decimal(row["value"])
        unit = row.get("unit", selected.get("unit", "provider-defined"))
        if type(unit) is not str or not unit:
            raise BLSAdapterError("MALFORMED_RECORD")
        identity = f"{series_id}:{row['year']}:{row['period']}"
        canonical = json.dumps(dict(row), sort_keys=True, separators=(",", ":"), default=str)
        output.append(
            BLSObservationV1(
                PROVIDER_ID,
                dataset_id,
                identity,
                _ns(obs_date),
                ingest_time_ns,
                value,
                unit,
                mapping_version,
                hashlib.sha256(canonical.encode()).hexdigest(),
                str(row["revision"]) if type(row.get("revision")) is str else None,
                obs_date,
                release_date or _date(row.get("release_date")),
                None,
            )
        )
    return tuple(output)


class BLSAdapter:
    configured = True

    def __init__(self, *, transport: Transport) -> None:
        self._transport = transport

    def fetch_series(
        self,
        *,
        series_id: str,
        dataset_id: str,
        mapping_version: str,
        ingest_time_ns: int,
        release_date: date | None = None,
        start_year: str | None = None,
        end_year: str | None = None,
        limit: int = MAX_RECORDS,
    ) -> tuple[BLSObservationV1, ...]:
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
        ):
            raise BLSAdapterError("INVALID_REQUEST")
        params = {"seriesid": series_id}
        if start_year is not None:
            params["startyear"] = start_year
        if end_year is not None:
            params["endyear"] = end_year
        try:
            response = self._transport.get(
                "https://api.bls.gov/publicAPI/v1/timeseries/data/",
                headers={},
                params=params,
                connect_timeout_s=3.0,
                read_timeout_s=5.0,
                total_timeout_s=10.0,
                allow_redirects=False,
            )
        except Exception:
            raise BLSAdapterError("HTTP_STATUS") from None
        if not 200 <= response.status_code < 300:
            raise BLSAdapterError("HTTP_STATUS")
        return parse_bls_series(
            response.body,
            series_id=series_id,
            dataset_id=dataset_id,
            mapping_version=mapping_version,
            ingest_time_ns=ingest_time_ns,
            release_date=release_date,
            limit=limit,
        )


def build_adapter(*, resolve_secret: Callable[[str], str], transport: Transport) -> BLSAdapter:
    del resolve_secret  # public v1 is intentionally keyless
    return BLSAdapter(transport=transport)
