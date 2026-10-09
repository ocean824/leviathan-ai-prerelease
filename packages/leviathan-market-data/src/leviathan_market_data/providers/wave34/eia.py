"""Offline-first U.S. Energy Information Administration API v2 adapter.

Official API schema and documentation: https://www.eia.gov/opendata/documentation.php
Official API v2 documentation PDF: https://www.eia.gov/opendata/documentation/APIv2.1.0.pdf
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

PROVIDER_ID = "eia"
CAPABILITIES = frozenset({"MACRO_SERIES"})
CREDENTIAL_NAMES = ("eia_api_key",)
MAX_RECORDS = 5000
MAX_BYTES = 2_000_000
_ROUTE = re.compile(r"[a-z0-9_./-]{1,160}\Z", re.ASCII)


class EIAAdapterError(ValueError):
    """Content-free provider error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class EIAObservationV1:
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


def _date(value: object, *, required: bool = False) -> date | None:
    if value is None or value == "":
        if required:
            raise EIAAdapterError("MALFORMED_RECORD")
        return None
    if type(value) is not str:
        raise EIAAdapterError("MALFORMED_RECORD")
    try:
        if re.fullmatch(r"\d{4}", value):
            return date(int(value), 1, 1)
        if re.fullmatch(r"\d{4}-\d{2}", value):
            return date.fromisoformat(value + "-01")
        if re.fullmatch(r"\d{4}Q[1-4]", value):
            return date(int(value[:4]), (int(value[-1]) - 1) * 3 + 1, 1)
        return date.fromisoformat(value)
    except ValueError:
        raise EIAAdapterError("MALFORMED_RECORD") from None


def _ns(value: date) -> int:
    return (value.toordinal() - date(1970, 1, 1).toordinal()) * 86_400_000_000_000


def _value(value: object) -> Decimal | None:
    if value in (None, "", "--"):
        return None
    try:
        return parse_decimal(value, field="value")
    except NumericError as exc:
        code = "PRECISION_EXCEEDED" if exc.code == "PRECISION_EXCEEDED" else "INVALID_VALUE"
        raise EIAAdapterError(code) from None
    except (InvalidOperation, ValueError):
        raise EIAAdapterError("INVALID_VALUE") from None


def parse_eia_data(
    payload: bytes | str | Mapping[str, object],
    *,
    dataset_id: str,
    mapping_version: str,
    ingest_time_ns: int,
    release_date: date | None = None,
    vintage_date: date | None = None,
    limit: int = MAX_RECORDS,
) -> tuple[EIAObservationV1, ...]:
    try:
        if isinstance(payload, bytes):
            if len(payload) > MAX_BYTES:
                raise EIAAdapterError("OVERSIZE")
            doc = json.loads(payload)
        elif isinstance(payload, str):
            if len(payload.encode()) > MAX_BYTES:
                raise EIAAdapterError("OVERSIZE")
            doc = json.loads(payload)
        else:
            doc = payload
    except EIAAdapterError:
        raise
    except Exception:
        raise EIAAdapterError("MALFORMED_RECORD") from None
    if (
        not isinstance(doc, Mapping)
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
        raise EIAAdapterError("INVALID_REQUEST")
    try:
        rows = doc["response"]["data"]
    except Exception:
        raise EIAAdapterError("SCHEMA_MISSING_COLUMN") from None
    if not isinstance(rows, list):
        raise EIAAdapterError("MALFORMED_RECORD")
    if len(rows) > limit:
        raise EIAAdapterError("CAP_EXCEEDED")
    output: list[EIAObservationV1] = []
    for row in rows:
        if not isinstance(row, Mapping) or "period" not in row or "value" not in row:
            raise EIAAdapterError("SCHEMA_MISSING_COLUMN")
        obs_date = _date(row["period"], required=True)
        assert obs_date is not None
        value = _value(row["value"])
        unit = row.get("units", "provider-defined")
        if type(unit) is not str or not unit:
            raise EIAAdapterError("MALFORMED_RECORD")
        series = row.get("series", row.get("series_id", ""))
        facets = ":".join(str(row.get(key, "")) for key in ("area", "product", "process", "series"))
        identity = f"{series}:{facets}:{obs_date.isoformat()}"
        canonical = json.dumps(dict(row), sort_keys=True, separators=(",", ":"), default=str)
        vintage = vintage_date or _date(row.get("vintage_date"))
        output.append(
            EIAObservationV1(
                PROVIDER_ID,
                dataset_id,
                identity,
                _ns(obs_date),
                ingest_time_ns,
                value,
                unit,
                mapping_version,
                hashlib.sha256(canonical.encode()).hexdigest(),
                vintage.isoformat() if vintage else None,
                obs_date,
                release_date or _date(row.get("release_date")),
                vintage,
            )
        )
    return tuple(output)


class EIAAdapter:
    def __init__(self, *, api_key: str | None, transport: Transport) -> None:
        self._api_key = api_key
        self._transport = transport

    @property
    def configured(self) -> bool:
        return self._api_key is not None

    def fetch_data(
        self,
        *,
        route: str,
        dataset_id: str,
        params: Mapping[str, str],
        mapping_version: str,
        ingest_time_ns: int,
        release_date: date | None = None,
        vintage_date: date | None = None,
        limit: int = MAX_RECORDS,
    ) -> tuple[EIAObservationV1, ...]:
        if not self.configured:
            raise EIAAdapterError("CREDENTIAL_UNAVAILABLE")
        if type(route) is not str or _ROUTE.fullmatch(route) is None or ".." in route:
            raise EIAAdapterError("INVALID_REQUEST")
        if (
            type(dataset_id) is not str
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
            raise EIAAdapterError("INVALID_REQUEST")
        request = {
            **dict(params),
            "api_key": self._api_key or "",
            "length": str(limit),
            "offset": "0",
            "sort[0][column]": "period",
            "sort[0][direction]": "asc",
        }
        try:
            response = self._transport.get(
                f"https://api.eia.gov/v2/{route}/data/",
                headers={},
                params=request,
                connect_timeout_s=3.0,
                read_timeout_s=5.0,
                total_timeout_s=10.0,
                allow_redirects=False,
            )
        except Exception:
            raise EIAAdapterError("HTTP_STATUS") from None
        if not 200 <= response.status_code < 300:
            raise EIAAdapterError("HTTP_STATUS")
        return parse_eia_data(
            response.body,
            dataset_id=dataset_id,
            mapping_version=mapping_version,
            ingest_time_ns=ingest_time_ns,
            release_date=release_date,
            vintage_date=vintage_date,
            limit=limit,
        )


def build_adapter(*, resolve_secret: Callable[[str], str], transport: Transport) -> EIAAdapter:
    try:
        secret: str | None = resolve_secret("eia_api_key")
        if type(secret) is not str or not secret:
            secret = None
    except Exception:
        secret = None
    return EIAAdapter(api_key=secret, transport=transport)
