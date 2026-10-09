"""Offline-first BEA data API adapter.

Official schema and response guide: https://apps.bea.gov/api/_pdf/bea_web_service_api_user_guide.pdf
Official key registration: https://apps.bea.gov/api/signup/
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

from leviathan_core.numeric import NumericError, exact_mul, parse_decimal

PROVIDER_ID = "bea"
CAPABILITIES = frozenset({"MACRO_SERIES"})
CREDENTIAL_NAMES = ("bea_api_key",)
MAX_RECORDS = 5000
MAX_BYTES = 2_000_000


class BEAAdapterError(ValueError):
    """Content-free provider error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class BEAObservationV1:
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


def _period(value: object) -> date:
    if type(value) is not str:
        raise BEAAdapterError("MALFORMED_RECORD")
    try:
        if re.fullmatch(r"\d{4}", value):
            return date(int(value), 1, 1)
        if re.fullmatch(r"\d{4}Q[1-4]", value):
            return date(int(value[:4]), (int(value[-1]) - 1) * 3 + 1, 1)
        if re.fullmatch(r"\d{4}M(0[1-9]|1[0-2])", value):
            return date(int(value[:4]), int(value[-2:]), 1)
        return date.fromisoformat(value)
    except ValueError:
        raise BEAAdapterError("MALFORMED_RECORD") from None


def _date(value: object) -> date | None:
    if value is None or value == "":
        return None
    if type(value) is not str:
        raise BEAAdapterError("MALFORMED_RECORD")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise BEAAdapterError("MALFORMED_RECORD") from None


def _ns(value: date) -> int:
    return (value.toordinal() - date(1970, 1, 1).toordinal()) * 86_400_000_000_000


def _value(raw: object, multiplier: object) -> Decimal | None:
    if raw in (None, "", "(D)", "(NA)", "(T)", "(L)", "(Z)", "--", "..."):
        return None
    try:
        if type(raw) is not str or not re.fullmatch(r"[+-]?[0-9,]+(?:\.[0-9]+)?", raw):
            raise ValueError
        if multiplier in (None, ""):
            exponent = 0
        elif type(multiplier) in (str, int) and re.fullmatch(r"-?[0-9]{1,2}", str(multiplier)):
            exponent = int(str(multiplier))
        else:
            raise ValueError
        unscaled = parse_decimal(raw.replace(",", ""), field="value")
        scale = parse_decimal(f"1e{exponent}", field="value")
        return exact_mul(unscaled, scale)
    except NumericError as exc:
        code = "PRECISION_EXCEEDED" if exc.code == "PRECISION_EXCEEDED" else "INVALID_VALUE"
        raise BEAAdapterError(code) from None
    except (InvalidOperation, ValueError):
        raise BEAAdapterError("INVALID_VALUE") from None


def parse_bea_data(
    payload: bytes | str | Mapping[str, object],
    *,
    dataset_id: str,
    mapping_version: str,
    ingest_time_ns: int,
    release_date: date | None = None,
    vintage_date: date | None = None,
    limit: int = MAX_RECORDS,
) -> tuple[BEAObservationV1, ...]:
    try:
        if isinstance(payload, bytes):
            if len(payload) > MAX_BYTES:
                raise BEAAdapterError("OVERSIZE")
            doc = json.loads(payload)
        elif isinstance(payload, str):
            if len(payload.encode()) > MAX_BYTES:
                raise BEAAdapterError("OVERSIZE")
            doc = json.loads(payload)
        else:
            doc = payload
    except BEAAdapterError:
        raise
    except Exception:
        raise BEAAdapterError("MALFORMED_RECORD") from None
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
        raise BEAAdapterError("INVALID_REQUEST")
    try:
        response = doc["BEAAPI"]["Results"]
        rows = response["Data"]
    except Exception:
        raise BEAAdapterError("SCHEMA_MISSING_COLUMN") from None
    if not isinstance(rows, list):
        raise BEAAdapterError("MALFORMED_RECORD")
    if len(rows) > limit:
        raise BEAAdapterError("CAP_EXCEEDED")
    output: list[BEAObservationV1] = []
    for row in rows:
        if not isinstance(row, Mapping) or not {"TimePeriod", "DataValue"} <= row.keys():
            raise BEAAdapterError("SCHEMA_MISSING_COLUMN")
        obs_date = _period(row["TimePeriod"])
        value = _value(row["DataValue"], row.get("UNIT_MULT", 0))
        unit = row.get("CL_UNIT", row.get("UNIT", "provider-defined"))
        if type(unit) is not str or not unit:
            raise BEAAdapterError("MALFORMED_RECORD")
        dimensions = ":".join(
            str(row.get(key, "")) for key in ("LineNumber", "SeriesCode", "TableName", "TimePeriod")
        )
        canonical = json.dumps(dict(row), sort_keys=True, separators=(",", ":"), default=str)
        output.append(
            BEAObservationV1(
                PROVIDER_ID,
                dataset_id,
                dimensions,
                _ns(obs_date),
                ingest_time_ns,
                value,
                unit,
                mapping_version,
                hashlib.sha256(canonical.encode()).hexdigest(),
                str(row["revision"]) if type(row.get("revision")) is str else None,
                obs_date,
                release_date or _date(row.get("release_date") or row.get("ReleaseDate")),
                vintage_date or _date(row.get("vintage_date")),
            )
        )
    return tuple(output)


class BEAAdapter:
    def __init__(self, *, api_key: str | None, transport: Transport) -> None:
        self._api_key = api_key
        self._transport = transport

    @property
    def configured(self) -> bool:
        return self._api_key is not None

    def fetch_data(
        self,
        *,
        dataset_id: str,
        params: Mapping[str, str],
        mapping_version: str,
        ingest_time_ns: int,
        release_date: date | None = None,
        vintage_date: date | None = None,
        limit: int = MAX_RECORDS,
    ) -> tuple[BEAObservationV1, ...]:
        if not self.configured:
            raise BEAAdapterError("CREDENTIAL_UNAVAILABLE")
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
            raise BEAAdapterError("INVALID_REQUEST")
        request = {
            "UserID": self._api_key or "",
            "method": "GetData",
            "ResultFormat": "JSON",
            "datasetname": dataset_id,
            **dict(params),
        }
        try:
            response = self._transport.get(
                "https://apps.bea.gov/api/data/",
                headers={},
                params=request,
                connect_timeout_s=3.0,
                read_timeout_s=5.0,
                total_timeout_s=10.0,
                allow_redirects=False,
            )
        except Exception:
            raise BEAAdapterError("HTTP_STATUS") from None
        if not 200 <= response.status_code < 300:
            raise BEAAdapterError("HTTP_STATUS")
        return parse_bea_data(
            response.body,
            dataset_id=dataset_id,
            mapping_version=mapping_version,
            ingest_time_ns=ingest_time_ns,
            release_date=release_date,
            vintage_date=vintage_date,
            limit=limit,
        )


def build_adapter(*, resolve_secret: Callable[[str], str], transport: Transport) -> BEAAdapter:
    try:
        secret: str | None = resolve_secret("bea_api_key")
        if type(secret) is not str or not secret:
            secret = None
    except Exception:
        secret = None
    return BEAAdapter(api_key=secret, transport=transport)
