"""Bounded, fixture-friendly adapters for primary public evidence sources."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from base64 import b64encode
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from decimal import Decimal, InvalidOperation
from email.utils import parsedate_to_datetime
from threading import BoundedSemaphore, Lock, Thread
from typing import Literal, Protocol, cast
from urllib.parse import urlencode

from .registry import PUBLIC_SOURCES

UTC = UTC
MAX_BODY_BYTES = 8_000_000
MAX_RETRIES = 2
_RETRY_DELAYS = (0.2, 0.5)
_ACTIVE_HTTP = BoundedSemaphore(8)
_SEC_REQUEST_LOCK = Lock()
_SEC_LAST_REQUEST = 0.0


class PublicSourceError(ValueError):
    """Sanitized error code; response bodies and credentials are never attached."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class PublicEvidenceV1:
    source_tier: int
    source_id: str
    record_id: str
    fetched_at: datetime
    as_of: datetime
    knowable_at: datetime | None
    factor_tags: tuple[str, ...]
    values: tuple[tuple[str, str], ...]
    redistribution: Literal[False] = False
    provider_session_id: str | None = None
    native_sequence: int | None = None
    event_at: datetime | None = None
    record_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if self.source_tier not in (1, 2, 3) or not self.source_id or not self.record_id:
            raise PublicSourceError("INVALID_PROVENANCE")
        stamps = tuple(
            value
            for value in (self.fetched_at, self.as_of, self.knowable_at, self.event_at)
            if value is not None
        )
        if any(value.tzinfo is None or value.utcoffset() is None for value in stamps):
            raise PublicSourceError("NAIVE_TIMESTAMP")
        if self.as_of > self.fetched_at or (
            self.knowable_at is not None and self.knowable_at > self.fetched_at
        ):
            raise PublicSourceError("FUTURE_DATED_EVIDENCE")
        if self.redistribution is not False:
            raise PublicSourceError("REDISTRIBUTION_FORBIDDEN")
        if self.native_sequence is not None and self.native_sequence < 0:
            raise PublicSourceError("INVALID_NATIVE_SEQUENCE")
        canonical = json.dumps(
            {
                "source_tier": self.source_tier,
                "source_id": self.source_id,
                "record_id": self.record_id,
                "fetched_at": self.fetched_at.isoformat(),
                "as_of": self.as_of.isoformat(),
                "knowable_at": None if self.knowable_at is None else self.knowable_at.isoformat(),
                "event_at": None if self.event_at is None else self.event_at.isoformat(),
                "factor_tags": self.factor_tags,
                "values": self.values,
                "redistribution": False,
                "provider_session_id": self.provider_session_id,
                "native_sequence": self.native_sequence,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        object.__setattr__(self, "record_digest", hashlib.sha256(canonical).hexdigest())


class HTTPResponse(Protocol):
    @property
    def status(self) -> int: ...

    @property
    def body(self) -> bytes: ...

    @property
    def headers(self) -> Mapping[str, str]: ...


class Transport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_s: float,
        max_bytes: int,
    ) -> HTTPResponse: ...


@dataclass(frozen=True, slots=True)
class _Response:
    status: int
    body: bytes
    headers: Mapping[str, str]


def _perform_http_attempt(
    request: urllib.request.Request,
    timeout_s: float,
    max_bytes: int,
    result: list[tuple[str, object]],
) -> None:
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            payload = response.read(max_bytes + 1)
            if len(payload) > max_bytes:
                result.append(("too_large", None))
            else:
                result.append(
                    ("ok", _Response(response.status, payload, dict(response.headers.items())))
                )
    except urllib.error.HTTPError as exc:
        result.append(("http", (exc.code, exc.headers.get("Retry-After"))))
    except Exception:
        result.append(("error", None))
    finally:
        _ACTIVE_HTTP.release()


class BoundedHTTPTransport:
    """Small stdlib transport with fixed time/body limits and bounded retries."""

    def __init__(self, *, max_retries: int = MAX_RETRIES) -> None:
        if type(max_retries) is not int or not 0 <= max_retries <= MAX_RETRIES:
            raise PublicSourceError("INVALID_HTTP_REQUEST")
        self._max_retries = max_retries

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_s: float = 8.0,
        max_bytes: int = MAX_BODY_BYTES,
    ) -> HTTPResponse:
        if (
            not url.startswith("https://")
            or not 0 < timeout_s <= 15
            or not 0 < max_bytes <= MAX_BODY_BYTES
        ):
            raise PublicSourceError("INVALID_HTTP_REQUEST")
        request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
        deadline = time.monotonic() + timeout_s
        for attempt in range(self._max_retries + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PublicSourceError("HTTP_DEADLINE_EXCEEDED")
            if not _ACTIVE_HTTP.acquire(timeout=remaining):
                raise PublicSourceError("HTTP_DEADLINE_EXCEEDED")
            result: list[tuple[str, object]] = []

            worker = Thread(
                target=_perform_http_attempt,
                args=(request, remaining, max_bytes, result),
                name="public-source-http",
                daemon=True,
            )
            worker.start()
            worker.join(timeout=max(0.0, remaining))
            if worker.is_alive():
                raise PublicSourceError("HTTP_DEADLINE_EXCEEDED")
            state, value = result[0] if result else ("error", None)
            if state == "ok":
                return cast(_Response, value)
            if state == "too_large":
                raise PublicSourceError("RESPONSE_TOO_LARGE")
            if state == "http":
                code: int
                retry_after_value: str | None
                code, retry_after_value = cast(tuple[int, str | None], value)
                if code not in (403, 429, 500, 502, 503, 504) or attempt == self._max_retries:
                    raise PublicSourceError("HTTP_STATUS") from None
                retry_after = _retry_after(retry_after_value)
                delay = retry_after if retry_after is not None else _RETRY_DELAYS[attempt]
            else:
                if attempt == self._max_retries:
                    raise PublicSourceError("HTTP_UNAVAILABLE") from None
                delay = _RETRY_DELAYS[attempt]
            remaining = deadline - time.monotonic()
            if delay >= remaining:
                raise PublicSourceError("HTTP_DEADLINE_EXCEEDED")
            time.sleep(delay)
        raise PublicSourceError("HTTP_UNAVAILABLE")


def _retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
            return max(0.0, (parsed - datetime.now(UTC)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return None


def _stamp(value: str | date | datetime) -> datetime:
    if isinstance(value, datetime):
        result = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    elif isinstance(value, date):
        result = datetime.combine(value, datetime.min.time(), UTC)
    else:
        raw = value.strip()
        try:
            result = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            try:
                result = datetime.combine(date.fromisoformat(raw[:10]), datetime.min.time(), UTC)
            except ValueError:
                raise PublicSourceError("INVALID_SOURCE_TIMESTAMP") from None
        result = result.replace(tzinfo=UTC) if result.tzinfo is None else result.astimezone(UTC)
    return result


def _source_stamp(value: object, fallback: datetime) -> datetime:
    if value is None:
        return _stamp(fallback)
    if isinstance(value, bool):
        raise PublicSourceError("INVALID_SOURCE_TIMESTAMP")
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.strip().isdigit()):
        try:
            epoch = float(value)
            scale = 1000.0 if abs(epoch) >= 100_000_000_000 else 1.0
            return datetime.fromtimestamp(epoch / scale, UTC)
        except (ValueError, OverflowError, OSError):
            raise PublicSourceError("INVALID_SOURCE_TIMESTAMP") from None
    if isinstance(value, (str, date, datetime)):
        return _stamp(value)
    raise PublicSourceError("INVALID_SOURCE_TIMESTAMP")


def _evidence(
    source_id: str,
    record_id: str,
    fetched_at: datetime,
    as_of: str | date | datetime,
    knowable_at: str | date | datetime | None,
    values: Mapping[str, object],
    *,
    provider_session_id: str | None = None,
    native_sequence: int | None = None,
    event_at: str | date | datetime | None = None,
) -> PublicEvidenceV1:
    entry = next((item for item in PUBLIC_SOURCES if item.source_id == source_id), None)
    if entry is None:
        raise PublicSourceError("UNKNOWN_SOURCE")
    fetch = _stamp(fetched_at)

    def value_text(value: object) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, (date, datetime)):
            return value.isoformat()
        if isinstance(value, (dict, list, tuple)):
            return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        return str(value)

    return PublicEvidenceV1(
        source_tier=entry.tier,
        source_id=source_id,
        record_id=record_id,
        fetched_at=fetch,
        as_of=_stamp(as_of),
        knowable_at=None if knowable_at is None else _stamp(knowable_at),
        factor_tags=entry.factor_tags,
        values=tuple(
            sorted(
                (
                    str(key),
                    value_text(value),
                )
                for key, value in values.items()
            )
        ),
        provider_session_id=provider_session_id,
        native_sequence=native_sequence,
        event_at=None if event_at is None else _stamp(event_at),
    )


def parse_public_json_rows(
    payload: bytes | str,
    *,
    source_id: str,
    fetched_at: datetime,
    event_fields: tuple[str, ...],
    knowable_fields: tuple[str, ...],
    key_fields: tuple[str, ...],
    event_at_fields: tuple[str, ...] = (),
    max_records: int = 5000,
) -> tuple[PublicEvidenceV1, ...]:
    """Normalize a bounded list response while retaining source and availability times."""
    if not 1 <= max_records <= 5000:
        raise PublicSourceError("INVALID_REQUEST")
    try:
        decoded = json.loads(payload)
    except (TypeError, ValueError):
        raise PublicSourceError("MALFORMED_JSON") from None
    rows = decoded if isinstance(decoded, list) else None
    if isinstance(decoded, dict):
        candidate = decoded.get("data", decoded.get("results"))
        rows = candidate if isinstance(candidate, list) else [decoded]
    if not isinstance(rows, list) or len(rows) > max_records:
        raise PublicSourceError(
            "RECORD_LIMIT_EXCEEDED" if isinstance(rows, list) else "MALFORMED_RECORD"
        )
    if any(not isinstance(row, dict) for row in rows):
        raise PublicSourceError("MALFORMED_RECORD")
    output: list[PublicEvidenceV1] = []

    def pick(source: Mapping[str, object], names: tuple[str, ...]) -> object | None:
        return next(
            (
                source[name.casefold()]
                for name in names
                if name.casefold() in source and source[name.casefold()] not in (None, "")
            ),
            None,
        )

    for index, row in enumerate(rows):
        normalized = {str(key).casefold(): value for key, value in row.items()}
        event_value = pick(normalized, event_fields)
        if event_value is None and not event_fields:
            event_value = fetched_at
        if event_value is None:
            raise PublicSourceError("SOURCE_EVENT_TIME_MISSING")
        availability_value = pick(normalized, knowable_fields)
        key_value = pick(normalized, key_fields)
        sequence_value = pick(normalized, ("sequence", "sequenceNumber", "nativeSequence", "seq"))
        try:
            sequence = None if sequence_value is None else int(str(sequence_value))
        except (ValueError, TypeError):
            raise PublicSourceError("INVALID_NATIVE_SEQUENCE") from None
        session_value = pick(normalized, ("sessionId", "providerSessionId", "session"))
        event_at_value = pick(normalized, event_at_fields)
        key = str(key_value) if key_value is not None else f"row:{index}"
        output.append(
            _evidence(
                source_id,
                key,
                fetched_at,
                _source_stamp(event_value, fetched_at),
                _source_stamp(availability_value, fetched_at),
                row,
                provider_session_id=None if session_value is None else str(session_value),
                native_sequence=sequence,
                event_at=None
                if event_at_value is None
                else _source_stamp(event_at_value, fetched_at),
            )
        )
    return tuple(output)


def parse_coinbase_derivatives_open_interest(
    payload: bytes | str, *, fetched_at: datetime, max_records: int = 500
) -> tuple[PublicEvidenceV1, ...]:
    """Normalize Coinbase's public US futures catalog OI using first-observed time."""
    if not 1 <= max_records <= 500:
        raise PublicSourceError("INVALID_REQUEST")
    try:
        decoded = json.loads(payload)
    except (TypeError, ValueError):
        raise PublicSourceError("MALFORMED_JSON") from None
    if not isinstance(decoded, dict):
        raise PublicSourceError("MALFORMED_RECORD")
    rows = decoded.get("products")
    if not isinstance(rows, list) or len(rows) > max_records:
        raise PublicSourceError(
            "RECORD_LIMIT_EXCEEDED" if isinstance(rows, list) else "MALFORMED_RECORD"
        )
    fetch = _stamp(fetched_at)
    output: list[PublicEvidenceV1] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise PublicSourceError("MALFORMED_RECORD")
        product_id = row.get("product_id")
        if not isinstance(product_id, str) or not product_id.strip():
            raise PublicSourceError("SCHEMA_MISSING_COLUMN")
        if product_id in seen:
            raise PublicSourceError("DUPLICATE_RECORD")
        seen.add(product_id)
        if row.get("product_type") != "FUTURE":
            raise PublicSourceError("SCHEMA_UNEXPECTED_PRODUCT_TYPE")
        details = row.get("future_product_details")
        if not isinstance(details, dict):
            raise PublicSourceError("SCHEMA_MISSING_COLUMN")
        perpetual_details = details.get("perpetual_details")
        open_interest = None
        if isinstance(perpetual_details, dict) and "open_interest" in perpetual_details:
            open_interest = perpetual_details["open_interest"]
        if open_interest is None:
            open_interest = details.get("open_interest")
        if not isinstance(open_interest, (str, int, float)) or isinstance(open_interest, bool):
            raise PublicSourceError("SCHEMA_MISSING_COLUMN")
        try:
            normalized_interest = Decimal(str(open_interest))
        except (InvalidOperation, ValueError):
            raise PublicSourceError("SCHEMA_INVALID_VALUE") from None
        if not normalized_interest.is_finite() or normalized_interest < 0:
            raise PublicSourceError("SCHEMA_INVALID_VALUE")
        values: dict[str, object] = {
            "product_id": product_id,
            "product_type": "FUTURE",
            "open_interest": str(open_interest),
            "open_interest_scope": "contract_units",
        }
        for key in ("contract_expiry", "contract_code", "contract_size", "display_name"):
            value = details.get(key, row.get(key))
            if value is not None:
                values[key] = value
        output.append(
            _evidence(
                "coinbase.derivatives_us",
                f"{product_id}:{fetch.isoformat()}",
                fetch,
                fetch,
                fetch,
                values,
            )
        )
    return tuple(output)


def parse_house_ptr_index(
    payload: bytes, *, filing_year: int, fetched_at: datetime, max_records: int = 5000
) -> tuple[PublicEvidenceV1, ...]:
    """Read the official House Clerk annual ZIP and emit indexed PTR filing evidence."""
    if (
        len(payload) > MAX_BODY_BYTES
        or not 2008 <= filing_year <= fetched_at.year
        or not 1 <= max_records <= 5000
    ):
        raise PublicSourceError("INVALID_REQUEST")
    try:
        with zipfile.ZipFile(__import__("io").BytesIO(payload)) as archive:
            names = [name for name in archive.namelist() if name.lower().endswith(".xml")]
            if not names or archive.getinfo(names[0]).file_size > MAX_BODY_BYTES:
                raise PublicSourceError("INVALID_HOUSE_ARCHIVE")
            root = ET.fromstring(archive.read(names[0]))
    except PublicSourceError:
        raise
    except (zipfile.BadZipFile, ET.ParseError, OSError, KeyError):
        raise PublicSourceError("INVALID_HOUSE_ARCHIVE") from None
    records: list[PublicEvidenceV1] = []
    for node in root.iter():
        row = {child.tag.rsplit("}", 1)[-1]: (child.text or "").strip() for child in node}
        filing_type = row.get("FilingType", "").upper()
        if filing_type not in {"P", "PTR", "PERIODIC TRANSACTION REPORT"}:
            continue
        if len(records) >= max_records:
            raise PublicSourceError("RECORD_LIMIT_EXCEEDED")
        filed = row.get("FilingDate") or row.get("DateReceived")
        doc_id = row.get("DocID") or row.get("DocumentID")
        if not filed or not doc_id:
            raise PublicSourceError("SCHEMA_MISSING_COLUMN")
        records.append(_evidence("house.ptr.bulk", doc_id, fetched_at, filed, fetched_at, row))
    return tuple(records)


def parse_sec_submissions(
    payload: bytes | str,
    *,
    cik: str,
    fetched_at: datetime,
    forms: tuple[str, ...] = ("13F-HR", "SC 13D", "SC 13D/A", "SC 13G", "SC 13G/A"),
    max_records: int = 5000,
) -> tuple[PublicEvidenceV1, ...]:
    """Normalize SEC company submissions into filing-time evidence, not period-time evidence."""
    if not re.fullmatch(r"\d{1,10}", cik) or not 1 <= max_records <= 5000:
        raise PublicSourceError("INVALID_REQUEST")
    try:
        document = json.loads(payload)
        recent = document["filings"]["recent"]
    except (TypeError, ValueError, KeyError):
        raise PublicSourceError("MALFORMED_JSON") from None
    if not isinstance(recent, dict):
        raise PublicSourceError("MALFORMED_RECORD")
    selected = {form.upper() for form in forms}
    form_rows = recent.get("form", [])
    fields = (
        "accessionNumber",
        "filingDate",
        "acceptanceDateTime",
        "reportDate",
        "primaryDocument",
    )
    if not isinstance(form_rows, list) or len(form_rows) > max_records:
        raise PublicSourceError("RECORD_LIMIT_EXCEEDED")
    if any(
        not isinstance(recent.get(name, []), list) or len(recent.get(name, [])) != len(form_rows)
        for name in fields
    ):
        raise PublicSourceError("SCHEMA_MISSING_COLUMN")
    rows: list[PublicEvidenceV1] = []
    for index, form in enumerate(form_rows):
        if str(form).upper() not in selected:
            continue
        row = {name: recent[name][index] for name in fields}
        acceptance = row["acceptanceDateTime"] or row["filingDate"]
        if not row["accessionNumber"] or not acceptance:
            raise PublicSourceError("SCHEMA_MISSING_COLUMN")
        source_id = "sec.edgar.13f" if str(form).upper().startswith("13F") else "sec.edgar.13dg"
        rows.append(
            _evidence(
                source_id,
                f"{cik}:{row['accessionNumber']}",
                fetched_at,
                row["reportDate"] or row["filingDate"],
                acceptance,
                {"cik": cik, "form": form, **row},
            )
        )
    return tuple(rows)


def parse_sec_form4(
    xml_payload: bytes | str, *, cik: str, accession: str, filed_at: datetime, fetched_at: datetime
) -> tuple[PublicEvidenceV1, ...]:
    if len(xml_payload) > MAX_BODY_BYTES or not re.fullmatch(r"\d{1,10}", cik):
        raise PublicSourceError("INVALID_REQUEST")
    try:
        root = ET.fromstring(xml_payload)
    except (ET.ParseError, TypeError):
        raise PublicSourceError("MALFORMED_XML") from None
    filing_time = _stamp(filed_at)
    items: list[PublicEvidenceV1] = []
    for index, transaction in enumerate(
        root.findall(".//nonDerivativeTransaction") + root.findall(".//derivativeTransaction")
    ):
        transaction_date = _xml_field(transaction, "transactionDate")
        if not transaction_date:
            raise PublicSourceError("SCHEMA_MISSING_COLUMN")
        record_date = _stamp(transaction_date)
        code = _xml_field(transaction, "transactionCode")
        shares = _xml_field(transaction, "transactionShares")
        price = _xml_field(transaction, "transactionPricePerShare")
        security = _xml_field(transaction, "securityTitle")
        items.append(
            _evidence(
                "sec.edgar.form4",
                f"{cik}:{accession}:{index}",
                fetched_at,
                record_date,
                filing_time,
                {
                    "cik": cik,
                    "accession": accession,
                    "transaction_date": transaction_date,
                    "transaction_code": code,
                    "shares": shares,
                    "price": price,
                    "security": security,
                },
            )
        )
    return tuple(items)


def _xml_field(transaction: ET.Element, name: str) -> str:
    node = transaction.find(name)
    if node is None:
        return ""
    value = node.find("value")
    text = node.text if value is None else value.text
    return "" if text is None else text.strip()


def parse_finra_regsho(
    payload: bytes | str, *, trade_date: date, fetched_at: datetime
) -> tuple[PublicEvidenceV1, ...]:
    text = payload.decode("utf-8-sig") if isinstance(payload, bytes) else payload
    reader = csv.DictReader(text.splitlines(), delimiter="|")
    required = {"Date", "Symbol", "ShortVolume", "ShortExemptVolume", "TotalVolume"}
    if not reader.fieldnames or not required <= set(reader.fieldnames):
        raise PublicSourceError("SCHEMA_MISSING_COLUMN")
    rows: list[PublicEvidenceV1] = []
    for row in reader:
        row_date = row["Date"].strip()
        try:
            parsed_date = date.fromisoformat(row_date)
            short, exempt, total = (
                int(row[name]) for name in ("ShortVolume", "ShortExemptVolume", "TotalVolume")
            )
        except (ValueError, TypeError, KeyError):
            raise PublicSourceError("MALFORMED_RECORD") from None
        symbol = row["Symbol"].strip()
        if parsed_date != trade_date or min(short, exempt, total) < 0 or not symbol:
            raise PublicSourceError("INVALID_RECORD")
        rows.append(
            _evidence(
                "finra.regsho.daily",
                f"{row_date}:{symbol}",
                fetched_at,
                parsed_date,
                _stamp(fetched_at),
                {
                    "symbol": symbol,
                    "short_volume": short,
                    "short_exempt_volume": exempt,
                    "total_volume": total,
                },
            )
        )
    return tuple(rows)


def parse_finra_weekly(
    payload: bytes | str, *, fetched_at: datetime
) -> tuple[PublicEvidenceV1, ...]:
    try:
        rows = json.loads(payload)
    except (TypeError, ValueError):
        raise PublicSourceError("MALFORMED_JSON") from None
    if not isinstance(rows, list):
        raise PublicSourceError("MALFORMED_RECORD")
    output: list[PublicEvidenceV1] = []
    for row in rows:
        if not isinstance(row, dict):
            raise PublicSourceError("MALFORMED_RECORD")
        folded = {str(key).lower(): value for key, value in row.items()}
        try:
            symbol = str(folded["issuesymbolidentifier"])
            week = date.fromisoformat(str(folded["weekstartdate"]))
            initial_publication_raw = str(folded["initialpublisheddate"])
            initial_publication = _stamp(initial_publication_raw)
            revision_value = folded.get("lastupdatedate")
            revision_at = _stamp(str(revision_value)) if revision_value else None
            shares = int(folded["totalweeklysharequantity"])
            trades = int(folded.get("totalweeklytradecount", folded.get("totaltradecountsum", 0)))
        except (KeyError, ValueError, TypeError):
            raise PublicSourceError("SCHEMA_MISSING_COLUMN") from None
        if min(shares, trades) < 0:
            raise PublicSourceError("INVALID_RECORD")
        output.append(
            _evidence(
                "finra.otc.weekly",
                f"{week}:{symbol}:{folded.get('summarytypecode', '')}:"
                f"{(revision_at or initial_publication).isoformat()}",
                fetched_at,
                week,
                revision_at or initial_publication,
                {
                    "symbol": symbol,
                    "week_start": week,
                    "shares": shares,
                    "trades": trades,
                    "initial_published_date": initial_publication_raw,
                    "last_update_date": None if revision_value is None else str(revision_value),
                    "report_type": folded.get("summarytypecode", folded.get("reporttype", "")),
                },
            )
        )
    return tuple(output)


def parse_cftc_cot(payload: bytes | str, *, fetched_at: datetime) -> tuple[PublicEvidenceV1, ...]:
    try:
        rows = json.loads(payload)
    except (TypeError, ValueError):
        raise PublicSourceError("MALFORMED_JSON") from None
    if not isinstance(rows, list):
        raise PublicSourceError("MALFORMED_RECORD")
    output: list[PublicEvidenceV1] = []
    for row in rows:
        if not isinstance(row, dict):
            raise PublicSourceError("MALFORMED_RECORD")
        try:
            report_date = date.fromisoformat(str(row["report_date_as_yyyy_mm_dd"]))
            # PRE rows do not include a publication timestamp. The safe default is
            # the first local fetch time; historical Tuesday positions are never
            # backdated into an earlier replay.
            publication = _stamp(fetched_at)
            market = str(row["market_and_exchange_names"])
            code = str(row["cftc_contract_market_code"])
        except (KeyError, ValueError, TypeError):
            raise PublicSourceError("SCHEMA_MISSING_COLUMN") from None
        output.append(
            _evidence(
                "cftc.cot.legacy",
                f"{code}:{report_date}",
                fetched_at,
                report_date,
                publication,
                {
                    "market": market,
                    "contract_code": code,
                    "report_date": report_date,
                    "publication_date": publication,
                    "open_interest": row.get("open_interest_all"),
                    "commercial_long": row.get("comm_positions_long_all"),
                    "commercial_short": row.get("comm_positions_short_all"),
                },
            )
        )
    return tuple(output)


def parse_treasury_curve(
    payload: bytes | str, *, fetched_at: datetime
) -> tuple[PublicEvidenceV1, ...]:
    try:
        root = ET.fromstring(payload)
    except (ET.ParseError, TypeError):
        raise PublicSourceError("MALFORMED_XML") from None
    entries: list[PublicEvidenceV1] = []
    for node in root.iter():
        if not node.tag.lower().endswith("entry"):
            continue
        props = {
            child.tag.rsplit("}", 1)[-1]: (child.text or "").strip()
            for child in node.iter()
            if child is not node
        }
        raw_date = props.get("NEW_DATE") or props.get("record_date")
        if not raw_date:
            raise PublicSourceError("SCHEMA_MISSING_COLUMN")
        try:
            as_of = date.fromisoformat(raw_date)
        except ValueError:
            raise PublicSourceError("INVALID_SOURCE_TIMESTAMP") from None
        values = {
            key: value for key, value in props.items() if key not in {"NEW_DATE", "record_date"}
        }
        entries.append(
            _evidence(
                "treasury.yield_curve",
                f"{as_of.isoformat()}:par-yield",
                fetched_at,
                as_of,
                _stamp(fetched_at),
                {"observation_date": as_of, **values},
            )
        )
    return tuple(entries)


class PublicSourcesClient:
    """Small direct adapter client; requests are capped and all inputs are explicit."""

    def __init__(
        self,
        *,
        transport: Transport | None = None,
        sec_user_agent: str,
        finra_credentials_resolver: Callable[[], tuple[str, str]] | None = None,
        sec_rate_per_second: int = 5,
        http_timeout_seconds: int = 8,
        http_max_retries: int = 2,
        coinbase_derivatives_enabled: bool = False,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not sec_user_agent.strip() or "@" not in sec_user_agent:
            raise PublicSourceError("SEC_USER_AGENT_REQUIRED")
        if type(sec_rate_per_second) is not int or not 1 <= sec_rate_per_second <= 10:
            raise PublicSourceError("SEC_RATE_MUST_BE_TEN_PER_SECOND")
        if not 1 <= http_timeout_seconds <= 15 or not 0 <= http_max_retries <= 2:
            raise PublicSourceError("INVALID_HTTP_REQUEST")
        if type(coinbase_derivatives_enabled) is not bool:
            raise PublicSourceError("INVALID_SOURCE_ENABLEMENT")
        self._transport = transport or BoundedHTTPTransport(max_retries=http_max_retries)
        self._timeout_s = float(http_timeout_seconds)
        self._user_agent = sec_user_agent.strip()
        self._finra_token: str | None = None
        self._finra_credentials_resolver = finra_credentials_resolver
        self._finra_token_deadline = 0.0
        self._sec_spacing = 1 / sec_rate_per_second
        self._coinbase_derivatives_enabled = coinbase_derivatives_enabled
        self._now = now or (lambda: datetime.now(UTC))

    @classmethod
    def from_vault(
        cls,
        *,
        sec_user_agent: str,
        vault_ref_resolver: Callable[[str, str], str] | None,
        finra_enabled: bool,
        sec_rate_per_second: int = 5,
        http_timeout_seconds: int = 8,
        http_max_retries: int = 2,
        coinbase_derivatives_enabled: bool = False,
        transport: Transport | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> PublicSourcesClient:
        """Build a client from project vault refs; missing credentials fail closed."""
        resolver: Callable[[], tuple[str, str]] | None = None
        if finra_enabled:
            if vault_ref_resolver is None:
                raise PublicSourceError("FINRA_CREDENTIAL_REQUIRED")

            def resolve_credentials() -> tuple[str, str]:
                values: list[str] = []
                for name in ("FINRA_CLIENT_ID", "FINRA_CLIENT_SECRET"):
                    reference = f"vault://leviathan-ai/development/FINRA/{name}"
                    try:
                        value = vault_ref_resolver(reference, name)
                    except Exception:
                        raise PublicSourceError("FINRA_CREDENTIAL_REQUIRED") from None
                    if type(value) is not str or not value:
                        raise PublicSourceError("FINRA_CREDENTIAL_REQUIRED")
                    values.append(value)
                return values[0], values[1]

            checked = resolve_credentials()
            del checked
            resolver = resolve_credentials
        return cls(
            transport=transport,
            sec_user_agent=sec_user_agent,
            finra_credentials_resolver=resolver,
            sec_rate_per_second=sec_rate_per_second,
            http_timeout_seconds=http_timeout_seconds,
            http_max_retries=http_max_retries,
            coinbase_derivatives_enabled=coinbase_derivatives_enabled,
            now=now,
        )

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        max_bytes: int = MAX_BODY_BYTES,
    ) -> bytes:
        response = self._transport.request(
            method,
            url,
            headers=headers or {},
            body=body,
            timeout_s=self._timeout_s,
            max_bytes=max_bytes,
        )
        if not 200 <= response.status < 300:
            raise PublicSourceError("HTTP_STATUS")
        return response.body

    def _sec_request(self, url: str, accept: str) -> bytes:
        """Serialize all SEC requests process-wide and enforce the configured interval."""
        global _SEC_LAST_REQUEST
        with _SEC_REQUEST_LOCK:
            wait = self._sec_spacing - (time.monotonic() - _SEC_LAST_REQUEST)
            if wait > 0:
                time.sleep(wait)
            _SEC_LAST_REQUEST = time.monotonic()
            return self._request(
                "GET",
                url,
                headers={"User-Agent": self._user_agent, "Accept": accept},
            )

    def fetch_sec_form4(
        self, *, xml_url: str, cik: str, accession: str, filed_at: datetime
    ) -> tuple[PublicEvidenceV1, ...]:
        if not xml_url.startswith("https://www.sec.gov/Archives/edgar/data/"):
            raise PublicSourceError("URL_NOT_ALLOWLISTED")
        body = self._sec_request(xml_url, "application/xml,text/xml")
        return parse_sec_form4(
            body, cik=cik, accession=accession, filed_at=filed_at, fetched_at=self._now()
        )

    def fetch_finra_regsho(self, *, market: str, trade_date: date) -> tuple[PublicEvidenceV1, ...]:
        if market not in {"CNMS", "FNSQ", "FNRA", "FNYX", "ORF"}:
            raise PublicSourceError("INVALID_MARKET")
        url = f"https://cdn.finra.org/equity/regsho/daily/{market}shvol{trade_date:%Y%m%d}.txt"
        return parse_finra_regsho(
            self._request("GET", url), trade_date=trade_date, fetched_at=self._now()
        )

    def fetch_finra_weekly(
        self, *, report_type: str, week_start: date, limit: int = 5000
    ) -> tuple[PublicEvidenceV1, ...]:
        if report_type not in {"ATS_W_SMBL", "OTC_W_SMBL"} or not 1 <= limit <= 5000:
            raise PublicSourceError("INVALID_REQUEST")
        self._finra_token = self._require_finra_token()
        payload = json.dumps(
            {
                "compareFilters": [
                    {
                        "compareType": "EQUAL",
                        "fieldName": "summaryTypeCode",
                        "fieldValue": report_type,
                    },
                    {
                        "compareType": "EQUAL",
                        "fieldName": "weekStartDate",
                        "fieldValue": week_start.isoformat(),
                    },
                ],
                "limit": limit,
            }
        ).encode()
        body = self._request(
            "POST",
            "https://api.finra.org/data/group/otcMarket/name/weeklySummary",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {self._finra_token}",
            },
            body=payload,
        )
        return parse_finra_weekly(body, fetched_at=self._now())

    def _finra_access_token(self) -> str:
        if self._finra_credentials_resolver is None:
            raise PublicSourceError("FINRA_CREDENTIAL_REQUIRED")
        client_id, client_secret = self._finra_credentials_resolver()
        basic = b64encode(f"{client_id}:{client_secret}".encode()).decode()
        payload = self._request(
            "POST",
            "https://ews.fip.finra.org/fip/rest/ews/oauth2/access_token?grant_type=client_credentials",
            headers={"Authorization": f"Basic {basic}", "Accept": "application/json"},
            body=b"",
        )
        try:
            token_doc = json.loads(payload)
            token = token_doc["access_token"]
            expires_in = int(token_doc.get("expires_in", 1800))
        except (TypeError, ValueError, KeyError):
            raise PublicSourceError("FINRA_AUTH_FAILED") from None
        if not isinstance(token, str) or not token or expires_in < 60:
            raise PublicSourceError("FINRA_AUTH_FAILED")
        self._finra_token_deadline = time.monotonic() + min(expires_in, 1800) - 30
        return token

    def _require_finra_token(self) -> str:
        if self._finra_token is None or time.monotonic() >= self._finra_token_deadline:
            self._finra_token = self._finra_access_token()
        return self._finra_token

    def fetch_finra_short_interest(
        self, *, settlement_date: date, limit: int = 5000
    ) -> tuple[PublicEvidenceV1, ...]:
        if not 1 <= limit <= 5000:
            raise PublicSourceError("INVALID_REQUEST")
        params = urlencode(
            {
                "limit": str(limit),
                "compareFilters": json.dumps(
                    [
                        {
                            "compareType": "EQUAL",
                            "fieldName": "settlementDate",
                            "fieldValue": settlement_date.isoformat(),
                        }
                    ],
                    separators=(",", ":"),
                ),
            }
        )
        payload = self._request(
            "GET",
            "https://api.finra.org/data/group/otcMarket/name/consolidatedShortInterest?" + params,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._require_finra_token()}",
            },
        )
        return parse_public_json_rows(
            payload,
            source_id="finra.short_interest",
            fetched_at=self._now(),
            event_fields=("settlementDate",),
            knowable_fields=("publicationDate", "publishedDate", "publicationTimestamp"),
            key_fields=("symbolCode", "issueSymbolIdentifier"),
            max_records=limit,
        )

    def fetch_nyfed_markets(
        self, *, endpoint_path: str, limit: int = 5000
    ) -> tuple[PublicEvidenceV1, ...]:
        allowed_prefixes = ("/api/rates/", "/api/rp/reverserepo/", "/api/pd/")
        if (
            not endpoint_path.startswith(allowed_prefixes)
            or ".." in endpoint_path
            or not 1 <= limit <= 5000
        ):
            raise PublicSourceError("INVALID_REQUEST")
        url = "https://markets.newyorkfed.org" + endpoint_path
        payload = self._request("GET", url, headers={"Accept": "application/json"})
        return parse_public_json_rows(
            payload,
            source_id="nyfed.markets",
            fetched_at=self._now(),
            event_fields=("effectiveDate", "operationDate", "date", "asOfDate"),
            knowable_fields=("publicationDate", "publishedAt", "releaseDate"),
            key_fields=("rateType", "operationId", "seriesId", "date"),
            max_records=limit,
        )

    def fetch_treasury_auctions(
        self, *, start_date: date, end_date: date, limit: int = 5000
    ) -> tuple[PublicEvidenceV1, ...]:
        if start_date > end_date or not 1 <= limit <= 5000:
            raise PublicSourceError("INVALID_REQUEST")
        query = urlencode(
            {
                "format": "json",
                "filter": (
                    f"auction_date:gte:{start_date.isoformat()},"
                    f"auction_date:lte:{end_date.isoformat()}"
                ),
                "sort": "-auction_date",
                "page[number]": "1",
                "page[size]": str(limit),
            }
        )
        payload = self._request(
            "GET",
            "https://api.fiscaldata.treasury.gov/services/api/fiscal_service/v1/accounting/od/auctions_query?"
            + query,
            headers={"Accept": "application/json"},
        )
        return parse_public_json_rows(
            payload,
            source_id="treasurydirect.auctions",
            fetched_at=self._now(),
            event_fields=("auction_date", "auctionDate"),
            knowable_fields=("announcement_date", "announcementDate", "publication_date"),
            key_fields=("cusip", "auction_date", "security_type"),
            max_records=limit,
        )

    def fetch_sec_submissions(
        self,
        *,
        submissions_url: str,
        cik: str,
        forms: tuple[str, ...] = ("13F-HR", "SC 13D", "SC 13D/A", "SC 13G", "SC 13G/A"),
    ) -> tuple[PublicEvidenceV1, ...]:
        if not submissions_url.startswith(
            "https://data.sec.gov/submissions/CIK"
        ) or not re.fullmatch(r"\d{1,10}", cik):
            raise PublicSourceError("URL_NOT_ALLOWLISTED")
        payload = self._sec_request(submissions_url, "application/json")
        return parse_sec_submissions(payload, cik=cik, fetched_at=self._now(), forms=forms)

    def fetch_house_ptr_index(self, *, filing_year: int) -> tuple[PublicEvidenceV1, ...]:
        if filing_year < 2008 or filing_year > self._now().year:
            raise PublicSourceError("INVALID_REQUEST")
        payload = self._request(
            "GET",
            f"https://disclosures-clerk.house.gov/public_disc/financial-pdfs/{filing_year}FD.ZIP",
            headers={"User-Agent": self._user_agent, "Accept": "application/zip"},
        )
        return parse_house_ptr_index(payload, filing_year=filing_year, fetched_at=self._now())

    def fetch_coinbase_derivatives_funding(
        self, *, symbol: str, trading_session_date: date
    ) -> tuple[PublicEvidenceV1, ...]:
        """Fetch unauthenticated CDE historical funding; no account/position endpoints."""
        if not self._coinbase_derivatives_enabled:
            raise PublicSourceError("COINBASE_DERIVATIVES_DISABLED")
        if not re.fullmatch(r"[A-Z0-9]{2,16}", symbol):
            raise PublicSourceError("INVALID_REQUEST")
        query = urlencode(
            {"symbol": symbol, "trading_session_date": trading_session_date.isoformat()}
        )
        payload = self._request(
            "GET",
            "https://api.exchange.fairx.net/rest/funding-rate?" + query,
            headers={"Accept": "application/json"},
        )
        return parse_public_json_rows(
            payload,
            source_id="coinbase.derivatives_us",
            fetched_at=self._now(),
            event_fields=("event_time",),
            knowable_fields=(),
            key_fields=("symbol", "event_time"),
            max_records=5000,
        )

    def fetch_coinbase_derivatives_instruments(
        self, *, product_codes: tuple[str, ...] = ("BIP", "BIT", "ETP", "ETH")
    ) -> tuple[PublicEvidenceV1, ...]:
        """Fetch bounded public CDE instrument metadata; firm positions are not queried."""
        if not self._coinbase_derivatives_enabled:
            raise PublicSourceError("COINBASE_DERIVATIVES_DISABLED")
        if (
            type(product_codes) is not tuple
            or not 1 <= len(product_codes) <= 20
            or any(not re.fullmatch(r"[A-Z0-9]{1,12}", code) for code in product_codes)
        ):
            raise PublicSourceError("INVALID_REQUEST")
        payload = self._request(
            "POST",
            "https://api.exchange.fairx.net/rest/instruments",
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            body=json.dumps({"product_codes": list(product_codes)}, separators=(",", ":")).encode(),
        )
        return parse_public_json_rows(
            payload,
            source_id="coinbase.derivatives_us",
            fetched_at=self._now(),
            event_fields=(),
            knowable_fields=(),
            key_fields=("symbol", "product_code"),
            max_records=500,
        )

    def fetch_coinbase_derivatives_open_interest(self) -> tuple[PublicEvidenceV1, ...]:
        """Fetch US futures OI from Coinbase's public Advanced Trade product catalog."""
        if not self._coinbase_derivatives_enabled:
            raise PublicSourceError("COINBASE_DERIVATIVES_DISABLED")
        records: list[PublicEvidenceV1] = []
        cursor: str | None = None
        for page_number in range(5):
            query: dict[str, str] = {
                "product_type": "FUTURE",
                "user_country_code": "US",
                "get_all_products": "true",
                "limit": "100",
            }
            if cursor is not None:
                query["cursor"] = cursor
            payload = self._request(
                "GET",
                "https://api.coinbase.com/api/v3/brokerage/market/products?"
                + urlencode(query),
                headers={"Accept": "application/json"},
            )
            fetched_at = self._now()
            records.extend(
                parse_coinbase_derivatives_open_interest(payload, fetched_at=fetched_at)
            )
            if len(records) > 500:
                raise PublicSourceError("RECORD_LIMIT_EXCEEDED")
            try:
                decoded = json.loads(payload)
            except (TypeError, ValueError):
                raise PublicSourceError("MALFORMED_JSON") from None
            pagination = decoded.get("pagination") if isinstance(decoded, dict) else None
            if not isinstance(pagination, dict) or not isinstance(pagination.get("has_next"), bool):
                raise PublicSourceError("MALFORMED_RECORD")
            if not pagination["has_next"]:
                return tuple(records)
            next_cursor = pagination.get("next_cursor")
            if (
                not isinstance(next_cursor, str)
                or not next_cursor.strip()
                or len(next_cursor) > 512
            ):
                raise PublicSourceError("INVALID_PAGINATION")
            if page_number == 4:
                raise PublicSourceError("RECORD_LIMIT_EXCEEDED")
            cursor = next_cursor
        raise PublicSourceError("RECORD_LIMIT_EXCEEDED")

    def fetch_cftc_cot(
        self, *, since: date | None = None, limit: int = 5000
    ) -> tuple[PublicEvidenceV1, ...]:
        if not 1 <= limit <= 5000:
            raise PublicSourceError("INVALID_REQUEST")
        params = {"$limit": str(limit), "$order": "report_date_as_yyyy_mm_dd DESC"}
        if since is not None:
            params["$where"] = f"report_date_as_yyyy_mm_dd >= '{since.isoformat()}'"
        url = "https://publicreporting.cftc.gov/resource/jun7-fc8e.json?" + urlencode(params)
        return parse_cftc_cot(
            self._request("GET", url, headers={"Accept": "application/json"}),
            fetched_at=self._now(),
        )

    def fetch_treasury_yield_curve(self, *, year: int) -> tuple[PublicEvidenceV1, ...]:
        if year < 1990 or year > self._now().year:
            raise PublicSourceError("INVALID_REQUEST")
        url = (
            "https://home.treasury.gov/resource-center/data-chart-center/interest-rates/pages/xml?"
            + urlencode(
                {
                    "data": "daily_treasury_yield_curve",
                    "field_tdr_date_value": str(year),
                    "page": "0",
                }
            )
        )
        return parse_treasury_curve(
            self._request("GET", url, headers={"Accept": "application/xml"}), fetched_at=self._now()
        )


__all__ = [
    "BoundedHTTPTransport",
    "PublicEvidenceV1",
    "PublicSourceError",
    "PublicSourcesClient",
    "parse_cftc_cot",
    "parse_finra_regsho",
    "parse_finra_weekly",
    "parse_house_ptr_index",
    "parse_public_json_rows",
    "parse_sec_form4",
    "parse_sec_submissions",
    "parse_treasury_curve",
]
