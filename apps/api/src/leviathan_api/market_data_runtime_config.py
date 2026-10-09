"""Strict, non-secret configuration for the local PAPER market-data runtime."""

from __future__ import annotations

import os
import re
import stat
import tomllib
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

MAX_CONFIG_BYTES = 64 * 1024
CONFIG_RELATIVE_PATH = Path("market-data") / "paper-runtime.toml"
CONFIG_PATH_ENV = "LEVIATHAN_MARKET_DATA_CONFIG"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_SCHEMA = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z", re.ASCII)
_DBN_SCHEMAS = frozenset({"trades", "mbo", "mbp-10", "ohlcv-1m"})
_MASSIVE_SCHEMAS = frozenset({"trades", "quotes", "aggregates", "ohlcv-1m"})
_DBN_STYPE_INPUTS = frozenset({"raw_symbol", "instrument_id", "parent", "continuous"})
_CREDENTIAL_SHAPE = re.compile(
    r"(?i)(?:api[_-]?key|secret|password|bearer|access[_-]?token)\s*[:=]|"
    r"\b(?:sk|db|pkc|mkey)[_-][A-Za-z0-9_-]{16,}\b|"
    r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b|"
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
)


class MarketDataConfigError(ValueError):
    """Fixed, content-free failure for local runtime configuration."""

    _CODES = frozenset(
        {
            "INVALID_CONFIG",
            "CONFIG_TOO_LARGE",
            "CONFIG_UNSAFE_PATH",
            "CONFIG_READ_FAILED",
        }
    )

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in self._CODES else "INVALID_CONFIG"
        super().__init__(self.code)


class ProviderFeedConfigV1(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    enabled: bool
    dataset: str
    stype_in: str
    schemas: tuple[str, ...]
    instruments: tuple[str, ...]

    @field_validator("dataset")
    @classmethod
    def _dataset(cls, value: str) -> str:
        if type(value) is not str or not value.isascii() or not _IDENTIFIER.fullmatch(value):
            raise ValueError("INVALID_CONFIG")
        if _CREDENTIAL_SHAPE.search(value):
            raise ValueError("INVALID_CONFIG")
        return value

    @field_validator("stype_in")
    @classmethod
    def _stype_in(cls, value: str) -> str:
        if type(value) is not str or not value.isascii() or not _SCHEMA.fullmatch(value):
            raise ValueError("INVALID_CONFIG")
        return value

    @field_validator("schemas")
    @classmethod
    def _schemas(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if (
            type(value) is not tuple
            or len(value) > 16
            or any(
                type(item) is not str or not item.isascii() or not _SCHEMA.fullmatch(item)
                for item in value
            )
            or len(set(value)) != len(value)
        ):
            raise ValueError("INVALID_CONFIG")
        return value

    @field_validator("instruments")
    @classmethod
    def _instruments(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if (
            type(value) is not tuple
            or len(value) > 2_000
            or any(
                type(item) is not str or not item.isascii() or not _IDENTIFIER.fullmatch(item)
                for item in value
            )
            or len(set(value)) != len(value)
            or any(_CREDENTIAL_SHAPE.search(item) for item in value)
        ):
            raise ValueError("INVALID_CONFIG")
        return value


class BackfillConfigV1(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    max_jobs: int = Field(ge=1, le=16)
    max_records: int = Field(ge=1, le=50_000)
    max_window_ns: int = Field(ge=1, le=31 * 24 * 60 * 60 * 1_000_000_000)
    max_estimated_usd: Decimal

    @field_validator("max_estimated_usd", mode="before")
    @classmethod
    def _parse_cost(cls, value: object) -> Decimal:
        if type(value) is not str or not re.fullmatch(
            r"(?:0|[1-9][0-9]{0,7})(?:\.[0-9]{1,4})?", value, re.ASCII
        ):
            raise ValueError("INVALID_CONFIG")
        try:
            result = Decimal(value)
        except InvalidOperation:
            raise ValueError("INVALID_CONFIG") from None
        if not result.is_finite() or result < 0:
            raise ValueError("INVALID_CONFIG")
        return result


class ReconnectConfigV1(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    min_delay_ms: int = Field(ge=100, le=5_000)
    max_delay_ms: int = Field(ge=100, le=30_000)
    max_attempts: int = Field(ge=1, le=100)

    @model_validator(mode="after")
    def _ordered(self) -> ReconnectConfigV1:
        if self.min_delay_ms > self.max_delay_ms:
            raise ValueError("INVALID_CONFIG")
        return self


class MarketDataRuntimeConfigV1(BaseModel):
    """Configuration contains identifiers and limits only; never credential material."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    schema_version: Literal[1]
    project_id: str
    environment: Literal["PAPER"]
    databento: ProviderFeedConfigV1
    massive: ProviderFeedConfigV1
    backfill: BackfillConfigV1
    reconnect: ReconnectConfigV1

    @field_validator("project_id")
    @classmethod
    def _project(cls, value: str) -> str:
        if type(value) is not str or not value.isascii() or not _IDENTIFIER.fullmatch(value):
            raise ValueError("INVALID_CONFIG")
        return value

    @model_validator(mode="after")
    def _providers(self) -> MarketDataRuntimeConfigV1:
        if (
            set(self.databento.schemas) - _DBN_SCHEMAS
            or self.databento.stype_in not in _DBN_STYPE_INPUTS
            or set(self.massive.schemas) - _MASSIVE_SCHEMAS
        ):
            raise ValueError("INVALID_CONFIG")
        if self.databento.enabled and (
            not self.databento.dataset
            or not self.databento.schemas
            or not self.databento.instruments
        ):
            raise ValueError("INVALID_CONFIG")
        if self.massive.enabled and (
            not self.massive.dataset or not self.massive.schemas or not self.massive.instruments
        ):
            raise ValueError("INVALID_CONFIG")
        return self


@dataclass(frozen=True, slots=True)
class MarketDataRuntimeConfigResolutionV1:
    status: Literal["CONFIGURED", "NOT_CONFIGURED", "INVALID_CONFIG"]
    source: Literal["INJECTED", "FILE", "NONE"]
    config: MarketDataRuntimeConfigV1 | None
    error_code: str | None = None


def validate_market_data_runtime_config(value: object) -> MarketDataRuntimeConfigV1:
    """Revalidate injected models too, including instances made via model_construct."""
    if type(value) is not MarketDataRuntimeConfigV1:
        raise MarketDataConfigError("INVALID_CONFIG")
    try:
        payload = value.model_dump(mode="python")
        backfill = payload.get("backfill")
        if type(backfill) is dict and type(backfill.get("max_estimated_usd")) is Decimal:
            backfill["max_estimated_usd"] = format(backfill["max_estimated_usd"], "f")
        return MarketDataRuntimeConfigV1.model_validate(payload, strict=True)
    except (ValidationError, TypeError, ValueError):
        raise MarketDataConfigError("INVALID_CONFIG") from None


def _contains_reparse_point(path: Path) -> bool:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            return True
    return False


def _read_bounded(path: Path) -> bytes:
    if not path.is_absolute() or _contains_reparse_point(path):
        raise MarketDataConfigError("CONFIG_UNSAFE_PATH")
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise MarketDataConfigError("CONFIG_UNSAFE_PATH")
        if before.st_size > MAX_CONFIG_BYTES:
            raise MarketDataConfigError("CONFIG_TOO_LARGE")
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino) or getattr(
                opened, "st_file_attributes", 0
            ) & 0x400:
                raise MarketDataConfigError("CONFIG_UNSAFE_PATH")
            raw = stream.read(MAX_CONFIG_BYTES + 1)
    except MarketDataConfigError:
        raise
    except OSError:
        raise MarketDataConfigError("CONFIG_READ_FAILED") from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise MarketDataConfigError("CONFIG_TOO_LARGE")
    return raw


def _reject_credential_content(value: object) -> None:
    if type(value) is str:
        if _CREDENTIAL_SHAPE.search(value):
            raise MarketDataConfigError("INVALID_CONFIG")
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str or _CREDENTIAL_SHAPE.search(key):
                raise MarketDataConfigError("INVALID_CONFIG")
            _reject_credential_content(item)
    elif type(value) is list:
        for item in value:
            _reject_credential_content(item)


def load_market_data_runtime_config(path: str | Path) -> MarketDataRuntimeConfigV1:
    """Read one existing local config file with bounded, strict TOML validation."""
    if not isinstance(path, (str, Path)):
        raise MarketDataConfigError("CONFIG_UNSAFE_PATH")
    raw = _read_bounded(Path(path))
    try:
        decoded = tomllib.loads(raw.decode("utf-8", errors="strict"))
        _reject_credential_content(decoded)
        # TOML arrays are converted only where the closed schema expects tuples.
        for provider in ("databento", "massive"):
            section = decoded.get(provider)
            if type(section) is dict:
                for field_name in ("schemas", "instruments"):
                    value = section.get(field_name)
                    if type(value) is list:
                        section[field_name] = tuple(value)
        return MarketDataRuntimeConfigV1.model_validate(decoded, strict=True)
    except MarketDataConfigError:
        raise
    except (UnicodeError, tomllib.TOMLDecodeError, ValidationError, TypeError, ValueError):
        raise MarketDataConfigError("INVALID_CONFIG") from None


def resolve_market_data_runtime_config(
    *,
    injected: object | None,
    app_data_dir: str | Path | None,
    environ: dict[str, str] | None = None,
) -> MarketDataRuntimeConfigResolutionV1:
    """Apply injected > existing data-root file > explicit env file > absent."""
    if injected is not None:
        try:
            config = validate_market_data_runtime_config(injected)
        except MarketDataConfigError as exc:
            return MarketDataRuntimeConfigResolutionV1("INVALID_CONFIG", "INJECTED", None, exc.code)
        return MarketDataRuntimeConfigResolutionV1("CONFIGURED", "INJECTED", config)

    path: Path | None = None
    if app_data_dir is not None:
        try:
            path = Path(os.path.abspath(Path(app_data_dir) / CONFIG_RELATIVE_PATH))
        except (TypeError, ValueError):
            return MarketDataRuntimeConfigResolutionV1(
                "INVALID_CONFIG", "FILE", None, "CONFIG_UNSAFE_PATH"
            )
    else:
        settings = os.environ if environ is None else environ
        configured_path = settings.get(CONFIG_PATH_ENV)
        if configured_path:
            path = Path(os.path.abspath(Path(configured_path)))
    if path is None:
        return MarketDataRuntimeConfigResolutionV1("NOT_CONFIGURED", "NONE", None)
    try:
        path.lstat()
    except FileNotFoundError:
        return MarketDataRuntimeConfigResolutionV1("NOT_CONFIGURED", "NONE", None)
    except OSError:
        return MarketDataRuntimeConfigResolutionV1(
            "INVALID_CONFIG", "FILE", None, "CONFIG_READ_FAILED"
        )
    try:
        config = load_market_data_runtime_config(path)
    except MarketDataConfigError as exc:
        return MarketDataRuntimeConfigResolutionV1("INVALID_CONFIG", "FILE", None, exc.code)
    return MarketDataRuntimeConfigResolutionV1("CONFIGURED", "FILE", config)


__all__ = [
    "CONFIG_PATH_ENV",
    "CONFIG_RELATIVE_PATH",
    "MAX_CONFIG_BYTES",
    "BackfillConfigV1",
    "MarketDataConfigError",
    "MarketDataRuntimeConfigResolutionV1",
    "MarketDataRuntimeConfigV1",
    "ProviderFeedConfigV1",
    "ReconnectConfigV1",
    "load_market_data_runtime_config",
    "resolve_market_data_runtime_config",
    "validate_market_data_runtime_config",
]
