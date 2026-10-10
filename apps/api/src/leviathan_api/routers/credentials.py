"""Status-only and write-only runtime credential API."""

from __future__ import annotations

from typing import Any, Literal, cast

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from pydantic_core import PydanticCustomError

from leviathan_core.seal import require
from leviathan_vault.app_credentials import CredentialError, CredentialStore, _validate_id

router = APIRouter(prefix="/live-trading/credentials", tags=["credentials"])


class CredentialPutRequest(BaseModel):
    """Strict write-only input. SecretStr repr never contains the supplied value."""

    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)

    key_id: SecretStr | None = None
    secret_key: SecretStr | None = None
    host: str | None = None
    port: int | None = None
    client_id: int | None = None
    account_id: str | None = None
    server: str | None = None
    login: str | None = None
    password: SecretStr | None = None
    server_id: str | None = None
    token: SecretStr | None = None
    confirm_environment: Literal["LIVE"] | None = None

    @field_validator("key_id", "secret_key", "password", "token")
    @classmethod
    def limit_secret_size(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value().encode("utf-8")) > 4096:
            raise PydanticCustomError("invalid_secret", "invalid secret")
        return value

    @field_validator("host", "account_id", "server", "login")
    @classmethod
    def limit_text_size(cls, value: str | None) -> str | None:
        if value is not None and len(value) > 256:
            raise PydanticCustomError("invalid_field", "invalid field")
        return value

    @field_validator("server_id", mode="before")
    @classmethod
    def validate_server_id(cls, value: object) -> object:
        if value is None:
            return value
        try:
            return _validate_id(value, "server_id")
        except CredentialError as exc:
            raise PydanticCustomError("invalid_id", "invalid identifier") from exc


class CredentialDeleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)

    confirm_environment: Literal["LIVE"] | None = None
    confirmation_token: SecretStr | None = Field(default=None, max_length=128)


def _store(request: Request) -> CredentialStore:
    store = getattr(request.app.state, "credential_store", None)
    if store is None:
        raise CredentialError("NOT_CONFIGURED")
    return cast(CredentialStore, store)


def _cache(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


@router.get("")
def status(request: Request, response: Response) -> dict[str, list[dict[str, Any]]]:
    _cache(response)
    profiles = _store(request).status_all()
    rows: list[dict[str, Any]] = []
    for profile in profiles:
        require(profile, "leviathan_vault.app_credentials.profile.v1")
        rows.append(
            {
                "provider": profile.provider,
                "environment": profile.environment,
                "profile": profile.profile_id,
                "configured": dict(profile.configured),
                "updated_at": profile.updated_at.isoformat(),
                "verification": "NOT_TESTED",
            }
        )
    for provider, environment, profile_id in _store(request).corrupt_profiles():
        secrets_by_provider: dict[str, tuple[str, ...]] = {
            "ALPACA": ("key_id", "secret_key"),
            "IBKR": (),
            "MT5": ("password",),
            "MCP": ("token",),
        }
        rows.append(
            {
                "provider": provider,
                "environment": environment,
                "profile": profile_id,
                "configured": {name: False for name in secrets_by_provider[provider]},
                "updated_at": None,
                "verification": "NOT_TESTED",
                "status": "CORRUPT",
            }
        )
    rows.sort(key=lambda row: (str(row["provider"]), str(row["environment"]), str(row["profile"])))
    return {"profiles": rows}
