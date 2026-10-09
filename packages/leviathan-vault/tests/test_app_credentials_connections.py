from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import SecretStr

from leviathan_vault.app_credentials import (
    SNAPTRADE_SUPPORTED_PROVIDERS,
    CredentialError,
    InMemoryCredentialStore,
)


def test_new_provider_allowlist_and_key_token_separation() -> None:
    store = InMemoryCredentialStore()
    profile = store.put_profile(
        "TASTYTRADE",
        "DEMO",
        "default",
        {
            "oauth_client_id": "client-1",
            "oauth_client_secret": SecretStr("synthetic-client-secret"),
            "access_token": SecretStr("synthetic-access-token"),
            "refresh_token": SecretStr("synthetic-refresh-token"),
            "token_expires_at": datetime(2030, 1, 1, tzinfo=UTC),
        },
    )
    assert profile.provider == "TASTYTRADE"
    assert set(profile.configured) == {"oauth_client_secret", "access_token", "refresh_token"}
    assert "synthetic-access-token" not in repr(profile)
    resolved = store.resolve("TASTYTRADE", "DEMO", "default")
    assert resolved.secret("access_token").get_secret_value() == "synthetic-access-token"
    assert resolved.secret("oauth_client_secret").get_secret_value() == "synthetic-client-secret"
    with pytest.raises(CredentialError) as caught:
        store.put_profile("BINANCE", "LIVE", "default", {})
    assert caught.value.code == "INVALID_PROVIDER"


def test_model_provider_optional_key_url_validation_and_redaction() -> None:
    store = InMemoryCredentialStore()
    profile = store.put_profile(
        "OPENAI_COMPATIBLE",
        "PAPER",
        "default",
        {"base_url": "http://localhost:8080/v1", "display_label": "Local model"},
    )
    assert profile.configured == {"api_key": False}
    assert store.resolve("OPENAI_COMPATIBLE", "PAPER", "default").profile == profile
    store.put_profile(
        "OPENAI_COMPATIBLE",
        "PAPER",
        "default",
        {
            "api_key": SecretStr("synthetic-key"),
            "base_url": "https://models.example/v1",
            "display_label": "Model",
        },
    )
    with pytest.raises(CredentialError, match="INVALID_BASE_URL"):
        store.put_profile(
            "OPENAI_COMPATIBLE",
            "PAPER",
            "bad-url",
            {"base_url": "http://example.com/v1", "display_label": "Bad"},
        )
    with pytest.raises(CredentialError, match="INVALID_BASE_URL"):
        store.put_profile(
            "OPENAI_COMPATIBLE",
            "PAPER",
            "userinfo",
            {"base_url": "https://user:pass@models.example/v1", "display_label": "Bad"},
        )


def test_routing_record_is_keyed_by_environment_and_profile() -> None:
    store = InMemoryCredentialStore()
    assert store.get_default_route("SNAPTRADE", "PAPER", "default") == "SNAPTRADE"
    assert store.get_default_route("IBKR", "PAPER", "default") == "DIRECT"
    store.set_default_route("PAPER", "default", "DIRECT")
    store.set_default_route("LIVE", "default", "SNAPTRADE")
    assert store.get_default_route("SNAPTRADE", "PAPER", "default") == "DIRECT"
    assert store.get_default_route("SNAPTRADE", "LIVE", "default") == "SNAPTRADE"
    assert store.get_default_route("IBKR", "LIVE", "default") == "DIRECT"
    assert store.get_default_route("SNAPTRADE", "PAPER", "other") == "SNAPTRADE"
    assert frozenset({"SNAPTRADE"}) == SNAPTRADE_SUPPORTED_PROVIDERS
    with pytest.raises(CredentialError, match="INVALID_DEFAULT_ROUTE"):
        store.set_default_route("PAPER", "default", "IBKR")


def test_openai_optional_organization_and_forex_mt5_fields() -> None:
    store = InMemoryCredentialStore()
    profile = store.put_profile(
        "OPENAI", "PAPER", "default", {"api_key": SecretStr("synthetic-openai-key")}
    )
    assert profile.organization is None
    store.put_profile(
        "FOREX_COM_MT5",
        "DEMO",
        "default",
        {
            "server": "demo-server",
            "login": "synthetic-login",
            "password": SecretStr("synthetic-password"),
        },
    )
    assert (
        store.resolve("FOREX_COM_MT5", "DEMO", "default").secret("password").get_secret_value()
        == "synthetic-password"
    )
