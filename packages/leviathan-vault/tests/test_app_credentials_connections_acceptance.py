from __future__ import annotations

import os
import shutil
from datetime import UTC, datetime

import pytest
from pydantic import SecretStr

from leviathan_vault.app_credentials import (
    SNAPTRADE_SUPPORTED_PROVIDERS,
    CredentialError,
    DPAPICredentialStore,
    InMemoryCredentialStore,
)

_PROVIDER_FIELDS: dict[str, dict[str, object]] = {
    "SNAPTRADE": {
        "api_key": SecretStr("synthetic-snaptrade-key"),
        "api_secret": SecretStr("synthetic-snaptrade-secret"),
    },
    "TASTYTRADE": {
        "oauth_client_id": "synthetic-client-id",
        "oauth_client_secret": SecretStr("synthetic-tasty-secret"),
        "access_token": SecretStr("synthetic-tasty-access"),
        "refresh_token": SecretStr("synthetic-tasty-refresh"),
        "token_expires_at": datetime(2030, 1, 1, tzinfo=UTC),
    },
    "CTRADER": {
        "oauth_client_id": "synthetic-client-id",
        "oauth_client_secret": SecretStr("synthetic-ctrader-secret"),
        "access_token": SecretStr("synthetic-ctrader-access"),
        "refresh_token": SecretStr("synthetic-ctrader-refresh"),
        "token_expires_at": datetime(2030, 1, 1, tzinfo=UTC),
    },
    "COINBASE": {
        "access_token": SecretStr("synthetic-coinbase-access"),
        "refresh_token": SecretStr("synthetic-coinbase-refresh"),
        "token_expires_at": datetime(2030, 1, 1, tzinfo=UTC),
    },
    "KRAKEN": {
        "api_key": SecretStr("synthetic-kraken-key"),
        "api_secret": SecretStr("synthetic-kraken-secret"),
    },
    "BINANCE_US": {
        "api_key": SecretStr("synthetic-binance-us-key"),
        "api_secret": SecretStr("synthetic-binance-us-secret"),
    },
    "FOREX_COM_MT5": {
        "server": "synthetic-demo-server",
        "login": "synthetic-login",
        "password": SecretStr("synthetic-forex-password"),
    },
    "RITHMIC": {
        "server": "synthetic-rithmic-server",
        "login": "synthetic-login",
        "password": SecretStr("synthetic-rithmic-password"),
    },
    "KALSHI": {
        "api_key": SecretStr("synthetic-kalshi-key"),
        "api_secret": SecretStr("synthetic-kalshi-secret"),
    },
    "ANTHROPIC": {"api_key": SecretStr("synthetic-anthropic-key")},
    "OPENAI": {"api_key": SecretStr("synthetic-openai-key")},
    "OPENAI_COMPATIBLE": {
        "base_url": "http://127.0.0.1:8080/v1",
        "display_label": "Synthetic local model",
    },
}


def test_allowlisted_providers_are_accepted_and_global_binance_is_not() -> None:
    store = InMemoryCredentialStore()
    seen: set[str] = set()
    for provider, fields in _PROVIDER_FIELDS.items():
        environment = "DEMO" if provider in {"FOREX_COM_MT5", "RITHMIC"} else "PAPER"
        profile = store.put_profile(provider, environment, "default", fields)
        seen.add(profile.provider)
    assert seen == set(_PROVIDER_FIELDS)
    assert frozenset({"SNAPTRADE"}) == SNAPTRADE_SUPPORTED_PROVIDERS

    for unknown in ("BINANCE", "BINANCE_GLOBAL", "NOT_A_PROVIDER"):
        with pytest.raises(CredentialError) as caught:
            store.put_profile(unknown, "PAPER", "default", {})
        assert caught.value.code == "INVALID_PROVIDER"
        assert str(caught.value) == "INVALID_PROVIDER"


def test_existing_alpaca_ibkr_and_mt5_shapes_and_environments_remain_supported() -> None:
    store = InMemoryCredentialStore()
    alpaca = store.put_profile(
        "ALPACA",
        "PAPER",
        "paper",
        {
            "key_id": SecretStr("synthetic-alpaca-key"),
            "secret_key": SecretStr("synthetic-alpaca-secret"),
        },
    )
    ibkr = store.put_profile(
        "IBKR",
        "LIVE",
        "ibkr-live",
        {"host": "127.0.0.1", "port": 7497, "client_id": 1, "account_id": "DU123"},
    )
    mt5 = store.put_profile(
        "MT5",
        "DEMO",
        "mt5-demo",
        {
            "server": "synthetic-demo",
            "login": "synthetic-login",
            "password": SecretStr("synthetic-mt5-password"),
        },
    )
    assert (alpaca.provider, ibkr.provider, mt5.provider) == ("ALPACA", "IBKR", "MT5")
    assert (
        store.resolve("ALPACA", "PAPER", "paper").secret("key_id").get_secret_value()
        == "synthetic-alpaca-key"
    )
    assert (
        store.resolve("MT5", "DEMO", "mt5-demo").secret("password").get_secret_value()
        == "synthetic-mt5-password"
    )
    with pytest.raises(CredentialError) as caught:
        store.put_profile("MT5", "PAPER", "bad-env", {})
    assert caught.value.code == "INVALID_ENVIRONMENT"


def test_oauth_tokens_are_not_api_keys_and_profiles_do_not_echo_secrets(caplog) -> None:
    store = InMemoryCredentialStore()
    canary = "synthetic-access-token-canary"
    profile = store.put_profile(
        "TASTYTRADE",
        "DEMO",
        "default",
        {
            "oauth_client_id": "synthetic-client-id",
            "oauth_client_secret": SecretStr("synthetic-client-secret"),
            "access_token": SecretStr(canary),
            "refresh_token": SecretStr("synthetic-refresh-token"),
            "token_expires_at": datetime(2030, 1, 1, tzinfo=UTC),
        },
    )
    resolved = store.resolve("TASTYTRADE", "DEMO", "default")
    assert set(profile.configured) == {
        "oauth_client_secret",
        "access_token",
        "refresh_token",
    }
    assert resolved.secret("access_token").get_secret_value() == canary
    for rendered in (
        repr(profile),
        str(profile),
        repr(store.status_all()),
        repr(resolved),
        str(resolved),
    ):
        assert canary not in rendered
        assert "synthetic-client-secret" not in rendered
    assert canary not in caplog.text

    with pytest.raises(CredentialError) as caught:
        store.put_profile("TASTYTRADE", "DEMO", "bad", {"api_key": SecretStr(canary)})
    assert caught.value.code == "INVALID_FIELDS"
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value)


@pytest.mark.parametrize(
    "provider,fields",
    [
        ("ANTHROPIC", {"api_key": SecretStr("synthetic-anthropic-key")}),
        ("OPENAI", {"api_key": SecretStr("synthetic-openai-key"), "organization": "synthetic-org"}),
    ],
)
def test_model_provider_credentials_are_scoped_to_paper_and_redacted(provider, fields) -> None:
    store = InMemoryCredentialStore()
    profile = store.put_profile(provider, "PAPER", "default", fields)
    assert profile.provider == provider
    api_key = fields.get("api_key")
    if isinstance(api_key, SecretStr):
        assert api_key.get_secret_value() not in repr(profile)
    with pytest.raises(CredentialError) as caught:
        store.resolve(provider, "LIVE", "default")
    assert caught.value.code == "INVALID_ENVIRONMENT"


def test_openai_compatible_allows_https_and_only_loopback_http() -> None:
    store = InMemoryCredentialStore()
    for url in (
        "http://localhost:8080/v1",
        "http://127.0.0.1:8080/v1",
        "https://models.example/v1",
    ):
        profile_id = (
            "http-localhost"
            if "localhost" in url
            else "http-ip"
            if url.startswith("http:")
            else "https"
        )
        profile = store.put_profile(
            "OPENAI_COMPATIBLE",
            "PAPER",
            profile_id,
            {"base_url": url, "display_label": "Synthetic model"},
        )
        assert profile.base_url == url
        assert store.resolve("OPENAI_COMPATIBLE", "PAPER", profile_id).profile == profile

    invalid_urls = (
        "http://models.example/v1",
        "http://localhost.example/v1",
        "http://127.0.0.2/v1",
        "https://user:password@models.example/v1",
        "https://models.example/v1?token=synthetic",
        "https://models.example/v1#fragment",
    )
    for index, url in enumerate(invalid_urls):
        with pytest.raises(CredentialError) as caught:
            store.put_profile(
                "OPENAI_COMPATIBLE",
                "PAPER",
                f"bad-{index}",
                {"base_url": url, "display_label": "Synthetic model"},
            )
        assert caught.value.code == "INVALID_BASE_URL"
        assert url not in str(caught.value)

    with pytest.raises(CredentialError) as caught:
        store.put_profile(
            "OPENAI_COMPATIBLE", "PAPER", "missing-label", {"base_url": "https://models.example/v1"}
        )
    assert caught.value.code == "INVALID_FIELDS"


def test_default_route_defaults_to_snaptrade_only_when_supported_and_is_isolated() -> None:
    store = InMemoryCredentialStore()
    assert store.get_default_route("SNAPTRADE", "PAPER", "default") == "SNAPTRADE"
    assert store.get_default_route("TASTYTRADE", "PAPER", "default") == "DIRECT"
    store.set_default_route("PAPER", "default", "DIRECT")
    store.set_default_route("LIVE", "default", "SNAPTRADE")
    assert store.get_default_route("SNAPTRADE", "PAPER", "default") == "DIRECT"
    assert store.get_default_route("TASTYTRADE", "PAPER", "default") == "DIRECT"
    assert store.get_default_route("SNAPTRADE", "LIVE", "default") == "SNAPTRADE"
    assert store.get_default_route("SNAPTRADE", "PAPER", "other") == "SNAPTRADE"
    with pytest.raises(CredentialError) as caught:
        store.set_default_route("PAPER", "default", "IBKR")
    assert caught.value.code == "INVALID_DEFAULT_ROUTE"


def test_environment_and_deletion_are_exact() -> None:
    store = InMemoryCredentialStore()
    profile = store.put_profile("KRAKEN", "PAPER", "default", _PROVIDER_FIELDS["KRAKEN"])
    with pytest.raises(CredentialError) as caught:
        store.resolve("KRAKEN", "LIVE", "default")
    assert caught.value.code == "NOT_CONFIGURED"
    store.delete_profile("KRAKEN", "PAPER", "default")
    with pytest.raises(CredentialError) as caught:
        store.resolve("KRAKEN", "PAPER", "default")
    assert caught.value.code == "NOT_CONFIGURED"
    recreated = store.put_profile("KRAKEN", "PAPER", "default", _PROVIDER_FIELDS["KRAKEN"])
    assert recreated.revision == profile.revision + 2


@pytest.mark.skipif(os.name != "nt", reason="DPAPI CurrentUser is Windows only")
def test_dpapi_root_and_identity_bind_cross_project_and_environment_access(tmp_path) -> None:
    project_a, project_b = tmp_path / "project-a", tmp_path / "project-b"
    first = DPAPICredentialStore(project_a)
    first.put_profile("SNAPTRADE", "PAPER", "default", _PROVIDER_FIELDS["SNAPTRADE"])
    second = DPAPICredentialStore(project_b)
    with pytest.raises(CredentialError) as caught:
        second.resolve("SNAPTRADE", "PAPER", "default")
    assert caught.value.code == "NOT_CONFIGURED"
    with pytest.raises(CredentialError) as caught:
        first.resolve("SNAPTRADE", "LIVE", "default")
    assert caught.value.code == "NOT_CONFIGURED"

    source = project_a / "PAPER" / "SNAPTRADE" / "default" / "profile.json"
    target_dir = project_b / "PAPER" / "SNAPTRADE" / "default"
    target_dir.mkdir(parents=True)
    shutil.copyfile(source, target_dir / "profile.json")
    reopened = DPAPICredentialStore(project_b)
    with pytest.raises(CredentialError) as caught:
        reopened.resolve("SNAPTRADE", "PAPER", "default")
    assert caught.value.code == "CORRUPT"
