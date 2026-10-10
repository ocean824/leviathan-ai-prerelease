from __future__ import annotations

from pathlib import Path

import pytest

from leviathan_api.market_data_runtime_config import (
    CONFIG_PATH_ENV,
    CONFIG_RELATIVE_PATH,
    MAX_CONFIG_BYTES,
    MarketDataConfigError,
    MarketDataRuntimeConfigV1,
    load_market_data_runtime_config,
    resolve_market_data_runtime_config,
)
from leviathan_api.wave35_mounts import Wave35MountDependenciesV1

_CONFIG = """\
schema_version = 1
project_id = "test-project"
environment = "PAPER"

[databento]
enabled = false
dataset = "synthetic-dataset"
stype_in = "raw_symbol"
schemas = ["trades"]
instruments = ["SYNTHETIC.SYMBOL"]

[massive]
enabled = false
dataset = "synthetic-dataset"
stype_in = "raw_symbol"
schemas = ["trades"]
instruments = ["SYNTHETIC.SYMBOL"]

[backfill]
max_jobs = 2
max_records = 1000
max_window_ns = 86400000000000
max_estimated_usd = "3.50"

[reconnect]
min_delay_ms = 200
max_delay_ms = 5000
max_attempts = 5
"""


def _write_config(root: Path, text: str = _CONFIG) -> Path:
    path = root / CONFIG_RELATIVE_PATH
    path.parent.mkdir(parents=True)
    path.write_text(text, encoding="utf-8")
    return path


def _injected(project_id: str = "injected-project") -> MarketDataRuntimeConfigV1:
    return MarketDataRuntimeConfigV1.model_validate(
        {
            "schema_version": 1,
            "project_id": project_id,
            "environment": "PAPER",
            "databento": {
                "enabled": False,
                "dataset": "synthetic-dataset",
                "stype_in": "raw_symbol",
                "schemas": ("trades",),
                "instruments": ("SYNTHETIC.SYMBOL",),
            },
            "massive": {
                "enabled": False,
                "dataset": "synthetic-dataset",
                "stype_in": "raw_symbol",
                "schemas": ("trades",),
                "instruments": ("SYNTHETIC.SYMBOL",),
            },
            "backfill": {
                "max_jobs": 2,
                "max_records": 1000,
                "max_window_ns": 86400000000000,
                "max_estimated_usd": "3.50",
            },
            "reconnect": {"min_delay_ms": 200, "max_delay_ms": 5000, "max_attempts": 5},
        },
        strict=True,
    )


def test_injected_config_has_precedence_over_local_file(tmp_path: Path) -> None:
    _write_config(tmp_path)

    result = resolve_market_data_runtime_config(
        injected=_injected(), app_data_dir=tmp_path, environ={}
    )

    assert (result.status, result.source) == ("CONFIGURED", "INJECTED")
    assert result.config is not None and result.config.project_id == "injected-project"


def test_local_file_is_loaded_from_existing_app_data_root(tmp_path: Path) -> None:
    _write_config(tmp_path)

    result = resolve_market_data_runtime_config(injected=None, app_data_dir=tmp_path, environ={})

    assert (result.status, result.source) == ("CONFIGURED", "FILE")
    assert result.config is not None and result.config.project_id == "test-project"


def test_public_source_settings_are_non_secret_and_require_sec_user_agent(tmp_path: Path) -> None:
    config = (
        _CONFIG
        + """

[public_sources]
enabled = true
sec_user_agent = "Leviathan contact@example.test"
sec_requests_per_second = 10
"""
    )
    path = _write_config(tmp_path, config)
    loaded = load_market_data_runtime_config(path)
    assert loaded.public_sources.enabled is True
    assert loaded.public_sources.sec_user_agent == "Leviathan contact@example.test"
    assert loaded.public_sources.sec_requests_per_second == 10

    unsafe = config.replace('sec_user_agent = "Leviathan contact@example.test"\n', "")
    path.write_text(unsafe, encoding="utf-8")
    with pytest.raises(MarketDataConfigError, match="INVALID_CONFIG"):
        load_market_data_runtime_config(path)


def test_explicit_path_env_is_used_only_when_app_data_root_is_unavailable(tmp_path: Path) -> None:
    path = tmp_path / "paper-runtime.toml"
    path.write_text(_CONFIG, encoding="utf-8")

    result = resolve_market_data_runtime_config(
        injected=None, app_data_dir=None, environ={CONFIG_PATH_ENV: str(path)}
    )

    assert (result.status, result.source) == ("CONFIGURED", "FILE")
    assert result.config is not None and result.config.project_id == "test-project"


def test_missing_config_is_explicit_not_configured(tmp_path: Path) -> None:
    result = resolve_market_data_runtime_config(injected=None, app_data_dir=tmp_path, environ={})
    no_path = resolve_market_data_runtime_config(injected=None, app_data_dir=None, environ={})

    assert (result.status, result.source, result.config) == ("NOT_CONFIGURED", "NONE", None)
    assert (no_path.status, no_path.source) == ("NOT_CONFIGURED", "NONE")


@pytest.mark.parametrize(
    ("contents", "code"),
    [
        ("[unknown]\nvalue = 1\n", "INVALID_CONFIG"),
        (_CONFIG.replace('environment = "PAPER"', 'environment = "LIVE"'), "INVALID_CONFIG"),
        (
            _CONFIG.replace(
                'max_estimated_usd = "3.50"',
                'max_estimated_usd = "3.50"\napi_key = "canary-secret-value"',
            ),
            "INVALID_CONFIG",
        ),
    ],
)
def test_malformed_or_unsafe_file_fails_closed_without_echo(
    tmp_path: Path, contents: str, code: str
) -> None:
    path = tmp_path / "bad.toml"
    path.write_text(contents, encoding="utf-8")

    with pytest.raises(MarketDataConfigError) as caught:
        load_market_data_runtime_config(path)

    assert caught.value.code == code
    assert str(caught.value) == code
    assert "canary-secret-value" not in str(caught.value)


def test_oversized_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "oversized.toml"
    path.write_bytes(b"#" * (MAX_CONFIG_BYTES + 1))

    with pytest.raises(MarketDataConfigError) as caught:
        load_market_data_runtime_config(path)

    assert caught.value.code == "CONFIG_TOO_LARGE"


def test_oversized_injected_model_cannot_bypass_revalidation() -> None:
    forged = MarketDataRuntimeConfigV1.model_construct(
        schema_version=1,
        project_id="test-project",
        environment="LIVE",
        databento=None,
        massive=None,
        backfill=None,
        reconnect=None,
    )
    result = resolve_market_data_runtime_config(injected=forged, app_data_dir=None, environ={})
    assert (result.status, result.source, result.error_code) == (
        "INVALID_CONFIG",
        "INJECTED",
        "INVALID_CONFIG",
    )


def test_w35_dependency_exposes_typed_config_injection() -> None:
    assert "market_data_runtime_config" in Wave35MountDependenciesV1.__dataclass_fields__
    assert (
        Wave35MountDependenciesV1(market_data_runtime_config=_injected()).market_data_runtime_config
        is not None
    )
