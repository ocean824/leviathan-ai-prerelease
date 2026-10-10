"""Runtime settings — env-driven, LEVIATHAN_ prefix, .env supported."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

from leviathan_core.schemas import OperatingMode


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LEVIATHAN_", env_file=".env", extra="ignore"
    )

    env: str = "development"
    operating_mode: OperatingMode = OperatingMode.RESEARCH
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    # SQLite until Docker brings TimescaleDB; set LEVIATHAN_DATABASE_URL to
    # postgresql+asyncpg://... when the compose stack is up.
    database_url: str = "sqlite+aiosqlite:///./data/leviathan.db"
    redis_url: str = "redis://localhost:6379/0"
    risk_lock_sha256: str = ""
    # Public trust configuration for the private Site Worker -> API assertion.
    worker_assertion_issuer: str = ""
    worker_assertion_audience: str = ""
    worker_assertion_jwks_json: str = ""
    # Desktop sets an absolute user-local path before importing the API.
    # Development defaults to project-local data/halt-state.sqlite3.
    halt_store_path: Path | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
