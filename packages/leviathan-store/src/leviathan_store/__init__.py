"""LEVIATHAN AI persistence package.

The core domain is pure — it speaks Layer-1 contracts and touches no
database. This package is where those frozen contracts finally hit
storage, without leaking a single ORM type back across the boundary:
callers hand in pydantic objects and get pydantic objects back.

    engine        async engine + sessionmaker wiring, schema bootstrap
    tables        SQLAlchemy 2.0 DeclarativeBase and portable tables
    repositories  async repos translating contracts <-> rows

SQLite/aiosqlite is the engine today; PostgreSQL/TimescaleDB arrives
with Docker. Only dialect-portable column types are used so the schema
stands up unchanged on both, and three ledgers — journal records,
genome validations, risk verdicts — are append-only: history is
extended, never rewritten.
"""

from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.repositories import (
    DecisionRepository,
    GenomeRepository,
    JournalRepository,
    RiskVerdictRepository,
    SetupRepository,
)
from leviathan_store.tables import (
    DecisionRow,
    GenomeRow,
    GenomeValidationRow,
    JournalRow,
    RiskVerdictRow,
    SetupRow,
    StoreBase,
)

__version__ = "0.1.0"

__all__ = [
    "DecisionRepository",
    "DecisionRow",
    "GenomeRepository",
    "GenomeRow",
    "GenomeValidationRow",
    "JournalRepository",
    "JournalRow",
    "RiskVerdictRepository",
    "RiskVerdictRow",
    "SetupRepository",
    "SetupRow",
    "StoreBase",
    "create_engine_and_sessionmaker",
    "init_schema",
]
