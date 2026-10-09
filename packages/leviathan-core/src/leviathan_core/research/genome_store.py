"""InMemoryGenomeStore — volatile genome repository with RBI validation history.

Genomes stale after 14 days without a PASSED validation record. The store
tracks per-genome validation history so callers can query staleness and
list only genomes that have passed validation recently enough to be active.

Doctrine: no genome reaches live execution without passing through the
Research Domain. Knowledge NEVER flows directly to execution.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from leviathan_core.schemas.strategy import StrategyGenome


@dataclass
class _ValidationRecord:
    genome_id: str
    stage: str
    passed: bool
    metrics: dict[str, Any]
    at: datetime


class InMemoryGenomeStore:
    """Volatile genome store with per-genome validation history.

    Staleness rule:
        A genome is stale if it has no PASSED validation record within
        the ``max_age_days`` window ending at ``as_of``. A genome with
        zero validation records is always stale.

    All ``as_of`` / ``at`` datetimes must be timezone-aware.
    """

    def __init__(self) -> None:
        self._genomes: dict[str, StrategyGenome] = {}
        self._history: dict[str, list[_ValidationRecord]] = {}

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def put(self, genome: StrategyGenome) -> None:
        """Insert or replace a genome by strategy_id."""
        self._genomes[genome.strategy_id] = genome
        if genome.strategy_id not in self._history:
            self._history[genome.strategy_id] = []

    def record_validation(
        self,
        genome_id: str,
        stage: str,
        passed: bool,
        metrics: dict[str, Any],
        at: datetime,
    ) -> None:
        """Append a validation record for the given genome_id.

        Args:
            genome_id: Must correspond to a genome already in the store.
            stage:     RBI stage label (e.g. "backtest_initial").
            passed:    Whether this validation passed.
            metrics:   Arbitrary metrics dict captured at this stage.
            at:        Timezone-aware datetime of the validation event.

        Raises:
            KeyError: if genome_id is not in the store.
            ValueError: if *at* is timezone-naive.
        """
        if genome_id not in self._genomes:
            raise KeyError(f"Unknown genome_id: {genome_id!r}")
        if at.tzinfo is None or at.utcoffset() is None:
            raise ValueError(f"record_validation: 'at' must be timezone-aware, got {at!r}")
        self._history[genome_id].append(
            _ValidationRecord(
                genome_id=genome_id,
                stage=stage,
                passed=passed,
                metrics=dict(metrics),
                at=at,
            )
        )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get(self, genome_id: str) -> StrategyGenome | None:
        """Return the genome with the given id, or None."""
        return self._genomes.get(genome_id)

    def is_stale(
        self,
        genome_id: str,
        as_of: datetime,
        max_age_days: int = 14,
    ) -> bool:
        """Return True if the genome has no PASSED validation within the window.

        The window is ``(as_of - max_age_days, as_of]`` — inclusive of
        ``as_of``, exclusive of exactly ``max_age_days + 1`` days ago.
        A genome with no records at all is always stale.

        Args:
            genome_id:    Must be a known genome_id (raises KeyError if not).
            as_of:        Timezone-aware reference datetime.
            max_age_days: Window size in days. Default 14.

        Raises:
            KeyError: if genome_id is unknown.
            ValueError: if *as_of* is timezone-naive.
        """
        if genome_id not in self._genomes:
            raise KeyError(f"Unknown genome_id: {genome_id!r}")
        if as_of.tzinfo is None or as_of.utcoffset() is None:
            raise ValueError(f"is_stale: 'as_of' must be timezone-aware, got {as_of!r}")

        cutoff = as_of - timedelta(days=max_age_days)
        records = self._history.get(genome_id, [])
        return not any(r.passed and r.at >= cutoff for r in records)

    def list_active(self, as_of: datetime, max_age_days: int = 14) -> list[StrategyGenome]:
        """Return all genomes that are NOT stale as of *as_of*.

        Args:
            as_of:        Timezone-aware reference datetime.
            max_age_days: Staleness window in days.

        Raises:
            ValueError: if *as_of* is timezone-naive.
        """
        if as_of.tzinfo is None or as_of.utcoffset() is None:
            raise ValueError(f"list_active: 'as_of' must be timezone-aware, got {as_of!r}")
        return [
            genome
            for genome_id, genome in self._genomes.items()
            if not self.is_stale(genome_id, as_of, max_age_days)
        ]

    def validation_history(self, genome_id: str) -> list[_ValidationRecord]:
        """Return the full validation history for a genome."""
        if genome_id not in self._genomes:
            raise KeyError(f"Unknown genome_id: {genome_id!r}")
        return list(self._history[genome_id])
