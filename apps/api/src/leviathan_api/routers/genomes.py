"""Strategy genome registry surface.

Staleness doctrine: a genome with no PASSED validation inside the last
14 days is stale and must re-run the RBI gauntlet before deployment.
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request
from leviathan_store.repositories import GenomeRepository

from leviathan_core.schemas import utcnow

STALE_AFTER = timedelta(days=14)


def _as_utc(dt: datetime) -> datetime:
    """SQLite drops tz info; treat stored naive datetimes as UTC."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)

router = APIRouter(prefix="/genomes", tags=["research"])


@router.get("")
async def list_genomes(request: Request) -> dict[str, object]:
    now = utcnow()
    async with request.app.state.sessionmaker() as session:
        repo = GenomeRepository(session)
        genomes = await repo.list_all()
        out = []
        for genome in genomes:
            latest = await repo.latest_validation(genome.strategy_id)
            stale = (
                latest is None
                or not latest.passed
                or (now - _as_utc(latest.validated_at)) > STALE_AFTER
            )
            out.append(
                {
                    "strategy_id": genome.strategy_id,
                    "family": genome.family,
                    "market": genome.market,
                    "timeframe": genome.timeframe,
                    "stale": stale,
                }
            )
    return {"genomes": out}
