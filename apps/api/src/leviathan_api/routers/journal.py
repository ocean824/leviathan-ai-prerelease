"""Trade journal surface — the memory domain over HTTP."""

from collections import Counter

from fastapi import APIRouter, Query, Request
from leviathan_store.repositories import JournalRepository

router = APIRouter(prefix="/journal", tags=["journal"])


@router.get("/records")
async def journal_records(
    request: Request, limit: int = Query(default=50, ge=1, le=500)
) -> dict[str, object]:
    async with request.app.state.sessionmaker() as session:
        key = request.app.state.leviathan.ledger_integrity_key
        repo = JournalRepository(session, integrity_key=key)
        historical = await repo.list_recent(limit=limit)
        undecodable_count = repo.undecodable_count
        verified = await repo.list_authoritative_recent(limit=None)
        verified_by_trade_id = {record.trade_id: record for record in verified}
        stats = dict(Counter(record.outcome.value for record in verified))
    records: list[dict[str, object]] = []
    unverified_count = undecodable_count
    verified_count = 0
    for record in historical:
        verified_record = verified_by_trade_id.get(record.trade_id)
        if verified_record is not None and verified_record == record:
            verified_count += 1
            visible_record = verified_record
            is_verified = True
        else:
            unverified_count += 1
            visible_record = record
            is_verified = False
        records.append(
            {
                **visible_record.model_dump(mode="json"),
                "provenance": (
                    "route_attempt_terminal_verified"
                    if is_verified
                    else "route_attempt_terminal_unverified"
                ),
            }
        )
    if verified_count == 0 and unverified_count == 0:
        provenance = "none"
    elif verified_count == 0:
        provenance = "unverified"
    elif unverified_count:
        provenance = "mixed"
    else:
        provenance = "verified"
    response: dict[str, object] = {
        "records": records,
        "stats": stats,
        "unverified_count": unverified_count,
        "provenance": provenance,
    }
    if undecodable_count:
        response["unverified_reasons"] = {"UNDECODABLE_ROW": undecodable_count}
    return response
