"""Pure taxonomy mapping with explicit conflict audit intents."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import fields, replace
from itertools import islice

from leviathan_core.numeric import canonical_json

from .models import (
    MappingAuditIntentV1,
    MappingDecisionV1,
    MappingRuleV1,
    PredictionError,
    PredictionMarketIdentityV1,
    _issue_mapping,
    _ns,
)

_PRIORITY = {"MANUAL": 3, "EXACT_TAG": 2, "PATTERN": 1}


def _content(rule: MappingRuleV1) -> bytes:
    return canonical_json({field.name: getattr(rule, field.name) for field in fields(rule)})


def _matches(market: PredictionMarketIdentityV1, rule: MappingRuleV1) -> bool:
    if rule.venue != market.venue:
        return False
    if rule.contract_id is not None and rule.contract_id != market.contract_id:
        return False
    if rule.match_kind == "MANUAL":
        return rule.contract_id == market.contract_id
    if rule.match_kind == "EXACT_TAG":
        return rule.match_value in market.tags
    # Pattern rules are bounded literal substring matches, never regex execution.
    return rule.match_value.casefold() in market.title.casefold()


def map_event(
    market: PredictionMarketIdentityV1,
    rules: Iterable[MappingRuleV1],
    *,
    asof_ns: int,
) -> MappingDecisionV1:
    """Choose manual, then exact tag, then pattern, or return a conflict intent."""
    if type(market) is not PredictionMarketIdentityV1:
        raise PredictionError("MARKET_IDENTITY_INVALID", "market")
    _ns(asof_ns, "asof_ns")
    market = replace(market)
    if market.metadata_available_ns > asof_ns:
        raise PredictionError("METADATA_NOT_AVAILABLE", "market")
    try:
        rows = tuple(islice(iter(rules), 257))
    except Exception:
        raise PredictionError("MAPPING_INPUT_INVALID", "rules") from None
    if len(rows) > 256 or any(type(row) is not MappingRuleV1 for row in rows):
        raise PredictionError("MAPPING_INPUT_INVALID", "rules")
    rows = tuple(replace(row) for row in rows)
    visible = tuple(
        row
        for row in rows
        if row.available_ns <= asof_ns
        and row.venue == market.venue
        and (row.contract_id is None or row.contract_id == market.contract_id)
    )
    ordered = tuple(sorted(_content(row) for row in visible))
    mapping_revision = hashlib.sha256(
        canonical_json(tuple(item.decode("ascii") for item in ordered))
    ).hexdigest()

    # Reconcile only the visible revisions of each rule ID.
    by_id: dict[str, list[MappingRuleV1]] = {}
    for rule in visible:
        by_id.setdefault(rule.rule_id, []).append(rule)
    active: list[MappingRuleV1] = []
    conflicts: set[str] = set()
    for rule_id, history in by_id.items():
        latest = max(item.available_ns for item in history)
        tied = [item for item in history if item.available_ns == latest]
        if len({_content(item) for item in tied}) > 1:
            if any(_matches(market, item) for item in tied):
                conflicts.add(rule_id)
        else:
            active.append(tied[0])
    if conflicts:
        return _issue_mapping(
            venue=market.venue,
            contract_id=market.contract_id,
            status="CONFLICT",
            targets=(),
            target_horizons=(),
            matched_rule_ids=tuple(sorted(conflicts)),
            priority=None,
            mapping_revision=mapping_revision,
            audit_intents=(
                MappingAuditIntentV1("RULE_REVISION_CONFLICT", tuple(sorted(conflicts))),
            ),
            asof_ns=asof_ns,
        )

    matches = [rule for rule in active if _matches(market, rule)]
    if not matches:
        return _issue_mapping(
            venue=market.venue,
            contract_id=market.contract_id,
            status="UNMAPPED",
            targets=(),
            target_horizons=(),
            matched_rule_ids=(),
            priority=None,
            mapping_revision=mapping_revision,
            audit_intents=(),
            asof_ns=asof_ns,
        )
    highest = max(_PRIORITY[rule.match_kind] for rule in matches)
    selected = [rule for rule in matches if _PRIORITY[rule.match_kind] == highest]
    ids = tuple(sorted({rule.rule_id for rule in selected}))
    targets = tuple(sorted({rule.internal_event_id for rule in selected}))
    target_horizons = tuple(sorted({(rule.internal_event_id, rule.horizon) for rule in selected}))
    priority = selected[0].match_kind
    groups = {rule.manual_group for rule in selected}
    explicit_one_to_many = priority == "MANUAL" and len(groups) == 1 and None not in groups
    horizon_conflict = len({target for target, _ in target_horizons}) != len(target_horizons)
    if horizon_conflict or (len(targets) > 1 and not explicit_one_to_many):
        return _issue_mapping(
            venue=market.venue,
            contract_id=market.contract_id,
            status="CONFLICT",
            targets=(),
            target_horizons=(),
            matched_rule_ids=ids,
            priority=priority,
            mapping_revision=mapping_revision,
            audit_intents=(MappingAuditIntentV1("MAPPING_CONFLICT", ids),),
            asof_ns=asof_ns,
        )
    return _issue_mapping(
        venue=market.venue,
        contract_id=market.contract_id,
        status="MAPPED",
        targets=targets,
        target_horizons=target_horizons,
        matched_rule_ids=ids,
        priority=priority,
        mapping_revision=mapping_revision,
        audit_intents=(),
        asof_ns=asof_ns,
    )
