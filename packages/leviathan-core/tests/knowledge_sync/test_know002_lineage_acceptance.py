"""Independent acceptance for pure, immutable KNOW-002 lineage decisions."""

from __future__ import annotations

import uuid

import pytest

from leviathan_core.knowledge_sync import (
    ParseFailureV1,
    ParseResultV1,
    SourceEnvelopeV1,
    parse_markdown,
)
from leviathan_core.knowledge_sync.lineage_models import (
    DedupDecisionV1,
    DocumentVersionV1,
    LineageEdgeV1,
    LineageEventV1,
    TombstoneV1,
    TrustedRenameV1,
    VaultSourceV1,
)
from leviathan_core.knowledge_sync.lineage_policy import (
    _RENAME_ISSUER,
    LineagePolicyError,
    decide_lineage,
    decide_tombstone,
    deterministic_chunk_id,
)
from leviathan_core.seal import require


def wire_id(number: int) -> str:
    return str(uuid.UUID(int=number, version=4))


ORG = wire_id(1)
VAULT = wire_id(2)
DOC = wire_id(3)
ACTOR = "actor-synthetic"


def parsed(
    *,
    doc_id: str = DOC,
    path: str = "research/notes.md",
    content: str = "# Synthetic note\n\nBounded fixture text.\n",
    created_at_ns: int = 10,
) -> ParseResultV1:
    result = parse_markdown(
        SourceEnvelopeV1(
            org_id=ORG,
            vault_id=VAULT,
            doc_id=doc_id,
            version_id=wire_id(1000 + created_at_ns),
            path=path,
            content_type="md",
            parser_version="parser-v1",
            chunker_version="chunker-v1",
            created_at_ns=created_at_ns,
            source_text=content,
        )
    )
    assert isinstance(result, ParseResultV1), getattr(result, "code", None)
    assert not isinstance(result, ParseFailureV1)
    return result


def decide(
    value: ParseResultV1,
    *,
    event_id: str,
    current_source: VaultSourceV1 | None = None,
    current_version: DocumentVersionV1 | None = None,
    force_reindex: bool = False,
    rename_evidence: TrustedRenameV1 | None = None,
    org_id: str = ORG,
    vault_id: str = VAULT,
    actor_id: str = ACTOR,
) -> DedupDecisionV1:
    result = decide_lineage(
        value,
        trusted_org_id=org_id,
        trusted_vault_id=vault_id,
        event_id=event_id,
        actor_id=actor_id,
        current_source=current_source,
        current_version=current_version,
        force_reindex=force_reindex,
        rename_evidence=rename_evidence,
    )
    assert type(result) is DedupDecisionV1
    return result


def issued_rename(
    *, doc_id: str, old_path: str, new_path: str, evidence_id: str = wire_id(3001)
) -> TrustedRenameV1:
    evidence = TrustedRenameV1(
        org_id=ORG,
        vault_id=VAULT,
        doc_id=doc_id,
        old_path=old_path,
        new_path=new_path,
        evidence_id=evidence_id,
    )
    return _RENAME_ISSUER.issue(evidence)


def _assert_parse_untrusted(value: object) -> None:
    with pytest.raises(LineagePolicyError) as denied:
        decide_lineage(
            value,
            trusted_org_id=ORG,
            trusted_vault_id=VAULT,
            event_id=wire_id(2099),
            actor_id=ACTOR,
        )

    assert denied.value.code == "PARSE_RESULT_UNTRUSTED"
    assert denied.value.args == ("PARSE_RESULT_UNTRUSTED",)
    assert str(denied.value) == "PARSE_RESULT_UNTRUSTED"
    assert "private-CANARY" not in str(denied.value)
    assert "source-CANARY" not in repr(denied.value)


def test_valid_unissued_parse_result_is_rejected_at_lineage_boundary() -> None:
    issued = parsed(content="# source-CANARY")
    reconstructed = ParseResultV1.model_validate(issued)

    assert reconstructed is not issued
    _assert_parse_untrusted(reconstructed)


def test_wrong_parser_result_type_is_rejected_without_leaking_failure_content() -> None:
    failure = parse_markdown(
        SourceEnvelopeV1(
            org_id=ORG,
            vault_id=VAULT,
            doc_id=DOC,
            version_id=wire_id(2999),
            path="research/notes.md",
            content_type="md",
            parser_version="parser-v1",
            chunker_version="chunker-v1",
            created_at_ns=10,
            source_text="[unsafe](javascript:alert(1)) source-CANARY",
        )
    )

    assert type(failure) is ParseFailureV1
    _assert_parse_untrusted(failure)


def test_low_level_tampered_parse_result_fails_closed_without_intents() -> None:
    issued = parsed(content="# source-CANARY")
    object.__setattr__(issued, "path", "../private-CANARY")

    _assert_parse_untrusted(issued)


def test_first_ingest_issues_version_lineage_event_and_stable_ids() -> None:
    source = parsed()
    first = decide(source, event_id=wire_id(2001))
    replay = decide(source, event_id=wire_id(2001))

    assert first.decision == "new_version"
    assert first.reason_code
    assert first.source is not None
    assert first.version is not None
    assert first.version.version_no == 1
    assert first.version.parent_version_id is None
    assert first.version.content_hash == source.source_hash
    assert first.version.path == source.path
    assert first.event is not None
    assert first.event.event_id == wire_id(2001)
    assert first.event.created_at_ns == source.created_at_ns
    assert first.event.actor_id == ACTOR
    assert require(first, "knowledge.lineage.v1") is first
    assert replay == first
    assert deterministic_chunk_id(first.version.version_id, 0) == deterministic_chunk_id(
        first.version.version_id, 0
    )
    assert deterministic_chunk_id(first.version.version_id, 0) != deterministic_chunk_id(
        first.version.version_id, 1
    )


def test_equal_path_and_content_returns_existing_version_without_new_event() -> None:
    original = parsed()
    first = decide(original, event_id=wire_id(2002))
    assert first.source is not None and first.version is not None
    before_source = first.source.model_dump(mode="json")
    before_version = first.version.model_dump(mode="json")

    duplicate = decide(
        parsed(created_at_ns=99),
        event_id=wire_id(2003),
        current_source=first.source,
        current_version=first.version,
    )

    assert duplicate.decision == "existing"
    assert duplicate.existing_version_id == first.version.version_id
    assert duplicate.version == first.version
    assert duplicate.event is None
    assert first.source.model_dump(mode="json") == before_source
    assert first.version.model_dump(mode="json") == before_version


def test_changed_content_appends_child_version_without_mutating_history() -> None:
    first = decide(parsed(), event_id=wire_id(2004))
    assert first.source is not None and first.version is not None
    old_source = first.source.model_dump(mode="json")
    old_version = first.version.model_dump(mode="json")
    changed = decide(
        parsed(content="# Synthetic note\n\nChanged fixture content.\n", created_at_ns=20),
        event_id=wire_id(2005),
        current_source=first.source,
        current_version=first.version,
    )

    assert changed.decision == "new_version"
    assert changed.source is not None and changed.version is not None
    assert changed.source.doc_id == first.source.doc_id
    assert changed.version.version_no == first.version.version_no + 1
    assert changed.version.parent_version_id == first.version.version_id
    assert changed.version.content_hash != first.version.content_hash
    assert changed.event is not None and changed.event.parent_version_id == first.version.version_id
    assert first.source.model_dump(mode="json") == old_source
    assert first.version.model_dump(mode="json") == old_version


def test_force_reindex_appends_parser_lineage_without_changing_content_identity() -> None:
    original = parsed()
    first = decide(original, event_id=wire_id(2006))
    assert first.source is not None and first.version is not None
    reparsed = parse_markdown(
        SourceEnvelopeV1(
            org_id=ORG,
            vault_id=VAULT,
            doc_id=original.doc_id,
            version_id=wire_id(1020),
            path=original.path,
            content_type="md",
            parser_version="parser-v2",
            chunker_version="chunker-v2",
            created_at_ns=20,
            source_text="# Synthetic note\n\nBounded fixture text.\n",
        )
    )
    assert isinstance(reparsed, ParseResultV1)

    indexed = decide(
        reparsed,
        event_id=wire_id(2007),
        current_source=first.source,
        current_version=first.version,
        force_reindex=True,
    )

    assert indexed.decision == "new_version"
    assert indexed.version is not None
    assert indexed.version.version_no == first.version.version_no + 1
    assert indexed.version.parent_version_id == first.version.version_id
    assert indexed.version.content_hash == first.version.content_hash
    assert indexed.version.parser_version == "parser-v2"
    assert indexed.version.chunker_version == "chunker-v2"
    assert indexed.reason_code


def test_same_content_at_distinct_path_is_a_separate_source_without_rename() -> None:
    first = decide(parsed(), event_id=wire_id(2008))
    second = decide(
        parsed(doc_id=wire_id(4), path="archive/notes.md"),
        event_id=wire_id(2009),
    )

    assert first.version is not None and second.version is not None
    assert first.version.content_hash == second.version.content_hash
    assert first.source is not None and second.source is not None
    assert first.source.path_hash != second.source.path_hash
    assert first.source.doc_id != second.source.doc_id
    assert second.decision == "new_version"


def test_rename_requires_issued_exact_tenant_document_and_path_evidence() -> None:
    original = parsed()
    first = decide(original, event_id=wire_id(2010))
    assert first.source is not None and first.version is not None
    renamed = parsed(path="research/renamed.md", created_at_ns=20)
    unissued = TrustedRenameV1(
        org_id=ORG,
        vault_id=VAULT,
        doc_id=original.doc_id,
        old_path=original.path,
        new_path=renamed.path,
        evidence_id=wire_id(3011),
    )
    rejected = decide(
        renamed,
        event_id=wire_id(2011),
        current_source=first.source,
        current_version=first.version,
        rename_evidence=unissued,
    )
    assert rejected.decision == "conflict"
    assert rejected.reason_code
    assert wire_id(3011) not in repr(rejected)

    accepted = decide(
        renamed,
        event_id=wire_id(2012),
        current_source=first.source,
        current_version=first.version,
        rename_evidence=issued_rename(
            doc_id=original.doc_id, old_path=original.path, new_path=renamed.path
        ),
    )
    assert accepted.decision == "rename"
    assert accepted.source is not None
    assert accepted.source.doc_id == first.source.doc_id
    assert accepted.source.path == renamed.path
    assert accepted.source.path_hash != first.source.path_hash
    assert accepted.event is not None
    assert accepted.event.old_path == original.path


def test_mismatched_tenant_or_stale_parent_fails_closed_without_payload_echo() -> None:
    first = decide(parsed(), event_id=wire_id(2013))
    assert first.source is not None and first.version is not None
    cases = (
        decide(
            parsed(), event_id=wire_id(2014), current_source=first.source,
            current_version=first.version, org_id=wire_id(5),
        ),
        decide(
            parsed(), event_id=wire_id(2015), current_source=first.source,
            current_version=first.version, vault_id=wire_id(6),
        ),
        decide(
            parsed(), event_id=wire_id(2016), current_source=first.source,
            current_version=DocumentVersionV1.model_validate(
                {**first.version.model_dump(mode="python"), "version_id": wire_id(9)}
            ),
        ),
    )
    for result in cases:
        assert result.decision == "conflict"
        assert result.reason_code
        assert wire_id(5) not in repr(result)
        assert wire_id(6) not in repr(result)


def test_tombstone_retains_current_history_and_returns_removal_intent_only() -> None:
    first = decide(parsed(), event_id=wire_id(2017))
    assert first.source is not None and first.version is not None
    before_source = first.source.model_dump(mode="json")
    before_version = first.version.model_dump(mode="json")

    deleted = decide_tombstone(
        first.source,
        first.version,
        trusted_org_id=ORG,
        trusted_vault_id=VAULT,
        tombstone_id=wire_id(3018),
        event_id=wire_id(2018),
        actor_id=ACTOR,
        deleted_at_ns=100,
    )

    assert deleted.decision == "tombstone"
    assert deleted.tombstone is not None
    assert deleted.tombstone.history_retained is True
    assert deleted.tombstone.vector_removal_intent is True
    assert deleted.tombstone.version_id == first.version.version_id
    assert deleted.event is not None
    assert deleted.event.deletion_tombstone is not None
    assert first.source.model_dump(mode="json") == before_source
    assert first.version.model_dump(mode="json") == before_version


def test_tombstone_wrong_tenant_and_invalid_time_fail_closed() -> None:
    first = decide(parsed(), event_id=wire_id(2019))
    assert first.source is not None and first.version is not None
    for tenant, deleted_at in ((wire_id(5), 100), (ORG, True)):
        try:
            value = decide_tombstone(
                first.source,
                first.version,
                trusted_org_id=tenant,
                trusted_vault_id=VAULT,
                tombstone_id="tombstone-invalid",
                event_id="event-invalid-delete",
                actor_id=ACTOR,
                deleted_at_ns=deleted_at,
            )
        except LineagePolicyError:
            continue
        assert value.decision == "conflict"
        assert value.tombstone is None


def test_deterministic_chunk_id_is_version_scoped_and_validates_sequence() -> None:
    first = decide(parsed(), event_id=wire_id(2020))
    second = decide(
        parsed(content="# Changed version", created_at_ns=20), event_id=wire_id(2021),
        current_source=first.source, current_version=first.version,
    )
    assert first.version is not None and second.version is not None
    first_id = deterministic_chunk_id(first.version.version_id, 7)
    assert first_id == deterministic_chunk_id(first.version.version_id, 7)
    assert first_id != deterministic_chunk_id(second.version.version_id, 7)
    assert first_id != deterministic_chunk_id(first.version.version_id, 8)
    for bad_sequence in (-1, True):
        with pytest.raises(LineagePolicyError):
            deterministic_chunk_id(first.version.version_id, bad_sequence)


def test_lineage_decisions_are_pure_issued_values_and_do_not_publish() -> None:
    source = parsed()
    before = source.model_dump(mode="json")
    first = decide(source, event_id=wire_id(2022))
    second = decide(source, event_id=wire_id(2022))

    assert require(first, "knowledge.lineage.v1") is first
    assert first == second
    assert first.event is not None and first.event.event_id == wire_id(2022)
    assert source.model_dump(mode="json") == before
    assert isinstance(first.event, LineageEventV1)
    assert isinstance(first.version, DocumentVersionV1)
    assert isinstance(first.source, VaultSourceV1)
    assert first.edge is None or isinstance(first.edge, LineageEdgeV1)
    assert first.tombstone is None or isinstance(first.tombstone, TombstoneV1)
