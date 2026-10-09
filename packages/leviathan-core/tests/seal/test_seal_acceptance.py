"""Independent adversarial acceptance for shared sealed issuance (ADR-0007)."""

from __future__ import annotations

import copy
import gc
import json
import pickle
import threading
import warnings
import weakref
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from itertools import count
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import BaseModel, PrivateAttr, create_model

from leviathan_core.seal import (
    MAX_DIGEST_NODES,
    Issuer,
    SealedModel,
    SealError,
    digest,
    require,
    verify,
)

FIXTURE = Path(__file__).parent / "fixtures" / "seal_acceptance.json"
_ISSUER_IDS = count()


class Child(SealedModel):
    text: str


class Record(SealedModel):
    value: int
    status: str
    tags: tuple[str, ...]
    child: Child


class LegacyTokenRecord(Record):
    _legacy_token: str = PrivateAttr(default="synthetic-private-token")


class EvidenceKind(Enum):
    TRADE = "trade"


@dataclass(frozen=True)
class FrozenEvidence:
    label: str
    amount: Decimal


def fixture_record() -> Record:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))["payload"]
    data["child"] = Child(**data["child"])
    data["tags"] = tuple(data["tags"])
    return Record(**data)


def new_issuer(purpose: str) -> Issuer:
    # Issuer tags are process-unique by contract; every test gets a fresh one.
    normalized = purpose.replace("-", "_")
    return Issuer(f"acceptance.{normalized}.{threading.get_ident()}.{next(_ISSUER_IDS)}")


def assert_code(error: SealError, expected: str) -> None:
    assert error.code == expected
    assert error.args == (expected,)
    assert str(error) == expected


def require_unissued(candidate: object, tag: str) -> None:
    assert not verify(candidate, tag)
    with pytest.raises(SealError) as caught:
        require(candidate, tag)
    assert_code(caught.value, "SEAL_NOT_ISSUED")


def assert_rejected_or_detected(mutation: Any, obj: Record, tag: str) -> None:
    try:
        mutation()
    except SealError as error:
        assert error.code in {"SEAL_FORBIDDEN_OPERATION", "SEAL_TAMPERED"}
        if error.code == "SEAL_TAMPERED":
            with pytest.raises(SealError) as caught:
                require(obj, tag)
            assert_code(caught.value, "SEAL_TAMPERED")
        else:
            assert require(obj, tag) is obj
        return
    with pytest.raises(SealError) as caught:
        require(obj, tag)
    assert_code(caught.value, "SEAL_TAMPERED")


def test_issue_binds_identity_content_and_issuer() -> None:
    issuer = new_issuer("basic")
    record = fixture_record()
    before = digest(record)
    assert len(before) == 64
    assert all(char in "0123456789abcdef" for char in before)
    assert issuer.issue(record) is record
    assert issuer.issued_here(record)
    assert verify(record, issuer.tag)
    assert require(record, issuer.tag) is record
    other_issuer = new_issuer("other")
    with pytest.raises(SealError) as caught:
        require(record, other_issuer.tag)
    assert_code(caught.value, "SEAL_WRONG_ISSUER")
    assert not verify(record, other_issuer.tag)


@pytest.mark.parametrize("tag", ["", "Upper", "9bad", "a" * 65, "bad-tag"])
def test_issuer_tag_grammar_is_closed(tag: str) -> None:
    with pytest.raises(SealError) as caught:
        Issuer(tag)
    assert_code(caught.value, "SEAL_INVALID_TAG")


def test_duplicate_issuer_tag_cannot_be_acquired_twice() -> None:
    issuer = new_issuer("duplicate")
    with pytest.raises(SealError) as caught:
        Issuer(issuer.tag)
    assert_code(caught.value, "SEAL_DUPLICATE_TAG")


def test_issuer_init_reentry_cannot_retag_or_squat_a_capability() -> None:
    issuer = new_issuer("init-reentry")
    proposed_tag = f"acceptance.reentry.{threading.get_ident()}.{next(_ISSUER_IDS)}"
    with pytest.raises(SealError) as caught:
        Issuer.__init__(issuer, proposed_tag)
    assert_code(caught.value, "SEAL_FORBIDDEN_OPERATION")

    target = fixture_record()
    assert issuer.issue(target) is target
    assert require(target, issuer.tag) is target
    with pytest.raises(SealError) as caught:
        Issuer.__init__(SimpleNamespace(), proposed_tag)  # type: ignore[arg-type]
    assert_code(caught.value, "SEAL_FORBIDDEN_OPERATION")

    # Failed re-entry must not reserve the proposed capability name.
    assert Issuer(proposed_tag).tag == proposed_tag


@pytest.mark.parametrize(
    ("initial", "replacement"),
    [
        (Decimal("1"), 1),
        (Decimal("1"), Decimal("1.00")),
    ],
    ids=["equal-value-int", "decimal-scale"],
)
def test_issued_seal_binds_primitive_type_and_decimal_scale(
    initial: Decimal, replacement: int | Decimal
) -> None:
    class AmountRecord(SealedModel):
        amount: Decimal

    issuer = new_issuer("primitive-shape")
    record = issuer.issue(AmountRecord(amount=initial))
    # Public canonical digests intentionally collapse these representations;
    # the private issuance binding must still detect their exact shape.
    if type(replacement) is Decimal:
        assert digest(initial) == digest(replacement)
    object.__getattribute__(record, "__dict__")["amount"] = replacement
    assert not verify(record, issuer.tag)
    with pytest.raises(SealError) as caught:
        require(record, issuer.tag)
    assert_code(caught.value, "SEAL_TAMPERED")


def test_caller_held_plain_nested_nodes_are_not_independently_issued() -> None:
    class PlainNode(BaseModel):
        label: str

    class Envelope(SealedModel):
        model_node: PlainNode
        dataclass_node: FrozenEvidence

    issuer = new_issuer("plain-nested-nodes")
    model_node = PlainNode(label="model")
    dataclass_node = FrozenEvidence("dataclass", Decimal("1"))
    root = issuer.issue(Envelope(model_node=model_node, dataclass_node=dataclass_node))
    root_ref = weakref.ref(root)

    require_unissued(model_node, issuer.tag)
    require_unissued(dataclass_node, issuer.tag)
    del root
    gc.collect()
    assert root_ref() is None
    # Caller-held children remain ordinary values after their former root dies.
    require_unissued(model_node, issuer.tag)
    require_unissued(dataclass_node, issuer.tag)


def test_forged_issuer_objects_cannot_issue_claimed_or_unclaimed_tags() -> None:
    claimed_issuer = new_issuer("forgery-target")
    unclaimed_tag = f"future.kernel.{next(_ISSUER_IDS)}"
    violations: list[str] = []

    for tag in (claimed_issuer.tag, unclaimed_tag):
        forged_issuers: tuple[tuple[str, object], ...] = (
            ("SimpleNamespace", SimpleNamespace(tag=tag)),
            ("bare-object-new", object.__new__(Issuer)),
        )
        forged_real_type = object.__new__(Issuer)
        object.__setattr__(forged_real_type, "_tag", tag)
        forged_issuers += (("object-new-with-tag", forged_real_type),)

        for forge_kind, forged in forged_issuers:
            if forge_kind == "bare-object-new":
                # Give the uninitialized instance the tag through the same
                # low-level route available to in-process callers.
                object.__setattr__(forged, "_tag", tag)
            target = fixture_record()
            try:
                result = Issuer.issue(forged, target)  # type: ignore[arg-type]
            except SealError as error:
                if error.code not in {"SEAL_FORBIDDEN_OPERATION", "SEAL_INVALID_MODEL"}:
                    violations.append(f"{forge_kind}/{tag}: unexpected code {error.code}")
            else:
                if result is not target or verify(target, tag):
                    violations.append(f"{forge_kind}/{tag}: forged issue was accepted")
                try:
                    require(target, tag)
                except SealError:
                    pass
                else:
                    violations.append(f"{forge_kind}/{tag}: require accepted forged issue")
            if verify(target, tag):
                violations.append(f"{forge_kind}/{tag}: verify accepted forged issue")
    assert not violations, "; ".join(violations)


def test_revalidated_public_copies_never_inherit_issuance() -> None:
    issuer = new_issuer("copy")
    record = issuer.issue(fixture_record())

    copied = record.model_copy(update={"value": 2})
    validated = type(record).model_validate(record)
    assert copied.value == 2
    assert validated == record
    require_unissued(copied, issuer.tag)
    require_unissued(validated, issuer.tag)
    assert require(record, issuer.tag) is record


def test_str_subclass_relabel_and_replace_copy_do_not_borrow_issuance() -> None:
    class Relabel(str):
        pass

    issuer = new_issuer("relabel")
    record = issuer.issue(fixture_record())
    assert not verify(record, Relabel(issuer.tag))
    with pytest.raises(SealError) as caught:
        require(record, Relabel(issuer.tag))
    assert_code(caught.value, "SEAL_WRONG_ISSUER")

    candidate = record.model_copy(update={"status": Relabel("UNTRUSTED")})
    require_unissued(candidate, issuer.tag)
    assert require(record, issuer.tag) is record


def test_gex_copied_seal_value_is_not_an_issuance_token() -> None:
    issuer = new_issuer("gex-token")
    issued = issuer.issue(fixture_record())
    copied = getattr(issued, "_seal", None)

    candidates: list[object] = []
    with suppress(SealError, TypeError, ValueError):
        fields = issued.model_dump()
        fields["child"] = Child(**fields["child"])
        candidates.append(type(issued)(**fields, _seal=copied))
    with suppress(SealError, TypeError, ValueError):
        candidates.append(issued.model_copy(update={"_seal": copied}))

    for candidate in candidates:
        require_unissued(candidate, issuer.tag)
    assert require(issued, issuer.tag) is issued


def test_mcp_private_attribute_token_copy_does_not_transfer_issuance() -> None:
    issuer = new_issuer("mcp-token")
    record = fixture_record()
    issued = issuer.issue(
        LegacyTokenRecord(
            value=record.value,
            status=record.status,
            tags=record.tags,
            child=record.child,
        )
    )
    private = issued.__pydantic_private__ or {}
    copied_token = private.get("_legacy_token")
    assert copied_token == "synthetic-private-token"

    try:
        candidate = issued.model_copy(update={"_legacy_token": copied_token})
    except (SealError, TypeError, ValueError):
        candidate = None
    if candidate is not None:
        require_unissued(candidate, issuer.tag)

    validated = type(issued).model_validate(issued)
    require_unissued(validated, issuer.tag)
    assert require(issued, issuer.tag) is issued


def test_equal_twins_and_gc_never_transfer_or_remove_survivor_issuance() -> None:
    issuer = new_issuer("equal-twins")
    survivor = issuer.issue(fixture_record())
    twin = type(survivor).model_validate(survivor)
    assert twin == survivor
    assert twin is not survivor
    require_unissued(twin, issuer.tag)

    twin_ref = weakref.ref(twin)
    del twin
    gc.collect()
    assert twin_ref() is None
    assert issuer.issued_here(survivor)
    assert require(survivor, issuer.tag) is survivor


def test_same_named_class_swap_invalidates_registered_type_identity() -> None:
    class NamedRecord(SealedModel):
        value: int

    twin_type = type(
        "NamedRecord",
        (SealedModel,),
        {
            "__module__": NamedRecord.__module__,
            "__qualname__": NamedRecord.__qualname__,
            "__annotations__": {"value": int},
        },
    )
    issuer = new_issuer("class-swap")
    record = issuer.issue(NamedRecord(value=7))
    assert twin_type is not NamedRecord
    object.__setattr__(record, "__class__", twin_type)

    assert not verify(record, issuer.tag)
    with pytest.raises(SealError) as caught:
        require(record, issuer.tag)
    assert_code(caught.value, "SEAL_TAMPERED")
    with pytest.raises(SealError) as caught:
        digest(record)
    assert_code(caught.value, "SEAL_TAMPERED")


def test_nested_same_named_class_swap_invalidates_parent_digest() -> None:
    class NestedTags(SealedModel):
        tags: tuple[str, ...]

    class Envelope(SealedModel):
        child: NestedTags

    def hostile_getattribute(self: object, name: str) -> Any:
        if name == "tags":
            return ("CANARY-NESTED-CLASS-SWAP",)
        return BaseModel.__getattribute__(self, name)

    def hostile_model_dump(self: object, **kwargs: Any) -> dict[str, Any]:
        return {"tags": ["CANARY-NESTED-CLASS-SWAP"]}

    twin_type = type(
        "NestedTags",
        (SealedModel,),
        {
            "__module__": NestedTags.__module__,
            "__qualname__": NestedTags.__qualname__,
            "__annotations__": {"tags": tuple[str, ...]},
            "__getattribute__": hostile_getattribute,
            "model_dump": hostile_model_dump,
        },
    )
    issuer = new_issuer("nested-class-swap")
    outer = issuer.issue(Envelope(child=NestedTags(tags=("safe",))))
    object.__setattr__(outer.child, "__class__", twin_type)

    assert not verify(outer, issuer.tag)
    with pytest.raises(SealError) as caught:
        require(outer, issuer.tag)
    assert_code(caught.value, "SEAL_TAMPERED")


def test_same_named_frozen_dataclass_swap_invalidates_issued_value() -> None:
    @dataclass(frozen=True)
    class InnerEvidence:
        value: str

    @dataclass(frozen=True)
    class EvidenceBox:
        inner: InnerEvidence

    @dataclass(frozen=True)
    class InnerTwin:
        value: str

    InnerTwin.__name__ = InnerEvidence.__name__
    InnerTwin.__qualname__ = InnerEvidence.__qualname__
    InnerTwin.__module__ = InnerEvidence.__module__
    issuer = new_issuer("dataclass-class-swap")
    box = issuer.issue(EvidenceBox(InnerEvidence("safe")))
    object.__setattr__(box.inner, "__class__", InnerTwin)

    assert not verify(box, issuer.tag)
    with pytest.raises(SealError) as caught:
        require(box, issuer.tag)
    assert_code(caught.value, "SEAL_TAMPERED")


def test_container_type_swap_and_lying_tuple_subclass_are_detected() -> None:
    issuer = new_issuer("container-types")
    record = issuer.issue(fixture_record())
    raw = object.__getattribute__(record, "__dict__")
    raw["tags"] = ["alpha", "beta"]
    with pytest.raises(SealError) as caught:
        require(record, issuer.tag)
    assert_code(caught.value, "SEAL_TAMPERED")
    raw["tags"].append("CANARY-APPENDED")
    with pytest.raises(SealError) as caught:
        require(record, issuer.tag)
    assert_code(caught.value, "SEAL_TAMPERED")

    class LyingTuple(tuple[str, ...]):
        def __getitem__(self, index: Any) -> str:
            return "CANARY-LYING-TUPLE"

    another = issuer.issue(fixture_record())
    object.__getattribute__(another, "__dict__")["tags"] = LyingTuple(
        ("alpha", "beta")
    )
    assert another.tags[0] == "CANARY-LYING-TUPLE"
    with pytest.raises(SealError) as caught:
        require(another, issuer.tag)
    assert_code(caught.value, "SEAL_TAMPERED")


def test_set_and_frozenset_substitution_is_detected() -> None:
    class SetRecord(SealedModel):
        labels: frozenset[str]

    issuer = new_issuer("set-types")
    record = issuer.issue(SetRecord(labels=frozenset({"a", "b"})))
    object.__getattribute__(record, "__dict__")["labels"] = {"a", "b"}
    with pytest.raises(SealError) as caught:
        require(record, issuer.tag)
    assert_code(caught.value, "SEAL_TAMPERED")

    class LyingSet(set[str]):
        def __iter__(self):
            return iter(("CANARY-LYING-SET",))

    another = issuer.issue(SetRecord(labels=frozenset({"a", "b"})))
    object.__getattribute__(another, "__dict__")["labels"] = LyingSet({"a", "b"})
    with pytest.raises(SealError) as caught:
        require(another, issuer.tag)
    assert_code(caught.value, "SEAL_TAMPERED")


def test_nested_mutation_is_blocked_on_direct_export_without_warning_leaks(
    capsys: pytest.CaptureFixture[str],
) -> None:
    class TagsChild(SealedModel):
        tags: tuple[str, ...]

    class TagsEnvelope(SealedModel):
        child: TagsChild

    issuer = new_issuer("nested-export")
    child = TagsChild(tags=("safe",))
    outer = issuer.issue(TagsEnvelope(child=child))
    assert verify(outer.child, issuer.tag)
    assert require(outer.child, issuer.tag) is outer.child

    canary = "CANARY-NESTED-SERIALIZER-7a31"
    object.__getattribute__(outer.child, "__dict__")["tags"] = ["safe", canary]
    export_error: SealError | None = None
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always")
        try:
            outer.child.model_dump()
        except SealError as error:
            export_error = error
    assert all(canary not in str(item.message) for item in seen)
    captured = capsys.readouterr()
    assert canary not in captured.out
    assert canary not in captured.err
    assert export_error is not None, "direct nested export returned mutated data"
    assert_code(export_error, "SEAL_TAMPERED")
    assert canary not in repr(export_error)


def test_nested_fields_set_tamper_fails_direct_export() -> None:
    class FieldsChild(SealedModel):
        value: str

    class FieldsEnvelope(SealedModel):
        child: FieldsChild

    issuer = new_issuer("nested-fields-set")
    outer = issuer.issue(FieldsEnvelope(child=FieldsChild(value="safe")))
    assert verify(outer.child, issuer.tag)
    assert require(outer.child, issuer.tag) is outer.child
    object.__getattribute__(outer.child, "__pydantic_fields_set__").clear()
    with pytest.raises(SealError) as caught:
        outer.child.model_dump(exclude_unset=True)
    assert_code(caught.value, "SEAL_TAMPERED")


def test_nested_model_is_issued_and_requires_integrity_at_direct_use() -> None:
    class DirectChild(SealedModel):
        value: str

    class DirectEnvelope(SealedModel):
        child: DirectChild

    issuer = new_issuer("nested-direct-use")
    outer = issuer.issue(DirectEnvelope(child=DirectChild(value="safe")))
    assert verify(outer.child, issuer.tag)
    assert require(outer.child, issuer.tag) is outer.child
    object.__getattribute__(outer.child, "__dict__")["value"] = "CANARY-DIRECT-CHILD"
    assert not verify(outer.child, issuer.tag)
    with pytest.raises(SealError) as caught:
        require(outer.child, issuer.tag)
    assert_code(caught.value, "SEAL_TAMPERED")


def test_instance_dict_cannot_shadow_issued_export_guard(
    capsys: pytest.CaptureFixture[str],
) -> None:
    issuer = new_issuer("guard-shadow")
    record = issuer.issue(fixture_record())
    raw = record.__dict__
    canary = "CANARY-GUARD-SHADOW"
    failures: list[str] = []
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always")
        try:
            raw["_require_if_issued"] = lambda: None
            raw["value"] = canary
        except (SealError, TypeError):
            assert require(record, issuer.tag) is record
            assert record.value == 1
        else:
            if verify(record, issuer.tag):
                # A defensive read-only/copying __dict__ is safe if writes did
                # not reach the sealed object's real state.
                assert record.value == 1
                assert record.model_dump()["value"] == 1
            else:
                for export in (
                    record.model_dump,
                    record.model_dump_json,
                    record.model_copy,
                ):
                    try:
                        export()
                    except SealError as error:
                        if error.code != "SEAL_TAMPERED":
                            failures.append(f"export raised unexpected {error.code}")
                    else:
                        failures.append("issued export bypassed tamper guard")
    assert all(canary not in str(item.message) for item in seen)
    captured = capsys.readouterr()
    assert canary not in captured.out
    assert canary not in captured.err
    assert not failures, "; ".join(failures)


def test_class_level_guard_override_cannot_shadow_export_verification() -> None:
    try:
        class ClassOverrideRecord(SealedModel):
            value: int

            def _require_if_issued(self) -> None:
                return None
    except (SealError, TypeError) as error:
        if isinstance(error, SealError):
            assert error.code in {"SEAL_FORBIDDEN_OPERATION", "SEAL_INVALID_MODEL"}
        return

    issuer = new_issuer("class-guard-override")
    record = issuer.issue(ClassOverrideRecord(value=1))
    object.__setattr__(record, "value", 100)
    with pytest.raises(SealError) as caught:
        record.model_dump()
    assert_code(caught.value, "SEAL_TAMPERED")


def test_output_affecting_extra_slot_state_is_rejected_or_digest_bound() -> None:
    try:
        class SlottedRecord(SealedModel):
            __slots__ = ("_actions",)
            value: str
    except (SealError, TypeError) as error:
        if isinstance(error, SealError):
            assert error.code in {"SEAL_FORBIDDEN_OPERATION", "SEAL_INVALID_MODEL"}
        return

    record = SlottedRecord(value="safe")
    object.__setattr__(record, "_actions", {"k": 1})
    issuer = new_issuer("slot-state")
    issuer.issue(record)
    record._actions["k"] = 2
    with pytest.raises(SealError) as caught:
        require(record, issuer.tag)
    assert_code(caught.value, "SEAL_TAMPERED")


def test_output_affecting_private_cache_is_digest_bound() -> None:
    class CachedRecord(SealedModel):
        value: str
        _cache: dict[str, int] = PrivateAttr(default_factory=lambda: {"k": 1})

        def render(self) -> tuple[str, int]:
            return self.value, self._cache["k"]

    issuer = new_issuer("private-cache")
    record = CachedRecord(value="safe")
    issuer.issue(record)
    assert record.render() == ("safe", 1)
    record._cache["k"] = 2
    with pytest.raises(SealError) as caught:
        require(record, issuer.tag)
    assert_code(caught.value, "SEAL_TAMPERED")


def test_reused_object_id_after_gc_does_not_inherit_registry_entry() -> None:
    class IdentityProbe(SealedModel):
        value: int

    issuer = new_issuer("id-reuse")
    recycled = 0
    for index in range(5_000):
        original = issuer.issue(IdentityProbe(value=index))
        original_id = id(original)
        del original
        candidate = IdentityProbe(value=index)
        if id(candidate) == original_id:
            recycled += 1
            assert not verify(candidate, issuer.tag)
            with pytest.raises(SealError) as caught:
                require(candidate, issuer.tag)
            assert_code(caught.value, "SEAL_NOT_ISSUED")
        del candidate
    assert recycled > 0, "identity allocator did not recycle ids in the tight loop"


def test_eight_thread_issue_and_verify_are_consistent() -> None:
    issuer = new_issuer("threads")
    record = fixture_record()
    barrier = threading.Barrier(8)
    outcomes: list[tuple[str, bool]] = []
    outcomes_lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        try:
            issuer.issue(record)
            result = "issued"
        except SealError as error:
            result = error.code
        with outcomes_lock:
            outcomes.append((result, verify(record, issuer.tag)))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sum(outcome == "issued" for outcome, _ in outcomes) == 1
    assert sum(outcome == "SEAL_ALREADY_ISSUED" for outcome, _ in outcomes) == 7
    assert all(valid for _, valid in outcomes)
    assert issuer.issued_here(record)


def test_reissuing_same_object_is_rejected() -> None:
    issuer = new_issuer("double-issue")
    record = issuer.issue(fixture_record())
    with pytest.raises(SealError) as caught:
        issuer.issue(record)
    assert_code(caught.value, "SEAL_ALREADY_ISSUED")


def test_reinit_with_changed_value_is_blocked_or_detected() -> None:
    issuer = new_issuer("reinit")
    record = issuer.issue(fixture_record())
    original = digest(record)
    assert_rejected_or_detected(
        lambda: BaseModel.__init__(
            record,
            value=100,
            status=record.status,
            tags=record.tags,
            child=record.child,
        ),
        record,
        issuer.tag,
    )
    if verify(record, issuer.tag):
        assert digest(record) == original


def test_reinit_with_copied_seal_value_is_never_a_capability() -> None:
    issuer = new_issuer("reinit-seal")
    record = issuer.issue(fixture_record())
    copied = getattr(record, "_seal", None)
    assert_rejected_or_detected(
        lambda: BaseModel.__init__(
            record,
            value=100,
            status=record.status,
            tags=record.tags,
            child=record.child,
            _seal=copied,
        ),
        record,
        issuer.tag,
    )


def test_object_setattr_mutation_fails_at_next_require_or_export() -> None:
    issuer = new_issuer("object-setattr")
    record = issuer.issue(fixture_record())
    assert_rejected_or_detected(
        lambda: object.__setattr__(record, "value", 100), record, issuer.tag
    )
    if not verify(record, issuer.tag):
        with pytest.raises(SealError) as caught:
            record.model_dump_json()
        assert_code(caught.value, "SEAL_TAMPERED")


def test_base_model_setstate_fails_at_next_use() -> None:
    issuer = new_issuer("setstate")
    record = issuer.issue(fixture_record())
    state = record.__getstate__()
    changed = dict(state)
    changed["__dict__"] = dict(state.get("__dict__", {}), value=100)
    assert_rejected_or_detected(
        lambda: BaseModel.__setstate__(record, changed), record, issuer.tag
    )


@pytest.mark.parametrize("field", ["status", "tags"])
def test_live_dict_item_mutation_fails_closed(field: str) -> None:
    issuer = new_issuer(f"dict-{field}")
    record = issuer.issue(fixture_record())
    raw = object.__getattribute__(record, "__dict__")
    changed = "HALTED" if field == "status" else ("evil",)
    assert_rejected_or_detected(
        lambda: raw.__setitem__(field, changed), record, issuer.tag
    )


def test_nested_text_dict_mutation_fails_closed() -> None:
    issuer = new_issuer("nested-dict")
    record = issuer.issue(fixture_record())
    raw = object.__getattribute__(record.child, "__dict__")
    assert_rejected_or_detected(
        lambda: raw.__setitem__("text", "SEAL-CONTENT-CANARY-8f24c1"),
        record,
        issuer.tag,
    )


def test_live_dict_replacement_fails_closed() -> None:
    issuer = new_issuer("dict-replacement")
    record = issuer.issue(fixture_record())
    replacement = {
        "value": 100,
        "status": record.status,
        "tags": record.tags,
        "child": record.child,
    }
    assert_rejected_or_detected(
        lambda: object.__setattr__(record, "__dict__", replacement),
        record,
        issuer.tag,
    )


def test_legacy_base_model_copy_update_is_blocked_or_detected() -> None:
    issuer = new_issuer("legacy-copy")
    record = issuer.issue(fixture_record())
    try:
        candidate = BaseModel.copy(record, update={"value": 100})
    except SealError as error:
        assert_code(error, "SEAL_FORBIDDEN_OPERATION")
    else:
        require_unissued(candidate, issuer.tag)
        assert require(record, issuer.tag) is record


@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_copy_deepcopy_and_pickle_are_blocked(operation: Any) -> None:
    issuer = new_issuer("copy-block")
    record = issuer.issue(fixture_record())
    with pytest.raises(SealError) as caught:
        operation(record)
    assert_code(caught.value, "SEAL_FORBIDDEN_OPERATION")
    assert require(record, issuer.tag) is record


def test_model_construct_is_blocked() -> None:
    with pytest.raises(SealError) as caught:
        Record.model_construct(value=1, status="READY", tags=(), child=Child(text="x"))
    assert_code(caught.value, "SEAL_FORBIDDEN_OPERATION")


def test_digest_is_canonical_for_mapping_decimal_enum_time_and_frozen_dataclass() -> None:
    left = {
        "amount": Decimal("0.50"),
        "nested": {"b": 2, "a": 1},
        "when": datetime(2026, 10, 5, tzinfo=UTC),
        "day": date(2026, 10, 5),
        "evidence": FrozenEvidence("fixture", Decimal("1.0")),
        "kind": EvidenceKind.TRADE,
    }
    right = {
        "evidence": FrozenEvidence("fixture", Decimal("1.00")),
        "day": date(2026, 10, 5),
        "when": datetime(2026, 10, 5, tzinfo=timezone(timedelta(0))),
        "nested": {"a": 1, "b": 2},
        "amount": Decimal("0.5"),
        "kind": EvidenceKind.TRADE,
    }
    assert digest(left) == digest(right)
    assert digest(frozenset({"b", "a"})) == digest(frozenset({"a", "b"}))
    assert digest(fixture_record()) == digest(fixture_record())


@pytest.mark.parametrize(
    "value",
    [
        1.25,
        b"bytes",
        object(),
        datetime(2026, 10, 5),
        {1: "non-string mapping key"},
    ],
)
def test_digest_rejects_values_outside_closed_domain(value: object) -> None:
    with pytest.raises(SealError) as caught:
        digest(value)
    assert_code(caught.value, "SEAL_UNSUPPORTED_TYPE")


def test_digest_node_limit_is_checked_before_container_expansion() -> None:
    class HugeMapping(dict[str, int]):
        expanded = 0

        def __len__(self) -> int:
            return MAX_DIGEST_NODES + 1

        def __iter__(self):
            self.expanded += 1
            return super().__iter__()

        def __getitem__(self, key: str) -> int:
            self.expanded += 1
            return super().__getitem__(key)

    huge = HugeMapping({"sentinel": 1})
    with pytest.raises(SealError) as caught:
        digest(huge)
    assert_code(caught.value, "SEAL_DIGEST_LIMIT")
    assert huge.expanded == 0

    assert digest(tuple(range(MAX_DIGEST_NODES - 1)))
    with pytest.raises(SealError) as caught:
        digest(tuple(range(MAX_DIGEST_NODES)))
    assert_code(caught.value, "SEAL_DIGEST_LIMIT")


def test_thousand_field_model_has_deterministic_bounded_digest_cost() -> None:
    field_count = 1_000
    wide_model = create_model(
        "WideAcceptanceRecord",
        __base__=SealedModel,
        **{f"field_{index:04d}": (int, ...) for index in range(field_count)},
    )
    value = wide_model(**{f"field_{index:04d}": index for index in range(field_count)})
    issuer = new_issuer("wide-model")
    assert issuer.issue(value) is value
    assert verify(value, issuer.tag)
    assert issuer.issued_here(value)
    assert len(digest(value)) == 64


def _exception_chain(error: BaseException) -> list[str]:
    messages: list[str] = []
    seen: set[int] = set()
    pending = [error]
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        messages.append(str(current))
        messages.append(repr(current))
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return messages


def test_validation_errors_are_content_free_including_chains() -> None:
    marker = json.loads(FIXTURE.read_text(encoding="utf-8"))["content_free_canary"]
    with pytest.raises(SealError) as caught:
        Record(value=marker, status="READY", tags=("ok",), child=Child(text="safe"))
    assert_code(caught.value, "SEAL_INVALID_MODEL")
    assert all(marker not in message for message in _exception_chain(caught.value))
    assert all(marker not in repr(item) for item in caught.value.args)


def test_assignment_and_delete_errors_echo_only_code() -> None:
    record = fixture_record()
    for action in (
        lambda: setattr(record, "status", "SEAL-CONTENT-CANARY-8f24c1"),
        lambda: delattr(record, "status"),
    ):
        with pytest.raises(SealError) as caught:
            action()
        assert_code(caught.value, "SEAL_FORBIDDEN_OPERATION")
