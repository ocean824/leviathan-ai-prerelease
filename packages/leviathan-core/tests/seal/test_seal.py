"""Writer regressions for the shared issuance boundary."""

from __future__ import annotations

import copy
import gc
import pickle
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum

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
from leviathan_core.seal._registry import _ISSUED
from leviathan_core.seal.digest import _tree_and_count


class Child(SealedModel):
    text: str


class Record(SealedModel):
    status: str
    amount: Decimal
    child: Child
    tags: tuple[str, ...]


class PrivateRecord(SealedModel):
    status: str
    _token: str = PrivateAttr(default="local-token")


def _record(status: str = "READY") -> Record:
    return Record(
        status=status,
        amount=Decimal("0.50"),
        child=Child(text="nested"),
        tags=("a", "b"),
    )


def _assert_code(action: object, code: str) -> None:
    with pytest.raises(SealError) as caught:
        action()  # type: ignore[operator]
    assert caught.value.code == code
    assert caught.value.args == (code,)
    assert str(caught.value) == code
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_identity_tag_and_equal_twins_survive_gc() -> None:
    issuer = Issuer("seal.test.twins")
    first, second = _record(), _record()
    assert first == second and first is not second
    assert issuer.issue(first) is first
    # Simulate a stale registry slot at a reused id without relying on the
    # allocator to recycle one during this test run.
    _ISSUED[id(second)] = _ISSUED[id(first)]
    try:
        assert not verify(second, issuer.tag)
        _assert_code(lambda: require(second, issuer.tag), "SEAL_NOT_ISSUED")
    finally:
        del _ISSUED[id(second)]
    assert issuer.issue(second) is second
    assert issuer.issued_here(first) and issuer.issued_here(second)
    assert require(first, issuer.tag) is first
    _assert_code(lambda value=first: issuer.issue(value), "SEAL_ALREADY_ISSUED")
    _assert_code(lambda: require(second, "other.tag"), "SEAL_WRONG_ISSUER")
    _assert_code(lambda: Issuer(issuer.tag), "SEAL_DUPLICATE_TAG")
    _assert_code(lambda: Issuer("bad-tag"), "SEAL_INVALID_TAG")
    assert not verify(_record(), issuer.tag)
    doomed_identity = id(first)
    del first
    gc.collect()
    assert issuer.issued_here(second)
    # Finalize retires the old identity; a later reused id cannot borrow it.
    assert doomed_identity not in _ISSUED
    assert not verify(_record(), issuer.tag)


def test_digest_canonical_domain_and_node_budget() -> None:
    assert digest({"b": Decimal("0.50"), "a": 1}) == digest(
        {"a": 1, "b": Decimal("0.5")}
    )
    assert digest({3, 1, 2}) == digest({2, 3, 1})
    assert len(digest({"at": datetime(2026, 1, 1, tzinfo=UTC)})) == 64

    class Flag(StrEnum):
        OK = "OK"

    @dataclass(frozen=True)
    class Frozen:
        state: Flag
        date: datetime

    assert len(digest(Frozen(Flag.OK, datetime(2026, 1, 1, tzinfo=UTC)))) == 64
    for value in (1.0, b"bytes", object(), datetime(2026, 1, 1)):
        _assert_code(lambda value=value: digest(value), "SEAL_UNSUPPORTED_TYPE")
    _assert_code(lambda: digest([0] * MAX_DIGEST_NODES), "SEAL_DIGEST_LIMIT")
    nested: object = None
    for _ in range(130):
        nested = [nested]
    _assert_code(lambda: digest(nested), "SEAL_DIGEST_LIMIT")


def test_reinitialization_and_raw_mutation_fail_closed() -> None:
    issuer = Issuer("seal.test.tamper")
    record = issuer.issue(_record())
    _assert_code(
        lambda: BaseModel.__init__(
            record, status="CHANGED", amount=Decimal("0.5"),
            child=Child(text="nested"), tags=("a", "b")
        ),
        "SEAL_FORBIDDEN_OPERATION",
    )
    _assert_code(lambda: record.__setstate__({"__dict__": {"status": "CHANGED"}}),
                 "SEAL_FORBIDDEN_OPERATION")
    record.__dict__["status"] = "CHANGED"
    assert not verify(record, issuer.tag)
    _assert_code(lambda: require(record, issuer.tag), "SEAL_TAMPERED")
    _assert_code(lambda: digest(record), "SEAL_TAMPERED")
    _assert_code(record.model_dump, "SEAL_TAMPERED")
    _assert_code(record.model_dump_json, "SEAL_TAMPERED")
    _assert_code(lambda: BaseModel.model_dump(record), "SEAL_TAMPERED")

    other = issuer.issue(_record())
    object.__setattr__(other, "status", "CHANGED")
    _assert_code(lambda: require(other, issuer.tag), "SEAL_TAMPERED")


def test_nested_mutation_and_base_setstate_are_detected() -> None:
    issuer = Issuer("seal.test.nested")
    record = issuer.issue(_record())
    record.child.__dict__["text"] = "changed"
    _assert_code(lambda: require(record, issuer.tag), "SEAL_TAMPERED")
    another = issuer.issue(_record())
    # Cycle 8: the base __setstate__ is refused before any state changes.
    _assert_code(lambda: BaseModel.__setstate__(another, {
        "__pydantic_fields_set__": {"status"},
        "__pydantic_extra__": None,
        "__pydantic_private__": None,
        "__dict__": {"status": "changed"},
    }), "SEAL_FORBIDDEN_OPERATION")
    assert require(another, issuer.tag) is another


def test_same_named_class_swap_cannot_preserve_issuance() -> None:
    class Named(SealedModel):
        value: int

    twin_type = type(
        "Named", (SealedModel,),
        {"__module__": Named.__module__, "__qualname__": Named.__qualname__,
         "__annotations__": {"value": int}},
    )
    issuer = Issuer("seal.test.class_swap")
    record = issuer.issue(Named(value=1))
    assert twin_type is not Named
    object.__setattr__(record, "__class__", twin_type)
    assert not verify(record, issuer.tag)
    _assert_code(lambda: require(record, issuer.tag), "SEAL_TAMPERED")
    _assert_code(lambda: digest(record), "SEAL_TAMPERED")


def test_copy_validate_construct_and_copied_tokens_do_not_issue() -> None:
    issuer = Issuer("seal.test.copy")
    record = issuer.issue(_record())
    clone = record.model_copy()
    assert clone == record and clone is not record
    _assert_code(lambda: require(clone, issuer.tag), "SEAL_NOT_ISSUED")
    checked = Record.model_validate(record)
    assert checked == record and checked is not record
    _assert_code(lambda: require(checked, issuer.tag), "SEAL_NOT_ISSUED")
    _assert_code(lambda: record.model_copy(update={"status": 1}), "SEAL_INVALID_MODEL")
    _assert_code(lambda: Record.model_construct(status="READY"), "SEAL_FORBIDDEN_OPERATION")
    _assert_code(lambda: record.copy(update={"status": "CHANGED"}), "SEAL_FORBIDDEN_OPERATION")
    _assert_code(lambda: copy.copy(record), "SEAL_FORBIDDEN_OPERATION")
    _assert_code(lambda: copy.deepcopy(record), "SEAL_FORBIDDEN_OPERATION")
    _assert_code(lambda: pickle.dumps(record), "SEAL_FORBIDDEN_OPERATION")
    _assert_code(
        lambda: Record(
            status="READY", amount=Decimal("0.5"), child=Child(text="nested"),
            tags=("a", "b"), _seal=getattr(record, "_seal", None)
        ),
        "SEAL_INVALID_MODEL",
    )

    private = issuer.issue(PrivateRecord(status="READY"))
    token = private.__pydantic_private__["_token"]
    _assert_code(
        lambda: private.model_copy(update={"_token": token}),
        "SEAL_INVALID_MODEL",
    )
    assert not verify(PrivateRecord(status="READY"), issuer.tag)


def test_assignment_deletion_and_validation_errors_are_content_free() -> None:
    canary = "SECRET_CANARY_6152"
    record = _record()
    for action in (
        lambda: setattr(record, "status", canary),
        lambda: delattr(record, "status"),
        lambda: setattr(record, "__dict__", {"status": canary}),
        lambda: Record.model_validate({"status": canary, "amount": object()}),
    ):
        with pytest.raises(SealError) as caught:
            action()
        error = caught.value
        assert canary not in repr(error)
        assert canary not in str(error)
        assert canary not in repr(error.args)
        assert error.__cause__ is None
        assert error.__context__ is None


def test_concurrent_issue_verify_and_linear_node_count() -> None:
    issuer = Issuer("seal.test.threads")
    records = [_record(str(i)) for i in range(64)]

    def worker(record: Record) -> bool:
        issuer.issue(record)
        return verify(record, issuer.tag) and require(record, issuer.tag) is record

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert all(pool.map(worker, records))
    assert all(issuer.issued_here(record) for record in records)

    wide_type = create_model(
        "Wide", __base__=SealedModel,
        **{f"f{i}": (int, i) for i in range(1_000)},
    )
    wide = wide_type()
    _, count = _tree_and_count(wide)
    assert count == 1_005
    assert len(digest(wide)) == 64


# Cycle 1 regressions: one per SEAL-001 cycle 0 review reproduction.


def test_forged_issuer_routes_cannot_issue() -> None:
    import types

    legit = Issuer("seal.test.forge")
    claimed = _record()
    _assert_code(lambda: Issuer.issue(types.SimpleNamespace(tag=legit.tag), claimed),  # type: ignore[arg-type]
                 "SEAL_FORBIDDEN_OPERATION")
    raw = object.__new__(Issuer)
    object.__setattr__(raw, "_tag", legit.tag)
    _assert_code(lambda: raw.issue(claimed), "SEAL_FORBIDDEN_OPERATION")
    unclaimed = object.__new__(Issuer)
    object.__setattr__(unclaimed, "_tag", "seal.test.future")
    _assert_code(lambda: unclaimed.issue(claimed), "SEAL_FORBIDDEN_OPERATION")
    assert not verify(claimed, legit.tag)
    assert not verify(claimed, "seal.test.future")


def test_nested_model_and_dataclass_class_swaps_are_tampering() -> None:
    issuer = Issuer("seal.test.nested.swap")
    record = issuer.issue(_record())
    twin = type("Child", (SealedModel,), {
        "__module__": Child.__module__, "__qualname__": Child.__qualname__,
        "__annotations__": {"text": str},
    })
    object.__setattr__(record.child, "__class__", twin)
    _assert_code(lambda: require(record, issuer.tag), "SEAL_TAMPERED")

    @dataclass(frozen=True)
    class Inner:
        v: str

    @dataclass(frozen=True)
    class Box:
        inner: Inner

    inner_twin = dataclass(frozen=True)(type("Inner", (), {
        "__module__": Inner.__module__, "__qualname__": Inner.__qualname__,
        "__annotations__": {"v": str},
    }))
    box = issuer.issue(Box(Inner("safe")))
    object.__setattr__(box.inner, "__class__", inner_twin)
    assert not verify(box, issuer.tag)


def test_container_kind_swaps_and_lying_subclasses_are_rejected() -> None:
    issuer = Issuer("seal.test.containers")

    class LyingTuple(tuple):  # type: ignore[type-arg]
        def __getitem__(self, i: object) -> str:  # type: ignore[override]
            return "CANARY-EVIL"

    for replacement in (["a", "b"], LyingTuple(("a", "b"))):
        record = issuer.issue(_record())
        object.__getattribute__(record, "__dict__")["tags"] = replacement
        _assert_code(lambda record=record: require(record, issuer.tag), "SEAL_TAMPERED")
    assert digest(("a",)) != digest(["a"])
    assert digest(frozenset({"a"})) != digest({"a"})
    _assert_code(lambda: digest(LyingTuple(("a",))), "SEAL_UNSUPPORTED_TYPE")


def test_instance_dict_cannot_shadow_export_guard() -> None:
    issuer = Issuer("seal.test.shadow")
    record = issuer.issue(_record())
    raw = record.__dict__
    raw["_require_if_issued"] = lambda: None
    raw["model_dump"] = lambda **_: {"status": "CANARY"}
    raw["status"] = "CANARY-TAMPERED"
    _assert_code(lambda: record.model_dump(), "SEAL_TAMPERED")
    _assert_code(record.model_dump_json, "SEAL_TAMPERED")
    _assert_code(record.model_copy, "SEAL_TAMPERED")


def test_nested_values_are_issued_and_export_checked_without_warnings() -> None:
    import warnings

    issuer = Issuer("seal.test.k23")
    record = issuer.issue(_record())
    child = record.child
    assert verify(child, issuer.tag) and require(child, issuer.tag) is child
    object.__getattribute__(child, "__dict__")["text"] = ["CANARY-APPENDED"]
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _assert_code(child.model_dump, "SEAL_TAMPERED")
        _assert_code(lambda: child.model_dump(exclude_unset=True), "SEAL_TAMPERED")
    other_root = issuer.issue(_record())
    other = other_root.child
    object.__getattribute__(other, "__pydantic_fields_set__").clear()
    _assert_code(lambda: other.model_dump(exclude_unset=True), "SEAL_TAMPERED")


def test_extra_slots_and_dataclass_caches_are_rejected() -> None:
    with pytest.raises(SealError) as caught:
        type("Slotted", (SealedModel,), {"__slots__": ("_actions",),
                                          "__annotations__": {"x": int}})
    assert caught.value.code == "SEAL_FORBIDDEN_OPERATION"
    assert SealedModel.__doc__ is not None and "caches" in SealedModel.__doc__
    assert "outside the digest" in SealedModel.__doc__

    @dataclass(frozen=True)
    class Cached:
        v: int

    value = Cached(1)
    object.__setattr__(value, "_cache", {"k": 2})
    _assert_code(lambda: digest(value), "SEAL_UNSUPPORTED_TYPE")


def test_recycled_ids_never_inherit_issuance_unconditionally() -> None:
    issuer = Issuer("seal.test.idreuse")
    recycled = 0
    for index in range(5_000):
        original = issuer.issue(Child(text=str(index)))
        original_id = id(original)
        del original
        candidate = Child(text=str(index))
        if id(candidate) == original_id:
            recycled += 1
            assert not verify(candidate, issuer.tag)
        del candidate
    assert recycled > 0


# Cycle 2 regressions: SEAL-001 cycle 1 review P1-5, P2-6, P3-7 and P3-8.


def test_exact_primitive_type_and_decimal_representation_are_bound() -> None:
    issuer = Issuer("seal.test.primitive")
    for replacement in (0.5, "0.50", Decimal("0.5"), Decimal("0.500"), Decimal("-0.50")):
        record = issuer.issue(_record())
        object.__getattribute__(record, "__dict__")["amount"] = replacement
        _assert_code(lambda record=record: require(record, issuer.tag), "SEAL_TAMPERED")

    class Px(SealedModel):
        amount: Decimal
        count: int

    px = issuer.issue(Px(amount=Decimal("2"), count=1))
    object.__getattribute__(px, "__dict__")["amount"] = 2
    _assert_code(lambda: require(px, issuer.tag), "SEAL_TAMPERED")
    _assert_code(px.model_dump_json, "SEAL_TAMPERED")
    flag = issuer.issue(Px(amount=Decimal("2"), count=1))
    object.__getattribute__(flag, "__dict__")["count"] = True
    _assert_code(lambda: require(flag, issuer.tag), "SEAL_TAMPERED")
    # The public digest keeps NUM-001 scale-equality.
    assert digest(Decimal("0.50")) == digest(Decimal("0.5"))


def test_nested_issuance_is_root_bound_and_never_covers_caller_objects() -> None:
    issuer = Issuer("seal.test.rootbound")

    class PlainVerdict(BaseModel):
        status: str

    class Result(SealedModel):
        plain: PlainVerdict
        child: Child

    @dataclass(frozen=True)
    class Box:
        inner: Child

    caller = PlainVerdict(status="APPROVED-BY-CALLER")
    result = issuer.issue(Result(plain=caller, child=Child(text="kernel")))
    assert verify(result, issuer.tag)
    assert not verify(caller, issuer.tag) and not verify(result.plain, issuer.tag)
    child = result.child
    assert verify(child, issuer.tag) and issuer.issued_here(child)
    caller_child = Child(text="caller")
    box = issuer.issue(Box(caller_child))
    assert verify(box, issuer.tag) and not verify(caller_child, issuer.tag)
    del result
    gc.collect()
    assert not verify(child, issuer.tag)
    _assert_code(lambda: require(child, issuer.tag), "SEAL_NOT_ISSUED")


def test_issuer_init_cannot_be_reentered_or_squatted() -> None:
    import types

    legit = Issuer("seal.test.reentry")
    _assert_code(lambda: Issuer.__init__(legit, "seal.test.retag"), "SEAL_FORBIDDEN_OPERATION")
    assert legit.tag == "seal.test.reentry"
    _assert_code(lambda: Issuer.__init__(types.SimpleNamespace(), "seal.test.squat"),  # type: ignore[arg-type]
                 "SEAL_FORBIDDEN_OPERATION")
    assert Issuer("seal.test.squat").tag == "seal.test.squat"
    assert Issuer("seal.test.retag").tag == "seal.test.retag"


def test_issue_walks_a_deep_chain_once() -> None:
    from leviathan_core.seal import _registry

    class Link(SealedModel):
        next: Link | None = None

    chain: Link | None = None
    for _ in range(60):
        chain = Link(next=chain)
    calls = 0
    real = _registry._raw_seal

    def counting(obj: object, *args: object) -> object:
        nonlocal calls
        calls += 1
        return real(obj, *args)  # type: ignore[arg-type]

    _registry._raw_seal = counting  # type: ignore[assignment]
    try:
        Issuer("seal.test.linear").issue(chain)
    finally:
        _registry._raw_seal = real
    assert calls == 1


# Cycle 3 regressions: SEAL-001 cycle 2 review P3-10 and P3-11.


def test_revalidation_bypass_schemas_are_rejected_at_class_definition() -> None:
    from typing import Annotated, Any

    from pydantic import ConfigDict, InstanceOf, SkipValidation, WrapValidator

    bypasses: list[object] = [
        Any, object, InstanceOf[Child], SkipValidation[Child], tuple[Any, ...],
        dict[str, InstanceOf[Child]], Child | SkipValidation[Child],
        Annotated[Child, WrapValidator(lambda value, handler: value)],
    ]
    for annotation in bypasses:
        with pytest.raises(SealError) as caught:
            type("Bypass", (SealedModel,), {"__annotations__": {"v": annotation}})
        assert caught.value.code == "SEAL_UNSUPPORTED_TYPE"
        assert caught.value.__cause__ is None
    with pytest.raises(SealError) as caught:
        type("Lazy", (SealedModel,), {
            "model_config": ConfigDict(revalidate_instances="never"),
            "__annotations__": {"v": int},
        })
    assert caught.value.code == "SEAL_UNSUPPORTED_TYPE"
    with pytest.raises(SealError) as caught:
        type("LazyChild", (Child,), {"model_config": ConfigDict(revalidate_instances="never")})
    assert caught.value.code == "SEAL_UNSUPPORTED_TYPE"
    # Ordinary nested SealedModel fields still revalidate into kernel-made copies.
    caller = Child(text="caller")
    issuer = Issuer("seal.test.bypass")
    record = issuer.issue(Record(status="R", amount=Decimal("1"), child=caller, tags=()))
    assert record.child is not caller and not verify(caller, issuer.tag)


def test_named_zero_offset_timezone_swap_is_tampering() -> None:
    from datetime import timedelta, timezone

    class Stamp(SealedModel):
        at: datetime

    issuer = Issuer("seal.test.tzname")
    stamp = issuer.issue(Stamp(at=datetime(2026, 1, 1, tzinfo=UTC)))
    renamed = datetime(2026, 1, 1, tzinfo=timezone(timedelta(0), "X"))
    _assert_code(lambda: digest(renamed), "SEAL_UNSUPPORTED_TYPE")  # cycle 7: UTC singleton only
    object.__getattribute__(stamp, "__dict__")["at"] = renamed
    _assert_code(lambda: require(stamp, issuer.tag), "SEAL_TAMPERED")


# Cycle 4 regressions: SEAL-001b cycle 3 review P2-12 and P3-13.


def test_default_nested_value_is_copied_per_root_and_stale_entries_reissue() -> None:
    default_child = Child(text="default")

    class WithDefault(SealedModel):
        child: Child = default_child

    issuer = Issuer("seal.test.default")
    first = issuer.issue(WithDefault())
    assert first.child is not default_child and not verify(default_child, issuer.tag)
    del first
    gc.collect()
    for _ in range(3):
        root = issuer.issue(WithDefault())
        assert require(root.child, issuer.tag) is root.child
        assert root.child.model_dump() == {"text": "default"}


def test_stale_nested_entry_is_absent_for_a_new_root() -> None:
    from leviathan_core.seal import _registry

    issuer = Issuer("seal.test.stale")
    first = issuer.issue(_record())
    child = first.child
    del first
    gc.collect()
    _assert_code(lambda: require(child, issuer.tag), "SEAL_NOT_ISSUED")
    assert _registry._entry_for(child) is not None and _registry._live_entry(child) is None
    assert issuer.issue(child) is child
    assert require(child, issuer.tag) is child


def test_nested_sealed_model_config_and_rebuild_cannot_bypass_revalidation() -> None:
    from leviathan_core.seal.model import _schema_bypasses

    class Inner(SealedModel):
        text: str

    class Outer(SealedModel):
        inner: Inner

    assert not _schema_bypasses(Outer.__pydantic_core_schema__)
    Inner.model_config["revalidate_instances"] = "never"
    try:
        Inner.model_rebuild(force=True)
        _assert_code(lambda: Inner(text="caller"), "SEAL_UNSUPPORTED_TYPE")
        Outer.model_rebuild(force=True)
        assert _schema_bypasses(Outer.__pydantic_core_schema__)
        _assert_code(lambda: Outer.model_validate({"inner": {"text": "x"}}),
                     "SEAL_UNSUPPORTED_TYPE")
    finally:
        Inner.model_config["revalidate_instances"] = "always"


# Cycle 5 regressions: SEAL-001c issuer-level digest node budget.


def test_issuer_node_budget_is_bounded_exact_and_used_for_verification() -> None:
    from leviathan_core.seal import MAX_DIGEST_NODES_CEILING
    from leviathan_core.seal.digest import _Budget, _walk

    class Wide(SealedModel):
        values: tuple[int, ...]

    def nodes(value: object) -> int:
        budget = _Budget(MAX_DIGEST_NODES_CEILING)
        _walk(value, budget)
        return budget.count

    overhead = nodes(Wide(values=()))
    wide = Wide(values=tuple(range(10_470 - overhead)))
    assert nodes(wide) == 10_470

    for bad in (MAX_DIGEST_NODES_CEILING + 1, 0, -1, True, False, 10_000.0, "10000", None):
        _assert_code(lambda bad=bad: Issuer("seal.test.budget.bad", max_digest_nodes=bad),  # type: ignore[arg-type]
                     "SEAL_DIGEST_LIMIT")
        _assert_code(lambda bad=bad: digest(1, max_nodes=bad), "SEAL_DIGEST_LIMIT")  # type: ignore[arg-type]
    # A rejected budget never claims the tag.
    assert Issuer("seal.test.budget.bad").tag == "seal.test.budget.bad"

    _assert_code(lambda: Issuer("seal.test.budget.default").issue(wide), "SEAL_DIGEST_LIMIT")
    _assert_code(lambda: digest(wide), "SEAL_DIGEST_LIMIT")
    large = Issuer("seal.test.budget.large", max_digest_nodes=20_000)
    assert large.issue(wide) is wide
    assert require(wide, large.tag) is wide and large.issued_here(wide)
    assert len(digest(wide, max_nodes=10_470)) == 64
    _assert_code(lambda: digest(wide, max_nodes=10_469), "SEAL_DIGEST_LIMIT")
    assert MAX_DIGEST_NODES_CEILING == 1_048_576
    _assert_code(lambda: Issuer("seal.test.budget.over", max_digest_nodes=1_048_577),
                 "SEAL_DIGEST_LIMIT")
    ceiling = Issuer("seal.test.budget.ceiling", max_digest_nodes=1_048_576)
    assert ceiling.max_digest_nodes == 1_048_576
    # Cost stays linear: one walk per issue, visiting each node exactly once.
    from leviathan_core.seal import _registry

    walks: list[int] = []
    real = _registry._raw_seal

    def counting(obj: object, *args: object) -> object:
        walks.append(nodes(obj))
        return real(obj, *args)  # type: ignore[arg-type]

    twin = Wide(values=wide.values)
    _registry._raw_seal = counting  # type: ignore[assignment]
    try:
        ceiling.issue(twin)
    finally:
        _registry._raw_seal = real
    assert walks == [10_470]
    # Verification walks with the issuer's budget, still fail-closed past it.
    object.__getattribute__(wide, "__dict__")["values"] = tuple(range(20_001))
    _assert_code(lambda: require(wide, large.tag), "SEAL_TAMPERED")


def test_issuer_budget_cannot_be_raised_past_the_ceiling_after_init() -> None:
    from leviathan_core.seal.digest import _Budget, _walk

    issuer = Issuer("seal.test.budget.forge", max_digest_nodes=100)
    with pytest.raises(AttributeError):
        object.__setattr__(issuer, "_max_nodes", 10**7)
    big = Child(text="x")
    assert issuer.max_digest_nodes == 100
    wide = Record(status="R", amount=Decimal("1"), child=big, tags=tuple(map(str, range(200))))
    budget = _Budget(10_000)
    _walk(wide, budget)
    assert budget.count > 100
    _assert_code(lambda: issuer.issue(wide), "SEAL_DIGEST_LIMIT")


# Cycle 6 regressions: SEAL-001d linear root export over nested SealedModels.


class _Chunk(SealedModel):
    text: str
    tags: tuple[str, ...]


class _Parse(SealedModel):
    chunks: tuple[_Chunk, ...]


def _parse(count: int = 124) -> _Parse:
    return _Parse(chunks=tuple(
        _Chunk(text=f"chunk-{index}", tags=("a", "b")) for index in range(count)
    ))


def _count_walks(action: object) -> list[int]:
    from leviathan_core.seal import _registry
    from leviathan_core.seal.digest import _Budget, _walk

    walks: list[int] = []
    real = _registry._raw_seal

    def counting(obj: object, *args: object) -> object:
        budget = _Budget(1_048_576)
        _walk(obj, budget)
        walks.append(budget.count)
        return real(obj, *args)  # type: ignore[arg-type]

    _registry._raw_seal = counting  # type: ignore[assignment]
    try:
        action()  # type: ignore[operator]
    finally:
        _registry._raw_seal = real
    return walks


def test_root_export_with_124_nested_children_is_linear() -> None:
    issuer = Issuer("seal.test.export.linear")
    root = issuer.issue(_parse())
    root_nodes = _count_walks(lambda: digest(root, max_nodes=10_000))[0]
    # Exactly one full check before and one after each export, each a single root walk.
    for export in (root.model_dump, root.model_dump_json, root.model_copy):
        assert _count_walks(export) == [root_nodes, root_nodes]
    assert _count_walks(lambda: _Parse.model_validate(root)) == [root_nodes, root_nodes]
    small = issuer.issue(_parse(4))
    small_nodes = _count_walks(lambda: digest(small))[0]
    assert _count_walks(small.model_dump_json) == [small_nodes, small_nodes]


def test_tampered_nested_child_is_detected_during_root_export() -> None:
    import pydantic

    from leviathan_core.seal.model import _EXPORT_COVER

    issuer = Issuer("seal.test.export.tamper")
    root = issuer.issue(_parse())
    object.__getattribute__(root.chunks[57], "__dict__")["text"] = "CANARY"
    for export in (root.model_dump, root.model_dump_json, root.model_copy):
        _assert_code(export, "SEAL_TAMPERED")

    victims: list[_Chunk] = []

    class Mutating(SealedModel):
        text: str

        @pydantic.field_serializer("text")
        def _mutate(self, value: str) -> str:
            if victims:
                object.__getattribute__(victims.pop(), "__dict__")["text"] = "CANARY-MID"
            return value

    class Holder(SealedModel):
        first: Mutating
        second: _Chunk

    holder = issuer.issue(Holder(first=Mutating(text="m"), second=_Chunk(text="s", tags=())))
    victims.append(holder.second)
    # Mutation during the export is caught by the post-export root check.
    _assert_code(holder.model_dump_json, "SEAL_TAMPERED")
    assert _EXPORT_COVER.get() is None


def test_direct_nested_export_stays_fully_guarded() -> None:
    issuer = Issuer("seal.test.export.direct")
    root = issuer.issue(_parse())
    child = root.chunks[10]
    root_nodes = _count_walks(lambda: digest(root))[0]
    assert _count_walks(child.model_dump_json) == [root_nodes, root_nodes]
    object.__getattribute__(root.chunks[99], "__dict__")["tags"] = ["CANARY"]
    _assert_code(child.model_dump, "SEAL_TAMPERED")
    _assert_code(child.model_dump_json, "SEAL_TAMPERED")


def test_export_cover_never_leaks_after_errors_or_into_other_threads() -> None:
    import threading

    import pydantic

    from leviathan_core.seal.model import _EXPORT_COVER, _covered

    seen: dict[str, bool] = {}
    fail = [True]

    class Probe(SealedModel):
        text: str

        @pydantic.field_serializer("text")
        def _probe(self, value: str) -> str:
            seen["here"] = _covered(self)
            worker = threading.Thread(target=lambda: seen.__setitem__("thread", _covered(self)))
            worker.start()
            worker.join()
            if fail[0]:
                raise RuntimeError("CANARY-SERIALIZER")
            return value

    class Box(SealedModel):
        probe: Probe

    issuer = Issuer("seal.test.export.leak")
    box = issuer.issue(Box(probe=Probe(text="p")))
    _assert_code(box.model_dump_json, "SEAL_INVALID_MODEL")
    assert seen == {"here": True, "thread": False}
    assert _EXPORT_COVER.get() is None and not _covered(box.probe)
    object.__getattribute__(box.probe, "__dict__")["text"] = "CANARY"
    fail[0] = False
    _assert_code(box.probe.model_dump, "SEAL_TAMPERED")
    _assert_code(box.model_dump, "SEAL_TAMPERED")
    assert _EXPORT_COVER.get() is None


def test_export_cover_does_not_apply_in_a_task_that_copied_the_context() -> None:
    import asyncio

    from leviathan_core.seal.model import _EXPORT_COVER, _covered, _Scope

    issuer = Issuer("seal.test.export.task")
    root = issuer.issue(_parse(2))
    child = root.chunks[0]

    async def main() -> tuple[bool, bool]:
        token = _EXPORT_COVER.set(_Scope(frozenset({id(child)})))
        try:
            here = _covered(child)
            spawned = await asyncio.create_task(asyncio.to_thread(lambda: _covered(child)))
            inner = await asyncio.create_task(_inner())
            return here, spawned or inner
        finally:
            _EXPORT_COVER.reset(token)

    async def _inner() -> bool:
        return _covered(child)


    assert asyncio.run(main()) == (True, False)
    assert not _covered(child)



# Cycle 7 regressions: SEAL-001d review P1-15 (stolen cover) and P1-16 (lying tzinfo).


def test_context_copied_during_export_never_carries_a_live_cover() -> None:
    import contextvars

    import pydantic

    stolen: list[contextvars.Context] = []

    class Thief(SealedModel):
        child: _Chunk

        @pydantic.computed_field  # type: ignore[prop-decorator]
        @property
        def snapshot(self) -> str:
            stolen.append(contextvars.copy_context())
            return "s"

    issuer = Issuer("seal.test.export.stolen")
    root = issuer.issue(Thief(child=_Chunk(text="safe", tags=())))
    root.model_dump_json()
    assert stolen
    object.__getattribute__(root.child, "__dict__")["text"] = "CANARY-STOLEN"
    ctx = stolen[0]
    _assert_code(lambda: ctx.run(root.child.model_dump), "SEAL_TAMPERED")
    _assert_code(lambda: ctx.run(root.model_dump), "SEAL_TAMPERED")
    _assert_code(lambda: ctx.run(root.model_dump_json), "SEAL_TAMPERED")
    _assert_code(lambda: ctx.run(lambda: root.child.__dict__), "SEAL_TAMPERED")


def test_post_export_check_ignores_even_a_live_cover() -> None:
    import pydantic

    issuer = Issuer("seal.test.export.strict")
    holder: list[object] = []

    class Inner(SealedModel):
        text: str

        @pydantic.field_serializer("text")
        def _tamper_then_reexport(self, value: str) -> str:
            # Inside the live scope: tamper a covered sibling, then export it.
            target = holder[0]
            object.__getattribute__(target, "__dict__")["text"] = "CANARY-LIVE"
            _assert_code(target.model_dump, "SEAL_TAMPERED")  # type: ignore[attr-defined]
            return value

    class Pair(SealedModel):
        a: Inner
        b: _Chunk

    pair = issuer.issue(Pair(a=Inner(text="a"), b=_Chunk(text="b", tags=())))
    holder.append(pair.b)
    _assert_code(pair.model_dump, "SEAL_TAMPERED")


def test_sealed_datetimes_accept_only_the_utc_singleton() -> None:
    from datetime import timedelta, timezone, tzinfo

    class LyingTZ(tzinfo):
        def utcoffset(self, dt: datetime | None) -> timedelta:
            import sys

            caller = sys._getframe(1).f_globals.get("__name__", "")
            return timedelta(0) if caller.startswith("leviathan_core.seal") else timedelta(hours=5)

        def tzname(self, dt: datetime | None) -> str:
            return "UTC"

        def dst(self, dt: datetime | None) -> timedelta:
            return timedelta(0)

    class CallerTZ(tzinfo):
        def utcoffset(self, dt: datetime | None) -> timedelta:
            return timedelta(0)

        def dst(self, dt: datetime | None) -> timedelta:
            return timedelta(0)

    class Stamp(SealedModel):
        at: datetime

    # timezone(timedelta(0)) is the UTC singleton itself, so it stays accepted.
    assert timezone(timedelta(0)) is UTC
    for zone in (LyingTZ(), CallerTZ(), timezone(timedelta(0), "UTC")):
        value = datetime(2026, 1, 1, 12, tzinfo=zone)
        _assert_code(lambda value=value: digest(value), "SEAL_UNSUPPORTED_TYPE")
        _assert_code(lambda value=value: _UTC_ISSUER.issue(Stamp(at=value)),
                     "SEAL_UNSUPPORTED_TYPE")
    stamp = _UTC_ISSUER.issue(Stamp(at=datetime(2026, 1, 1, 12, tzinfo=UTC)))
    object.__getattribute__(stamp, "__dict__")["at"] = datetime(2026, 1, 1, 12, tzinfo=LyingTZ())
    _assert_code(lambda: require(stamp, _UTC_ISSUER.tag), "SEAL_TAMPERED")


_UTC_ISSUER = Issuer("seal.test.utc.only")



# Cycle 8 regressions: SEAL-001e base __setstate__ and state-slot replacement.


def test_base_setstate_on_issued_model_is_refused_before_any_mutation() -> None:
    issuer = Issuer("seal.test.setstate")
    for state in ({}, {
        "__pydantic_fields_set__": {"status"},
        "__pydantic_extra__": {"x": 1},
        "__pydantic_private__": {"p": 2},
        "__dict__": {"status": "CANARY", "amount": Decimal("9"), "child": None, "tags": ()},
    }):
        record = issuer.issue(_record())
        before = digest(record)
        raw = object.__getattribute__(record, "__dict__")
        fields_set = object.__getattribute__(record, "__pydantic_fields_set__")
        _assert_code(lambda record=record, state=state: BaseModel.__setstate__(record, state),
                     "SEAL_FORBIDDEN_OPERATION")
        assert object.__getattribute__(record, "__dict__") is raw
        assert object.__getattribute__(record, "__pydantic_fields_set__") is fields_set
        assert require(record, issuer.tag) is record and digest(record) == before
        for slot in ("__pydantic_fields_set__", "__pydantic_extra__",
                     "__pydantic_private__", "__dict__"):
            _assert_code(lambda record=record, slot=slot: object.__setattr__(record, slot, {}),
                         "SEAL_FORBIDDEN_OPERATION")
            _assert_code(lambda record=record, slot=slot: object.__delattr__(record, slot),
                         "SEAL_FORBIDDEN_OPERATION")
        assert require(record, issuer.tag) is record
    # Unissued instances keep pydantic's normal state handling.
    loose = _record()
    BaseModel.__setstate__(loose, {
        "__pydantic_fields_set__": {"status"}, "__pydantic_extra__": None,
        "__pydantic_private__": None, "__dict__": dict(object.__getattribute__(loose, "__dict__")),
    })
    assert loose.status == "READY"
    # In-place mutation of the same slots is still detected at require and export.
    record = issuer.issue(_record())
    object.__getattribute__(record, "__pydantic_fields_set__").clear()
    _assert_code(lambda: require(record, issuer.tag), "SEAL_TAMPERED")
    _assert_code(record.model_dump, "SEAL_TAMPERED")
