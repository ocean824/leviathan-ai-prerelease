from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType

import pytest

from leviathan_core.seal import Issuer, SealError, digest, verify
from leviathan_core.seal.digest import _raw_seal


def test_mappingproxy_and_dict_have_the_same_canonical_digest() -> None:
    values = {"z": (1, "two"), "a": {"enabled": True}}
    assert digest(MappingProxyType(values)) == digest(values)


def test_mappingproxy_with_non_string_keys_is_rejected() -> None:
    with pytest.raises(SealError, match="SEAL_UNSUPPORTED_TYPE"):
        digest(MappingProxyType({1: "value"}))


def test_mappingproxy_over_dict_subclass_is_rejected() -> None:
    class LyingDict(dict[str, int]):
        def __getitem__(self, key: str) -> int:
            return 999

    with pytest.raises(SealError, match="SEAL_UNSUPPORTED_TYPE"):
        digest(MappingProxyType(LyingDict(answer=1)))


def test_mappingproxy_over_custom_mapping_is_rejected_without_iteration() -> None:
    class EndlessMapping(Mapping[str, int]):
        def __getitem__(self, key: str) -> int:
            raise AssertionError("must not read wrapped mapping")

        def __iter__(self) -> Iterator[str]:
            raise AssertionError("must not iterate wrapped mapping")

        def __len__(self) -> int:
            raise AssertionError("must not count wrapped mapping")

    with pytest.raises(SealError, match="SEAL_UNSUPPORTED_TYPE"):
        digest(MappingProxyType(EndlessMapping()))


def test_mappingproxy_over_mappingproxy_is_rejected() -> None:
    inner = MappingProxyType({"answer": 42})
    with pytest.raises(SealError, match="SEAL_UNSUPPORTED_TYPE"):
        digest(MappingProxyType(inner))


def test_mappingproxy_budget_is_checked_before_values_expand() -> None:
    with pytest.raises(SealError, match="SEAL_DIGEST_LIMIT"):
        _raw_seal(MappingProxyType({"answer": 42}), limit=1)


def test_mappingproxy_over_exact_dict_can_be_issued_and_is_content_bound() -> None:
    @dataclass(frozen=True)
    class Holder:
        values: object

    issuer = Issuer("test.mappingproxy")
    backing = {"answer": 42}
    record = issuer.issue(Holder(MappingProxyType(backing)))
    assert verify(record, issuer.tag)
    backing["answer"] = 43
    assert not verify(record, issuer.tag)
