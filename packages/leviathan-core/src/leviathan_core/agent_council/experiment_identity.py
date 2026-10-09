"""Bounded canonical parameters, exact Decimal values and experiment identity."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Literal, NoReturn

from leviathan_core.numeric import NumericError, canonical_json, canonical_str

if TYPE_CHECKING:
    from .state_models import ExperimentSpecV1, TypedParamV1

MAX_PARAMETER_BYTES = 65536
MAX_PARAMETER_DEPTH = 32
MAX_PARAMETER_NODES = 4096
MAX_PARAMETER_INTEGER_BITS = 130
class ParameterError(ValueError):
    """A parameter cannot be represented safely and canonically."""


class PrecisionExceededError(ParameterError):
    """An input has more than 34 significant Decimal digits."""

    def __init__(self) -> None:
        super().__init__("PRECISION_EXCEEDED")


class IdentityConflictError(ValueError):
    """An idempotency key has already been bound to a different experiment."""


def _utf8(value: str) -> bytes:
    if len(value) > MAX_PARAMETER_BYTES:
        raise ParameterError("parameters exceed 64 KiB")
    try:
        return value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ParameterError("parameters contain unsupported Unicode") from None


def _precheck_json_structure(value: str) -> None:
    """Bound container expansion before the JSON decoder allocates nested values."""

    depth = 0
    nodes = 1
    in_string = False
    escaped = False
    for char in value:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            nodes += 1
            if depth > MAX_PARAMETER_DEPTH:
                raise ParameterError("parameters exceed nesting depth")
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise ParameterError("parameters must be valid JSON")
        elif char == ",":
            nodes += 1
        if nodes > MAX_PARAMETER_NODES * 6:
            raise ParameterError("parameters exceed node bounds")


def canonical_decimal(value: Decimal) -> str:
    """Return exact plain form without rounding or exponent expansion first."""

    if not isinstance(value, Decimal) or not value.is_finite():
        raise ParameterError("Decimal must be finite")
    parts = value.as_tuple()
    if len(parts.digits) > 50 or abs(value.adjusted()) > 38:
        raise ParameterError("Decimal exceeds coefficient or exponent bounds")
    try:
        return canonical_str(value)
    except NumericError as error:
        if error.code == "PRECISION_EXCEEDED":
            raise PrecisionExceededError() from None
        raise ParameterError("Decimal cannot be represented exactly at precision 34") from None


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ParameterError("parameters contain duplicate JSON keys")
        result[key] = value
    return result


def _consume(budget: list[int], *, nodes: int = 1, bytes_: int = 0) -> None:
    budget[0] -= nodes
    budget[1] -= bytes_
    if budget[0] < 0 or budget[1] < 0:
        raise ParameterError("parameters exceed size or node bounds")


def _reject_fraction(_value: str) -> NoReturn:
    raise ParameterError("fractional or exponent JSON numbers require typed Decimal parameters")


def _parse_raw_json(parameters: str) -> dict[str, object]:
    raw_bytes = _utf8(parameters)
    if len(raw_bytes) > MAX_PARAMETER_BYTES:
        raise ParameterError("parameters exceed 64 KiB")
    _precheck_json_structure(parameters)
    try:
        parsed = json.loads(
            parameters,
            parse_float=_reject_fraction,
            object_pairs_hook=_pairs_without_duplicates,
        )
    except ParameterError:
        raise
    except (json.JSONDecodeError, ValueError, RecursionError):
        raise ParameterError("parameters must be valid JSON") from None
    if not isinstance(parsed, dict):
        raise ParameterError("experiment parameters must be a JSON object")
    return parsed


def canonicalize_raw_json(parameters: str) -> str:
    """Canonical ordinary JSON; no key has transport meaning."""

    parsed = _parse_raw_json(parameters)
    canonicalize_parameters(parsed)
    try:
        encoded = canonical_json(parsed)
    except NumericError:
        raise ParameterError("parameters cannot be serialized") from None
    if len(encoded) > MAX_PARAMETER_BYTES:
        raise ParameterError("parameters exceed 64 KiB")
    return encoded.decode("ascii")


def canonicalize_parameters(
    parameters: Mapping[str, object] | str,
) -> tuple[TypedParamV1, ...]:
    """Convert exact scalar types into a sorted schema-level typed tuple."""

    from .state_models import TypedParamV1

    source = _parse_raw_json(parameters) if isinstance(parameters, str) else parameters
    if not isinstance(source, Mapping):
        raise ParameterError("experiment parameters must be a JSON object")
    if len(source) > MAX_PARAMETER_NODES:
        raise ParameterError("parameters exceed node bounds")
    budget = [MAX_PARAMETER_NODES, MAX_PARAMETER_BYTES]
    result: list[TypedParamV1] = []
    for key in source:
        if type(key) is not str:
            raise ParameterError("parameter names must be ASCII identifiers")
    for key in sorted(source):
        _consume(budget, bytes_=len(_utf8(key)))
        value = source[key]
        kind: Literal["decimal", "int", "bool", "str"]
        text: str
        if type(value) is Decimal:
            kind, text = "decimal", canonical_decimal(value)
        elif type(value) is bool:
            kind, text = "bool", "true" if value else "false"
        elif type(value) is int:
            if value.bit_length() > MAX_PARAMETER_INTEGER_BITS:
                raise ParameterError("integer parameter exceeds bounds")
            try:
                kind, text = "int", canonical_str(value)
            except NumericError:
                raise ParameterError("integer parameter exceeds bounds") from None
        elif type(value) is str:
            kind, text = "str", value
        else:
            raise ParameterError("unsupported parameter type")
        _consume(budget, nodes=0, bytes_=len(_utf8(text)))
        try:
            result.append(TypedParamV1(name=key, kind=kind, value=text))
        except ValueError:
            raise ParameterError("parameter name or value is invalid") from None
    try:
        encoded = canonical_json([entry.model_dump() for entry in result])
    except NumericError:
        raise ParameterError("parameters cannot be serialized") from None
    if len(encoded) > MAX_PARAMETER_BYTES:
        raise ParameterError("parameters exceed 64 KiB")
    return tuple(result)


def derive_experiment_id(spec: ExperimentSpecV1) -> str:
    """Hash reproducibility inputs; the idempotency key is deliberately excluded."""

    payload = {
        "hypothesis_id": spec.hypothesis_id,
        "hypothesis_version": spec.hypothesis_version,
        "dataset_hash": spec.dataset.content_hash,
        "dataset_version": spec.dataset.version,
        "dataset_is_holdout": spec.dataset.is_holdout,
        "signals": sorted((ref.signal_id, ref.version) for ref in spec.signal_refs),
        "engine_version": spec.engine_version,
        "typed_parameters": [entry.model_dump() for entry in spec.typed_parameters],
        "seed": spec.seed,
        "train_window": (
            None if spec.train_window is None else spec.train_window.model_dump(mode="json")
        ),
        "test_window": spec.test_window.model_dump(mode="json"),
        "run_version": spec.run_version,
        "parent_experiment_id": spec.parent_experiment_id,
    }
    return "exp_" + hashlib.sha256(canonical_json(payload)).hexdigest()


def propose_experiment_identity(
    spec: ExperimentSpecV1, existing_by_key: Mapping[str, str]
) -> tuple[str, dict[str, str]]:
    """Return identity and proposed registry; caller persists it atomically."""

    identity = derive_experiment_id(spec)
    bound = existing_by_key.get(spec.idempotency_key)
    if bound is not None and bound != identity:
        raise IdentityConflictError("idempotency key already binds a different experiment")
    proposal = dict(existing_by_key)
    proposal[spec.idempotency_key] = identity
    return identity, proposal
