"""Versioned, typed block catalog schema. It describes blocks; it executes none."""

from __future__ import annotations

import re
from collections.abc import Mapping
from decimal import Decimal
from hashlib import sha256
from typing import Any, Literal

from pydantic import field_validator, model_validator

from leviathan_core.ea_builder.graph import EaModelError, KindV1, PlatformV1, _GraphModel
from leviathan_core.numeric import canonical_json, parse_decimal, parse_int

_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_.:-]{0,127}\Z")
MAX_BLOCKS = 512
MAX_PORTS_PER_BLOCK = 32
MAX_PARAMS_PER_BLOCK = 64

CategoryV1 = Literal[
    "event",
    "indicator",
    "control",
    "trade",
    "risk",
    "money",
    "time_filter",
    "news_filter",
    "variable",
    "portfolio",
    "delay",
    "state",
    "math",
    "filter",
]


class _BlockModel(_GraphModel):
    """Block catalog records share the guarded EA schema boundary."""


class PortV1(_BlockModel):
    name: str
    kind: KindV1
    unit: str | None
    required: bool
    symbol_scope: str | None
    timeframe_scope: str | None

    @field_validator("name", "unit", "symbol_scope", "timeframe_scope")
    @classmethod
    def _identifier(cls, value: str | None) -> str | None:
        if value is not None and not _ID.fullmatch(value):
            raise ValueError("port names and scopes must be stable identifiers")
        return value


class ParameterSpecV1(_BlockModel):
    name: str
    kind: KindV1
    required: bool
    unit: str | None
    minimum: Decimal | None
    maximum: Decimal | None
    choices: tuple[str, ...]

    @field_validator("name", "unit")
    @classmethod
    def _identifier(cls, value: str | None) -> str | None:
        if value is not None and not _ID.fullmatch(value):
            raise ValueError("parameter name and unit must be stable identifiers")
        return value

    @model_validator(mode="after")
    def _bounds(self) -> ParameterSpecV1:
        lower = parse_decimal(self.minimum, field="minimum") if self.minimum is not None else None
        upper = parse_decimal(self.maximum, field="maximum") if self.maximum is not None else None
        if lower is not None and upper is not None and lower > upper:
            raise ValueError("minimum exceeds maximum")
        if self.kind not in {"int", "decimal", "percent"} and (
            self.minimum is not None or self.maximum is not None
        ):
            raise ValueError("numeric bounds require numeric kind")
        if self.kind == "enum" and not self.choices:
            raise ValueError("enum requires explicit choices")
        if self.kind != "enum" and self.choices:
            raise ValueError("choices require enum kind")
        if len(set(self.choices)) != len(self.choices):
            raise ValueError("duplicate enum choices")
        return self


class BlockDefinitionV1(_BlockModel):
    block_id: str
    category: CategoryV1
    inputs: tuple[PortV1, ...]
    outputs: tuple[PortV1, ...]
    parameters: tuple[ParameterSpecV1, ...]
    targets: tuple[PlatformV1, ...]
    warmup_bars: int
    delay_bound: int | None

    @model_validator(mode="before")
    @classmethod
    def _bounded_schema(cls, data: Any) -> Any:
        if isinstance(data, Mapping):
            inputs = data.get("inputs")
            outputs = data.get("outputs")
            parameters = data.get("parameters")
            if (
                isinstance(inputs, (list, tuple))
                and isinstance(outputs, (list, tuple))
                and len(inputs) + len(outputs) > MAX_PORTS_PER_BLOCK
            ):
                raise EaModelError("PORT_LIMIT", "inputs", "out_of_range")
            if isinstance(parameters, (list, tuple)) and len(parameters) > MAX_PARAMS_PER_BLOCK:
                raise EaModelError("PARAMETER_LIMIT", "parameters", "out_of_range")
        return data

    @field_validator("block_id")
    @classmethod
    def _identity(cls, value: str) -> str:
        if not _ID.fullmatch(value):
            raise ValueError("block id must be stable")
        return value

    @model_validator(mode="after")
    def _well_formed(self) -> BlockDefinitionV1:
        if len(self.inputs) + len(self.outputs) > MAX_PORTS_PER_BLOCK:
            raise EaModelError("PORT_LIMIT", "inputs", "out_of_range")
        if len(self.parameters) > MAX_PARAMS_PER_BLOCK:
            raise EaModelError("PARAMETER_LIMIT", "parameters", "out_of_range")
        parse_int(self.warmup_bars, field="warmup_bars", min_value=0, max_value=10**38)
        if self.delay_bound is not None:
            parse_int(self.delay_bound, field="delay_bound", min_value=1, max_value=10**38)
        if not self.targets or len(set(self.targets)) != len(self.targets):
            raise ValueError("targets must be nonempty and unique")
        for group in (self.inputs, self.outputs, self.parameters):
            names = [item.name for item in group]
            if len(names) != len(set(names)):
                raise ValueError("duplicate port or parameter name")
        if self.category == "event" and any(
            output.kind == "order-intent" for output in self.outputs
        ):
            raise EaModelError("EVENT_ORDER_INTENT", "outputs", "invalid")
        return self


class BlockCatalogV1(_BlockModel):
    catalog_id: str
    version: int
    blocks: tuple[BlockDefinitionV1, ...]

    @field_validator("blocks", mode="before")
    @classmethod
    def _bounded_blocks(cls, value: object) -> object:
        if isinstance(value, (list, tuple)) and len(value) > MAX_BLOCKS:
            raise EaModelError("CATALOG_BLOCK_LIMIT", "blocks", "out_of_range")
        return value

    def canonical_digest(self) -> str:
        """Bind declarative catalog content independently of declaration order."""
        blocks: list[dict[str, Any]] = []
        for block in self.blocks:
            item = block.model_dump(mode="python")
            for group in ("inputs", "outputs", "parameters"):
                members = item[group]
                if group == "parameters":
                    for member in members:
                        member["choices"] = sorted(member["choices"])
                item[group] = sorted(
                    members, key=lambda member: (member["name"], canonical_json(member))
                )
            item["targets"] = sorted(item["targets"])
            blocks.append(item)
        document = {
            "catalog_id": self.catalog_id,
            "version": self.version,
            "blocks": sorted(blocks, key=lambda item: (item["block_id"], canonical_json(item))),
        }
        return sha256(canonical_json(document)).hexdigest()

    @field_validator("catalog_id")
    @classmethod
    def _identity(cls, value: str) -> str:
        if not _ID.fullmatch(value):
            raise ValueError("catalog id must be stable")
        return value

    @field_validator("version")
    @classmethod
    def _version(cls, value: int) -> int:
        return parse_int(value, field="version", min_value=1, max_value=10**38)


def standard_catalog_v1() -> BlockCatalogV1:
    """Small declarative MT catalog; definitions grant no execution or export right."""

    def port(name: str, kind: KindV1, required: bool) -> PortV1:
        return PortV1(
            name=name,
            kind=kind,
            unit=None,
            required=required,
            symbol_scope=None,
            timeframe_scope=None,
        )

    def parameter(
        name: str,
        kind: KindV1,
        *,
        minimum: Decimal | None = None,
        maximum: Decimal | None = None,
        choices: tuple[str, ...] = (),
    ) -> ParameterSpecV1:
        return ParameterSpecV1(
            name=name,
            kind=kind,
            required=True,
            unit=None,
            minimum=minimum,
            maximum=maximum,
            choices=choices,
        )

    def block(
        block_id: str,
        category: CategoryV1,
        inputs: tuple[PortV1, ...],
        outputs: tuple[PortV1, ...],
        parameters: tuple[ParameterSpecV1, ...] = (),
        *,
        targets: tuple[PlatformV1, ...] = ("MT4", "MT5"),
        warmup_bars: int = 0,
        delay_bound: int | None = None,
    ) -> BlockDefinitionV1:
        return BlockDefinitionV1(
            block_id=block_id,
            category=category,
            inputs=inputs,
            outputs=outputs,
            parameters=parameters,
            targets=targets,
            warmup_bars=warmup_bars,
            delay_bound=delay_bound,
        )

    event_out = (port("event", "event", False),)
    event_in = (port("event", "event", True),)
    intent_in = (port("intent", "order-intent", True),)
    intent_out = (port("intent", "order-intent", False),)
    blocks = (
        block("tick_event", "event", (), event_out),
        block("bar_event", "event", (), event_out),
        block("session_event", "event", (), event_out),
        block(
            "sma_indicator",
            "indicator",
            event_in,
            (port("value", "numeric-series", False),),
            (parameter("period", "int", minimum=Decimal(1), maximum=Decimal(100_000)),),
            warmup_bars=1,
        ),
        block(
            "control_if",
            "control",
            (*event_in, port("condition", "bool", True)),
            event_out,
        ),
        block(
            "control_loop",
            "control",
            event_in,
            event_out,
            (parameter("max_iterations", "int", minimum=Decimal(1), maximum=Decimal(1_024)),),
        ),
        block("trade_entry", "trade", intent_in, ()),
        block("trade_exit", "trade", intent_in, ()),
        block(
            "risk_cap",
            "risk",
            event_in,
            intent_out,
            (parameter("max_daily_loss", "percent", minimum=Decimal(0), maximum=Decimal(100)),),
        ),
        block(
            "money_size",
            "money",
            intent_in,
            intent_out,
            (parameter("max_lots", "decimal", minimum=Decimal("0.01")),),
        ),
        block(
            "time_filter",
            "time_filter",
            event_in,
            event_out,
            (
                parameter("start_ns", "int", minimum=Decimal(0)),
                parameter("end_ns", "int", minimum=Decimal(0)),
            ),
        ),
        block(
            "news_filter",
            "news_filter",
            event_in,
            event_out,
            (
                parameter("start_ns", "int", minimum=Decimal(0)),
                parameter("end_ns", "int", minimum=Decimal(0)),
            ),
        ),
        block(
            "variable",
            "variable",
            (),
            (port("value", "decimal", False),),
            (parameter("value", "decimal"),),
        ),
        block("portfolio_router", "portfolio", intent_in, intent_out),
        block("delay", "delay", event_in, event_out, delay_bound=1),
        block("state", "state", event_in, event_out, delay_bound=1),
        block(
            "mt4_pending_order",
            "trade",
            intent_in,
            (),
            targets=("MT4",),
        ),
    )
    return BlockCatalogV1(catalog_id="leviathan_standard", version=1, blocks=blocks)
