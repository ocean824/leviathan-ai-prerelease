"""Declarative EA catalog extension for the causal signal block subset."""

from __future__ import annotations

from leviathan_core.ea_builder.blocks import (
    BlockCatalogV1,
    BlockDefinitionV1,
    ParameterSpecV1,
    PortV1,
)
from leviathan_core.ea_builder.graph import EaModelError, PlatformV1
from leviathan_core.ea_builder.signal_blocks import SignalBlockError

SIGNAL_CATALOG_VERSION_V1 = 1


def _port(name: str, kind: str, required: bool = True) -> PortV1:
    return PortV1(
        name=name,
        kind=kind,  # type: ignore[arg-type]
        unit=None,
        required=required,
        symbol_scope=None,
        timeframe_scope=None,
    )


def _enum_parameter(name: str, choices: tuple[str, ...]) -> ParameterSpecV1:
    return ParameterSpecV1(
        name=name,
        kind="enum",
        required=True,
        unit=None,
        minimum=None,
        maximum=None,
        choices=choices,
    )


def _signal_key_parameter() -> ParameterSpecV1:
    # EA-001 has no dedicated signal-key parameter kind. Its stable symbol kind
    # applies the same closed identifier grammar without permitting free text.
    return ParameterSpecV1(
        name="signal_key",
        kind="symbol",
        required=True,
        unit=None,
        minimum=None,
        maximum=None,
        choices=(),
    )


def signal_block_definitions_v1() -> tuple[BlockDefinitionV1, ...]:
    """Return the four versioned definitions, independent of catalog order."""
    mt_targets: tuple[PlatformV1, ...] = ("MT4", "MT5")
    return (
        BlockDefinitionV1(
            block_id="compare.v1",
            category="math",
            inputs=(_port("left", "decimal"), _port("right", "decimal")),
            outputs=(_port("condition", "bool", False),),
            parameters=(_enum_parameter("op", ("gt", "lt", "ge", "le")),),
            targets=mt_targets,
            warmup_bars=0,
            delay_bound=None,
        ),
        BlockDefinitionV1(
            block_id="crossover.v1",
            category="math",
            # EA-001 KindV1 has no NumericSeriesV1 port kind. The catalog keeps
            # nominal scalar channels; the signal kernel requires issued series
            # bundles and checks their current/prior bar pairing before emission.
            inputs=(_port("left", "decimal"), _port("right", "decimal")),
            outputs=(_port("condition", "bool", False),),
            parameters=(_enum_parameter("direction", ("above", "below")),),
            targets=mt_targets,
            warmup_bars=1,
            delay_bound=None,
        ),
        BlockDefinitionV1(
            block_id="entry_signal.v1",
            category="event",
            inputs=(_port("condition", "bool"),),
            outputs=(_port("signal", "event", False),),
            parameters=(_signal_key_parameter(),),
            targets=mt_targets,
            warmup_bars=0,
            delay_bound=None,
        ),
        BlockDefinitionV1(
            block_id="exit_signal.v1",
            category="event",
            inputs=(_port("condition", "bool"),),
            outputs=(_port("signal", "event", False),),
            parameters=(_signal_key_parameter(),),
            targets=mt_targets,
            warmup_bars=0,
            delay_bound=None,
        ),
    )


def signal_catalog_v1() -> tuple[BlockDefinitionV1, ...]:
    """Public catalog-definition spelling used by catalog builders."""
    return signal_block_definitions_v1()


def extend_signal_catalog_v1(catalog: BlockCatalogV1) -> BlockCatalogV1:
    """Return a new catalog containing the signal definitions, never a mutation."""
    if not isinstance(catalog, BlockCatalogV1):
        raise SignalBlockError("INVALID_CATALOG")
    definitions = signal_block_definitions_v1()
    existing_ids = {block.block_id for block in catalog.blocks}
    if any(block.block_id in existing_ids for block in definitions):
        raise SignalBlockError("CATALOG_CONFLICT")
    try:
        return BlockCatalogV1(
            catalog_id=catalog.catalog_id,
            version=catalog.version,
            blocks=(*catalog.blocks, *definitions),
        )
    except EaModelError:
        raise SignalBlockError("INVALID_CATALOG") from None


__all__ = [
    "SIGNAL_CATALOG_VERSION_V1",
    "extend_signal_catalog_v1",
    "signal_block_definitions_v1",
    "signal_catalog_v1",
]
