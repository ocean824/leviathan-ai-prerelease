"""Versioned, text-only preset adapters for Golden Goose and KLP seed settings.

This module ingests parameter configuration only. It does not recover or infer
compiled strategy logic. Seed bytes remain external; repository fixtures contain
only sanitized key/value parameter rows with presentation hints removed.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, TypeAlias

from .mt_set_import import (
    MAX_SET_BYTES,
    FieldTypeV1,
    InstrumentMappingV1,
    MtSetImportError,
    ParameterSpecV1,
    SetImportMetadataV1,
    SetPresetV1,
    TimezoneMappingV1,
    parse_mt_set,
)

SEED_MANIFEST_SHA256 = "f67c0acd7b4cf3851994e6597daaba02d62dcc332c7e56620a2fd046c715a05d"
LICENSE_ATTESTATION_REFERENCE = "seed-manifest-owner-attestation-2026-10-09"
FamilyIdV1: TypeAlias = Literal["GOLDEN_GOOSE", "KLP"]
PresetRoleV1: TypeAlias = Literal["CHALLENGE", "VERIFICATION", "POST_FUNDED", "HARVEST", "PROFILE"]


@dataclass(frozen=True, slots=True, kw_only=True)
class SeedPresetIndexEntryV1:
    preset_id: str
    family_id: FamilyIdV1
    preset_role: PresetRoleV1
    platform: Literal["MT4", "MT5"]
    preset_version: str
    source_manifest_path: str
    source_sha256: str
    fixture_name: str
    fixture_sha256: str
    crack_labelled: bool
    license_attestation_ref: str

    @property
    def source_locator(self) -> str:
        return f"{self.source_manifest_path}#sha256={self.source_sha256}"


@dataclass(frozen=True, slots=True, kw_only=True)
class ParameterFieldMappingV1:
    source_name: str
    canonical_name: str
    value_type: FieldTypeV1
    unit: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ImportedSeedPresetV1:
    schema_version: Literal["1"]
    family_id: FamilyIdV1
    preset_role: PresetRoleV1
    preset_id: str
    preset_version: str
    platform: Literal["MT4", "MT5"]
    source_manifest_path: str
    source_locator: str
    source_sha256: str
    source_manifest_sha256: str
    crack_labelled: bool
    license_attestation_ref: str
    field_mappings: tuple[ParameterFieldMappingV1, ...]
    parsed_set: SetPresetV1


# Mixed integer/decimal source fields are normalized to Decimal; AsianEnd is
# preserved as text because source presets use both clock labels and integers.
_SCHEMA_TYPES: Mapping[FieldTypeV1, tuple[str, ...]] = {
    "integer": (
        "adxMaxValue",
        "adxMaxValueAction",
        "adxPeriod",
        "adxTimeframe",
        "asianEndMode",
        "autoResumeMode",
        "BeginClosingAfter",
        "BiStart",
        "CandleFilter",
        "csfStart",
        "csfTimeFrameStart",
        "CSTimeFrame",
        "CutLevel",
        "delay",
        "dgAmount",
        "dgType",
        "EMATimeFrame",
        "EquityProtection",
        "floatingBasketType",
        "FOMCIndent",
        "FOMCNews",
        "ghostLevel",
        "ghostPipStep",
        "ghostTP",
        "GMT_Offset",
        "HighColor",
        "HighIndent",
        "HighNews",
        "LicenceType",
        "LMMType",
        "LondonEnd",
        "londonEndMode",
        "LondonStart",
        "lotMultInterval",
        "LowColor",
        "LowIndent",
        "LowNews",
        "lsType",
        "MA1",
        "MA2",
        "MA3",
        "maEntryDir",
        "maMethod",
        "maxCharts",
        "MaxOrders",
        "MaxSpread",
        "MidleColor",
        "MidleIndent",
        "MidleNews",
        "Min_Time",
        "MinNews",
        "newCsTimeframe",
        "newMinTime",
        "NewYorkEnd",
        "newyorkEndMode",
        "NewYorkStart",
        "NFPIndent",
        "NFPNews",
        "PipSteps",
        "PipStepType",
        "profitBasketType",
        "PSMType",
        "realTradeDir",
        "ResumeTradingAfter",
        "rsiBuyThresh",
        "rsiEntryDir",
        "rsiPeriod",
        "rsiSellThresh",
        "rsiTimeframe",
        "StopDay",
        "StopDay_TP",
        "TakeProfits",
        "threshAfterEvery",
        "threshLowerBy",
        "threshStart",
        "threshTP",
        "timeBasedOn",
        "TradesType",
        "trendStartLevel",
        "trendStopLoss",
        "trendTakeProfit",
        "trendTpType",
        "trendType",
        "TS_type",
        "wgType",
        "YogaType",
    ),
    "decimal": (
        "AmpThreshold",
        "AsianStart",
        "BasketGoal",
        "DMInterval",
        "DMPipStepMult",
        "DMStart",
        "epAmount",
        "fbGoal",
        "fbIncrement",
        "fbInterval",
        "fbIntervalStart",
        "fbNewGoal",
        "fbStart",
        "fbStop",
        "LotMultiplier",
        "LSMInterval",
        "LSMMultiplier",
        "LSMStart",
        "MaximumEquityLimit",
        "maxLot",
        "MinimumEquityLimit",
        "perCashAmmount",
        "PipStep",
        "PipStepMult",
        "startingLot",
        "stopLoss",
        "TakeProfit",
        "trailIncrement",
        "TrailStart",
        "TrailStop",
        "trendLotPerc",
        "WeeklyGoal",
        "YogaStart",
        "YogaStop",
    ),
    "boolean": (
        "AutoReset",
        "autoScale",
        "DeleteTP",
        "DisableClosing_DN",
        "DrawNewsLines",
        "fbAutoReset",
        "fbDirectionalBased",
        "LipoMode",
        "ShowPanel",
        "StopTradeByDT",
        "StopTradeByDT_TP",
        "TradeAsian",
        "TradeLondon",
        "TradeNewYork",
        "trendCloseTogether",
        "trendTradeOnce",
        "turnOffDLL",
        "Use_AmpMode",
        "Use_DDManager",
        "Use_GMT",
        "Use_HedgingMode",
        "Use_LSM",
        "Use_NewsFilter",
        "Use_ProfitBasket",
        "useAccSL",
        "useAccTP",
        "useADX",
        "useCSFilter",
        "useCSFManager",
        "useDailyGoal",
        "useEMAFilter",
        "useEntryDelay",
        "useEqProtector",
        "useFbManager",
        "useFloatingBasket",
        "useGhostTrades",
        "useMACrossDelay",
        "useMaxCharts",
        "useRSI",
        "UsesSpreadFilter",
        "useTesterSettings",
        "useTpManager",
        "useTradingSessions",
        "useTrailStop",
        "useTrendTrade",
        "UseWeeklyGoal",
        "YogaMode",
    ),
    "string": (
        "AsianEnd",
        "Currencies",
        "EA_Name",
        "StopTime",
        "StopTime_TP",
        "strategyName",
        "tradingDays",
        "TrailStarts",
        "TrailStops",
    ),
}
GOLDEN_GOOSE_KLP_PARAMETER_SCHEMA_V1: Mapping[str, ParameterSpecV1] = MappingProxyType(
    {
        name: ParameterSpecV1(value_type=kind, unit="source-unit-unspecified")
        for kind, names in _SCHEMA_TYPES.items()
        for name in names
    }
)

# Exact 16 source parameter snapshots: 13 Golden Goose and 3 KLP presets.
_SEED_ROWS = (
    SeedPresetIndexEntryV1(
        preset_id="gg-1k-harvest-goal-mt4",
        family_id="GOLDEN_GOOSE",
        preset_role="HARVEST",
        platform="MT4",
        source_manifest_path="inputs/strategy-seeds/manifest.json",
        source_sha256="d6560e88c369e460a663e76373f6dfa15bde2a7d1a612252dcd917f8379ce37c",
        fixture_name="gg-1k-harvest-goal-mt4.set",
        fixture_sha256="85f0229c281484f243443ce2ab563a0ffbba9b1d3faae66bcae44bb41f6dbbe8",
        crack_labelled=False,
        license_attestation_ref="seed-manifest-owner-attestation-2026-10-09",
        preset_version="seed-d6560e88c369",
    ),
    SeedPresetIndexEntryV1(
        preset_id="gg-2-5k-harvest-goal-mt4",
        family_id="GOLDEN_GOOSE",
        preset_role="HARVEST",
        platform="MT4",
        source_manifest_path="inputs/strategy-seeds/manifest.json",
        source_sha256="feef3685af23a6db5989d358fb99a6a8b18857130dddab6833dfb83cc3294bbf",
        fixture_name="gg-2-5k-harvest-goal-mt4.set",
        fixture_sha256="e5f7a2942710e4bbabe466aa78155fd6a0d714b41c9ea0929ae30590739cac39",
        crack_labelled=False,
        license_attestation_ref="seed-manifest-owner-attestation-2026-10-09",
        preset_version="seed-feef3685af23",
    ),
    SeedPresetIndexEntryV1(
        preset_id="gg-2k-harvest-goal-mt4",
        family_id="GOLDEN_GOOSE",
        preset_role="HARVEST",
        platform="MT4",
        source_manifest_path="inputs/strategy-seeds/manifest.json",
        source_sha256="777d38a4d059f5edd1d532d2213efef2bcd3ca12409aed05d543053fdab1e8b5",
        fixture_name="gg-2k-harvest-goal-mt4.set",
        fixture_sha256="f22c4a98918df171bec7dbd170592e6a2b89cf937d5d170141511420a00e83f1",
        crack_labelled=False,
        license_attestation_ref="seed-manifest-owner-attestation-2026-10-09",
        preset_version="seed-777d38a4d059",
    ),
    SeedPresetIndexEntryV1(
        preset_id="gg-dg",
        family_id="GOLDEN_GOOSE",
        preset_role="CHALLENGE",
        platform="MT5",
        source_manifest_path="inputs/strategy-seeds/manifest.json",
        source_sha256="99e694dcc2fec52e19fcfa8dc658da0d957b1e49515a61c3380e311226fb6324",
        fixture_name="gg-dg.set",
        fixture_sha256="58f31315b287d978c2b0e5ead44b26412caac7dc3bcfec93f2c9ae0011c7d31f",
        crack_labelled=False,
        license_attestation_ref="seed-manifest-owner-attestation-2026-10-09",
        preset_version="seed-99e694dcc2fe",
    ),
    SeedPresetIndexEntryV1(
        preset_id="gg-dg-modified-v3-4",
        family_id="GOLDEN_GOOSE",
        preset_role="PROFILE",
        platform="MT4",
        source_manifest_path="inputs/strategy-seeds/manifest.json",
        source_sha256="3d4b6424779fe4ea5ed711f70ad56fb7631965ec0ec3110b818c991036decfb7",
        fixture_name="gg-dg-modified-v3-4.set",
        fixture_sha256="d2dcc6df4efa2b6a4e591ed581fd7fbb58bd385a654f1dc0324767d1e2fa879a",
        crack_labelled=False,
        license_attestation_ref="seed-manifest-owner-attestation-2026-10-09",
        preset_version="seed-3d4b6424779f",
    ),
    SeedPresetIndexEntryV1(
        preset_id="gg-dt-mt4",
        family_id="GOLDEN_GOOSE",
        preset_role="CHALLENGE",
        platform="MT4",
        source_manifest_path="inputs/strategy-seeds/manifest.json",
        source_sha256="c34a72eef725c540854dcade57cc6ea9ff3279bd761263da2743768a6ff06826",
        fixture_name="gg-dt-mt4.set",
        fixture_sha256="6918d429b1a7ed74d07b9cc6f8188e3cd70cc9dd5d8f3480b410a09111d6e189",
        crack_labelled=False,
        license_attestation_ref="seed-manifest-owner-attestation-2026-10-09",
        preset_version="seed-c34a72eef725",
    ),
    SeedPresetIndexEntryV1(
        preset_id="gg-dt-mt5",
        family_id="GOLDEN_GOOSE",
        preset_role="CHALLENGE",
        platform="MT5",
        source_manifest_path="inputs/strategy-seeds/manifest.json",
        source_sha256="1c5e402d52ee6144f983a734aee203121041b23b94419e94683abaaa5b7607b9",
        fixture_name="gg-dt-mt5.set",
        fixture_sha256="8c6eb369d6bd646aabe6a1371307c00f86458c5e8ca233dd79a5d15ca9f055db",
        crack_labelled=False,
        license_attestation_ref="seed-manifest-owner-attestation-2026-10-09",
        preset_version="seed-1c5e402d52ee",
    ),
    SeedPresetIndexEntryV1(
        preset_id="gg-ma",
        family_id="GOLDEN_GOOSE",
        preset_role="CHALLENGE",
        platform="MT5",
        source_manifest_path="inputs/strategy-seeds/manifest.json",
        source_sha256="10e37510ae009e18e1c3e03beea8da3bff0aedea8b1a93e07a691cfacfc8a1c6",
        fixture_name="gg-ma.set",
        fixture_sha256="fe7e9e4a97b99d65e748b68b84d69121beae17ccd8c8a1277e0909072de089a4",
        crack_labelled=False,
        license_attestation_ref="seed-manifest-owner-attestation-2026-10-09",
        preset_version="seed-10e37510ae00",
    ),
    SeedPresetIndexEntryV1(
        preset_id="golden-goose-5k-harvest-goal-w-news-filter-mt4",
        family_id="GOLDEN_GOOSE",
        preset_role="HARVEST",
        platform="MT4",
        source_manifest_path="inputs/strategy-seeds/manifest.json",
        source_sha256="6c5a56d9ee9a091ab6005bc7365a15989ff4451780afdd79a1e0bd09443cea11",
        fixture_name="golden-goose-5k-harvest-goal-w-news-filter-mt4.set",
        fixture_sha256="94297658984b2e0dc247f39f020f5c8745024ffd5147c1fa9a0a72771a1a230d",
        crack_labelled=False,
        license_attestation_ref="seed-manifest-owner-attestation-2026-10-09",
        preset_version="seed-6c5a56d9ee9a",
    ),
    SeedPresetIndexEntryV1(
        preset_id="golden-goose-ftmo-challenge-mt4",
        family_id="GOLDEN_GOOSE",
        preset_role="CHALLENGE",
        platform="MT4",
        source_manifest_path="inputs/strategy-seeds/manifest.json",
        source_sha256="3f464603bb2658f5f8bd187f3f97e726a0a59982321d2192022a09f6d2b26928",
        fixture_name="golden-goose-ftmo-challenge-mt4.set",
        fixture_sha256="9568036beea27f7a6ed8aff4542fdca75cd4088e30fcf6228245833f90e014c5",
        crack_labelled=False,
        license_attestation_ref="seed-manifest-owner-attestation-2026-10-09",
        preset_version="seed-3f464603bb26",
    ),
    SeedPresetIndexEntryV1(
        preset_id="golden-goose-ftmo-challenge-mt5",
        family_id="GOLDEN_GOOSE",
        preset_role="CHALLENGE",
        platform="MT5",
        source_manifest_path="inputs/strategy-seeds/manifest.json",
        source_sha256="d41a1b4fa649f760e9c885c2a703da0cd275b426200b8c58b41ced92165b0c2f",
        fixture_name="golden-goose-ftmo-challenge-mt5.set",
        fixture_sha256="1bdec3963783fd3f87baeb94fbdd7b46ccd2e80f9209d38b363e363fa03a741f",
        crack_labelled=False,
        license_attestation_ref="seed-manifest-owner-attestation-2026-10-09",
        preset_version="seed-d41a1b4fa649",
    ),
    SeedPresetIndexEntryV1(
        preset_id="golden-goose-ftmo-verification-mt4",
        family_id="GOLDEN_GOOSE",
        preset_role="CHALLENGE",
        platform="MT4",
        source_manifest_path="inputs/strategy-seeds/manifest.json",
        source_sha256="32ee1d9c0ed642a7bec118303dc15225bf06d52245d596bef492a8b3874062f3",
        fixture_name="golden-goose-ftmo-verification-mt4.set",
        fixture_sha256="61afe8f924791570ba6b96ed85b46275098db0a7051042533ba961466ae6454f",
        crack_labelled=False,
        license_attestation_ref="seed-manifest-owner-attestation-2026-10-09",
        preset_version="seed-32ee1d9c0ed6",
    ),
    SeedPresetIndexEntryV1(
        preset_id="golden-goose-ftmo-verification-mt5",
        family_id="GOLDEN_GOOSE",
        preset_role="CHALLENGE",
        platform="MT5",
        source_manifest_path="inputs/strategy-seeds/manifest.json",
        source_sha256="da5b4548fe26bc9080bbe9e5ec1e0fbf1902419d9e191bea59f1f64d502dea3a",
        fixture_name="golden-goose-ftmo-verification-mt5.set",
        fixture_sha256="61043e603acfb3b7ba008c0b0962a19749fe51e856dd468371d64af41cdb1c27",
        crack_labelled=False,
        license_attestation_ref="seed-manifest-owner-attestation-2026-10-09",
        preset_version="seed-da5b4548fe26",
    ),
    SeedPresetIndexEntryV1(
        preset_id="klp-ftmo-m2-2-2-m2-100k-10-0-pct-mdlbal",
        family_id="KLP",
        preset_role="VERIFICATION",
        platform="MT5",
        source_manifest_path="inputs/strategy-seeds/manifest.json",
        source_sha256="50437614df715fe3f648a19830d98f39c0cf60226585d0a6c9b482c90a5dba0f",
        fixture_name="klp-ftmo-m2-2-2-m2-100k-10-0-pct-mdlbal.set",
        fixture_sha256="173b7ec6d7bd05e0342700a424db5d5ac2161edca4abeb34041c7889056dd5e7",
        crack_labelled=False,
        license_attestation_ref="seed-manifest-owner-attestation-2026-10-09",
        preset_version="seed-50437614df71",
    ),
    SeedPresetIndexEntryV1(
        preset_id="klp-ftmo-m2-2-2-m2-100k-2-0-pct-mdlbal",
        family_id="KLP",
        preset_role="POST_FUNDED",
        platform="MT5",
        source_manifest_path="inputs/strategy-seeds/manifest.json",
        source_sha256="f1e4d3b46aa20aaab8e3c0fcd49d0b93105115f66630b7adb4a00e06f7ffe11f",
        fixture_name="klp-ftmo-m2-2-2-m2-100k-2-0-pct-mdlbal.set",
        fixture_sha256="38ff0aa8d2a26275a042f7f88745d110ebb9c8238740bb9aedb777e989bbf231",
        crack_labelled=False,
        license_attestation_ref="seed-manifest-owner-attestation-2026-10-09",
        preset_version="seed-f1e4d3b46aa2",
    ),
    SeedPresetIndexEntryV1(
        preset_id="klp-ftmo-m2-2-2-m2-100k-5-0-pct-mdlbal",
        family_id="KLP",
        preset_role="VERIFICATION",
        platform="MT5",
        source_manifest_path="inputs/strategy-seeds/manifest.json",
        source_sha256="ea49ababbfd74f15d72a1708c49300f12c6f1f7d9751aa980d840af0373231ee",
        fixture_name="klp-ftmo-m2-2-2-m2-100k-5-0-pct-mdlbal.set",
        fixture_sha256="b2bf047681d739db77632b65c0b694680b198b742b619b65811748a3b1fa5608",
        crack_labelled=False,
        license_attestation_ref="seed-manifest-owner-attestation-2026-10-09",
        preset_version="seed-ea49ababbfd7",
    ),
)
EA_RECON_PRESET_REGISTRY_V1: Mapping[str, SeedPresetIndexEntryV1] = MappingProxyType(
    {entry.preset_id: entry for entry in _SEED_ROWS}
)

_SECRET_KEY = re.compile(
    r"(?:api.?key|secret|password|passwd|token|credential|private.?key|access.?key|authorization|auth.?token)",
    re.IGNORECASE | re.ASCII,
)
_SECRET_VALUE = tuple(
    re.compile(pattern, re.IGNORECASE | re.ASCII)
    for pattern in (
        r"AKIA[0-9A-Z]{16}",
        r"gh[pousr]_[A-Za-z0-9]{20,}",
        r"sk_(?:live|test)_[A-Za-z0-9]{12,}",
        r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    )
)


def _quarantine_secret_fields(raw_set: bytes) -> None:
    """Reject secret-like field names/value patterns without echoing content."""
    try:
        if raw_set.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = raw_set.decode("utf-16")
        elif raw_set.startswith(b"\xef\xbb\xbf"):
            text = raw_set.decode("utf-8-sig")
        else:
            try:
                text = raw_set.decode("utf-8")
            except UnicodeDecodeError:
                text = raw_set.decode(
                    "utf-16-le" if raw_set[1::2].count(0) > len(raw_set) // 6 else "utf-16-be"
                )
    except (AttributeError, UnicodeDecodeError):
        return  # The canonical parser returns its own content-free byte error.
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(";") or "=" not in stripped:
            continue
        name, cell = stripped.split("=", 1)
        if _SECRET_KEY.search(name.strip()):
            raise MtSetImportError("SECRET_FIELD_QUARANTINED")
        value = cell.strip().split("||", 1)[0]
        if any(pattern.search(value) for pattern in _SECRET_VALUE):
            raise MtSetImportError("SECRET_VALUE_QUARANTINED")


def import_ea_seed_preset(preset_id: str, raw_set: bytes) -> ImportedSeedPresetV1:
    """Import one registered Golden Goose/KLP SET, retaining original digest.

    The exact source digest or the reviewed sanitized fixture digest is required.
    A caller cannot relabel arbitrary SET bytes as an approved seed preset.
    """
    entry = EA_RECON_PRESET_REGISTRY_V1.get(preset_id)
    if entry is None:
        raise MtSetImportError("UNKNOWN_SEED_PRESET")
    if type(raw_set) is not bytes:
        raise MtSetImportError("INVALID_SET_BYTES")
    if not raw_set:
        raise MtSetImportError("INVALID_SET_BYTES")
    if len(raw_set) > MAX_SET_BYTES:
        raise MtSetImportError("EXCESSIVE_SIZE")
    _quarantine_secret_fields(raw_set)
    digest = hashlib.sha256(raw_set).hexdigest()
    if digest not in {entry.source_sha256, entry.fixture_sha256}:
        raise MtSetImportError("SOURCE_HASH_MISMATCH")
    metadata = SetImportMetadataV1(
        preset_id=entry.preset_id,
        preset_version=entry.preset_version,
        platform=entry.platform,
        source_family="TITAN_X",
        source_locator=entry.source_locator,
        instrument_mapping=InstrumentMappingV1(
            source_symbol="UNBOUND",
            instrument_id="UNBOUND",
            mapping_version="unbound-v1",
        ),
        timezone_mapping=TimezoneMappingV1(
            source_timezone=None,
            iana_timezone=None,
            mapping_version="unresolved-v1",
        ),
        license_status="TASK_AUTHORIZED",
        license_reference=entry.license_attestation_ref,
    )
    parsed = parse_mt_set(raw_set, schema=GOLDEN_GOOSE_KLP_PARAMETER_SCHEMA_V1, metadata=metadata)
    mappings = tuple(
        ParameterFieldMappingV1(
            source_name=name,
            canonical_name=name,
            value_type=parameter.value_type,
            unit=parameter.unit,
        )
        for name, parameter in sorted(
            parsed.parameters.items(), key=lambda item: item[0].casefold()
        )
    )
    return ImportedSeedPresetV1(
        schema_version="1",
        family_id=entry.family_id,
        preset_role=entry.preset_role,
        preset_id=entry.preset_id,
        preset_version=entry.preset_version,
        platform=entry.platform,
        source_manifest_path="inputs/strategy-seeds/manifest.json",
        source_locator=entry.source_locator,
        source_sha256=entry.source_sha256,
        source_manifest_sha256=SEED_MANIFEST_SHA256,
        crack_labelled=entry.crack_labelled,
        license_attestation_ref=entry.license_attestation_ref,
        field_mappings=mappings,
        parsed_set=parsed,
    )
