"""Offline, nonsecret preflight for proposed Neon and Cloudflare resources.

This module never contacts providers or resolves vault aliases. Exit codes are
0 (ready for a later review), 1 (invalid/unsafe intent), and 2 (blockers).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, SupportsIndex
from urllib.parse import urlsplit

import yaml

from leviathan_core.numeric import NumericError, canonical_json, exact_add, parse_decimal, parse_int

ENVS = ("development", "staging", "live")
ROOT_KEYS = frozenset({"schema_version", "project", "environments"})
ENV_KEYS = frozenset({"identity", "resources"})
RESOURCE_KEYS = frozenset({
    "provider", "kind", "name", "purpose", "requirements", "owner", "approver",
    "region", "jurisdiction", "data_classification", "tier", "minimum_tier",
    "cost", "credential_aliases", "neon", "binding", "retention",
})
COST_KEYS = frozenset({"currency", "monthly_cap", "price_source", "retrieved_on"})
NEON_KEYS = frozenset({"project", "branch", "role"})
RETENTION_KEYS = frozenset({"days", "lock_intent", "legal_hold", "delete_on_destroy"})
ALIAS = re.compile(
    r"vault://leviathan-ai/(development|live)/(neon|cloudflare|cloudflare-r2)/[A-Z][A-Z0-9_]*\Z"
)
NAME = re.compile(r"[a-z][a-z0-9-]*\Z")
REQ = re.compile(r"LEV-REQ-[0-9]{3}\Z")
MONEY = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,2})?\Z")
CURRENCY = re.compile(r"[A-Z]{3}\Z")
PURPOSES = frozenset({"licensing", "async_jobs", "cold_archive"})
REGIONS = frozenset({"us-east", "us-central", "global"})
JURISDICTIONS = frozenset({"US"})
TIERS = frozenset({"minimum", "minimum-paid-to-confirm"})
SECRET_KEY = re.compile(
    r"(?:password|passwd|token|secret|api[_-]?key|private[_-]?key|credential)", re.I
)
SECRET_VALUE = re.compile(
    r"(?:-----BEGIN |\bBearer\s+|\bAKIA[0-9A-Z]{16}\b|\bsk[-_][A-Za-z0-9]{8,}"
    r"|(?:password|passwd|token|secret|api[_-]?key|private[_-]?key)\s*[:=]"
    r"|factory-admin|(?:postgres(?:ql)?|mysql|mongodb|redis)://)",
    re.I,
)
Row = tuple[str, str, str, dict[str, Any], tuple[str, Decimal] | None]
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _members_digest(values: frozenset[str]) -> str:
    return hashlib.sha256(canonical_json(sorted(values))).hexdigest()


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("REGISTRY_INVALID")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class ResourceIntentRegistries:
    """Fully validated immutable snapshots built from reviewed local file bytes."""

    registry_json_bytes: bytes = field(repr=False)
    requirements_map_bytes: bytes = field(repr=False)
    registry_sha256: str = field(init=False)
    owner_snapshot_id: str = field(init=False)
    owners: frozenset[str] = field(init=False, repr=False)
    price_source_snapshot_id: str = field(init=False)
    price_sources: frozenset[str] = field(init=False, repr=False)
    requirements_map_sha256: str = field(init=False)
    requirement_ids: frozenset[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        try:
            if (
                type(self.registry_json_bytes) is not bytes
                or type(self.requirements_map_bytes) is not bytes
                or len(self.registry_json_bytes) > 65_536
                or len(self.requirements_map_bytes) > 2_097_152
            ):
                raise ValueError
            document = json.loads(
                self.registry_json_bytes.decode("utf-8"), object_pairs_hook=_json_object
            )
            required = frozenset({
                "schema_version", "owner_snapshot_id", "owners",
                "price_source_snapshot_id", "price_sources", "requirements_map_sha256",
            })
            if (
                not _shape(document, required, required)
                or type(document["schema_version"]) is not int
                or document["schema_version"] != 1
            ):
                raise ValueError
            owners_raw = document["owners"]
            prices_raw = document["price_sources"]
            if (
                not isinstance(owners_raw, list)
                or not owners_raw
                or not isinstance(prices_raw, list)
                or not prices_raw
                or not all(isinstance(value, str) and NAME.fullmatch(value) for value in owners_raw)
                or not all(_safe_price_url(value) for value in prices_raw)
            ):
                raise ValueError
            owners = frozenset(owners_raw)
            prices = frozenset(prices_raw)
            if len(owners) != len(owners_raw) or len(prices) != len(prices_raw):
                raise ValueError
            owner_id = document["owner_snapshot_id"]
            price_id = document["price_source_snapshot_id"]
            map_id = document["requirements_map_sha256"]
            if (
                not isinstance(owner_id, str)
                or owner_id != _members_digest(owners)
                or not isinstance(price_id, str)
                or price_id != _members_digest(prices)
                or not isinstance(map_id, str)
                or not SHA256.fullmatch(map_id)
                or map_id != hashlib.sha256(self.requirements_map_bytes).hexdigest()
            ):
                raise ValueError
            requirement_document = yaml.load(
                self.requirements_map_bytes.decode("utf-8"), Loader=_UniqueLoader
            )
            if not isinstance(requirement_document, dict):
                raise ValueError
            records = requirement_document.get("requirements")
            if not isinstance(records, list) or not records:
                raise ValueError
            ids = [record.get("id") for record in records if isinstance(record, dict)]
            if len(ids) != len(records) or not all(isinstance(value, str) for value in ids):
                raise ValueError
            requirement_ids = frozenset(ids)
            if len(requirement_ids) != len(ids):
                raise ValueError
            object.__setattr__(
                self, "registry_sha256", hashlib.sha256(self.registry_json_bytes).hexdigest()
            )
            object.__setattr__(self, "owner_snapshot_id", owner_id)
            object.__setattr__(self, "owners", owners)
            object.__setattr__(self, "price_source_snapshot_id", price_id)
            object.__setattr__(self, "price_sources", prices)
            object.__setattr__(self, "requirements_map_sha256", map_id)
            object.__setattr__(self, "requirement_ids", requirement_ids)
        except (UnicodeError, ValueError, TypeError, yaml.YAMLError):
            raise ValueError("REGISTRY_INVALID") from None

    def __copy__(self) -> None:
        raise TypeError("immutable registries")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("immutable registries")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> tuple[Any, ...]:
        raise TypeError("immutable registries")


@dataclass(frozen=True, slots=True)
class ValidationResult:
    exit_code: int
    report: str
    errors: tuple[str, ...]
    blockers: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.exit_code) is not int
            or self.exit_code not in {0, 1, 2}
            or not isinstance(self.report, str)
            or type(self.errors) is not tuple
            or type(self.blockers) is not tuple
            or not all(isinstance(code, str) for code in (*self.errors, *self.blockers))
        ):
            raise TypeError("invalid result")

    def __copy__(self) -> None:
        raise TypeError("immutable result")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("immutable result")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> tuple[Any, ...]:
        raise TypeError("immutable result")


class _UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader: _UniqueLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise ValueError("invalid mapping")
        result[key] = loader.construct_object(value_node)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def load_manifest(path: Path) -> object:
    """Load a local YAML or JSON document without duplicate keys or arbitrary tags."""
    try:
        if path.stat().st_size > 262_144:
            raise ValueError("document too large")
        content = path.read_text(encoding="utf-8")
        if len(content.encode("utf-8")) > 262_144:
            raise ValueError("document too large")
        return yaml.load(content, Loader=_UniqueLoader)
    except (OSError, UnicodeError, yaml.YAMLError, ValueError):
        raise ValueError("INVALID_DOCUMENT") from None


def load_registries(
    registry_path: Path, requirements_map_path: Path
) -> ResourceIntentRegistries:
    """Load only local, bounded reviewed snapshots; no default path is inferred."""
    try:
        if registry_path.stat().st_size > 65_536:
            raise ValueError
        if requirements_map_path.stat().st_size > 2_097_152:
            raise ValueError
        return ResourceIntentRegistries(
            registry_path.read_bytes(), requirements_map_path.read_bytes()
        )
    except (OSError, ValueError):
        raise ValueError("REGISTRY_INVALID") from None


def _shape(value: object, allowed: frozenset[str], required: frozenset[str]) -> bool:
    return (
        isinstance(value, dict)
        and all(isinstance(key, str) for key in value)
        and set(value) <= allowed
        and required <= set(value)
    )


def _safe_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value) <= 160
        and value.isascii()
        and all(32 <= ord(char) <= 126 for char in value)
        and SECRET_VALUE.search(value) is None
        and "://" not in value
    )


def _no_secret_fields(
    value: object,
    active: set[int] | None = None,
    depth: int = 0,
    visits: list[int] | None = None,
) -> bool:
    if depth > 32:
        return False
    if active is None:
        active = set()
    if visits is None:
        visits = [0]
    visits[0] += 1
    if visits[0] > 10_000:
        return False
    if isinstance(value, (dict, list)):
        if id(value) in active:
            return False
        active.add(id(value))
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                return False
            if key != "credential_aliases" and SECRET_KEY.search(key):
                return False
            if not _no_secret_fields(child, active, depth + 1, visits):
                return False
    elif isinstance(value, list):
        if not all(_no_secret_fields(child, active, depth + 1, visits) for child in value):
            return False
    elif isinstance(value, str) and SECRET_VALUE.search(value):
        return False
    if isinstance(value, (dict, list)):
        active.remove(id(value))
    return True


def _safe_price_url(value: object) -> bool:
    if (
        not isinstance(value, str)
        or len(value) > 300
        or not value.isascii()
        or SECRET_VALUE.search(value)
    ):
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and bool(hostname)
        and hostname != "localhost"
        and hostname is not None
        and "." in hostname
        and username is None
        and password is None
        and port in (None, 443)
        and not parsed.query
        and not parsed.fragment
        and not re.search(r"[\s\\]", value)
    )


def _money(value: object) -> Decimal | None:
    if not isinstance(value, str) or not MONEY.fullmatch(value):
        return None
    try:
        return parse_decimal(value, field="monthly_cap", max_sig_digits=34, max_abs_adjusted=38)
    except NumericError:
        return None


def _cost(
    resource: dict[str, Any],
    today: date,
    where: str,
    blockers: list[str],
    errors: list[str],
    registries: ResourceIntentRegistries | None,
) -> tuple[str, Decimal] | None:
    cost = resource.get("cost")
    if cost is None:
        blockers.append(f"{where}: COST_MISSING")
        return None
    if not _shape(cost, COST_KEYS, frozenset()):
        errors.append(f"{where}: COST_INVALID")
        return None
    currency = cost.get("currency")
    amount = _money(cost.get("monthly_cap"))
    if currency is None or cost.get("monthly_cap") is None:
        blockers.append(f"{where}: COST_CAP_MISSING")
    elif not isinstance(currency, str) or not CURRENCY.fullmatch(currency) or amount is None:
        errors.append(f"{where}: COST_CAP_INVALID")
    elif amount <= 0:
        blockers.append(f"{where}: COST_CAP_PLACEHOLDER")
    source = cost.get("price_source")
    retrieved = cost.get("retrieved_on")
    if source is None or retrieved is None:
        blockers.append(f"{where}: PRICE_EVIDENCE_MISSING")
    elif not _safe_price_url(source):
        errors.append(f"{where}: PRICE_SOURCE_INVALID")
    else:
        if registries is not None and source not in registries.price_sources:
            blockers.append(f"{where}: PRICE_SOURCE_UNAPPROVED")
        try:
            if not isinstance(retrieved, str) or not re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}", retrieved
            ):
                raise ValueError
            retrieved_date = date.fromisoformat(retrieved)
            age = (today - retrieved_date).days
            if age < 0 or age > 30:
                blockers.append(f"{where}: PRICE_EVIDENCE_STALE")
        except ValueError:
            errors.append(f"{where}: PRICE_DATE_INVALID")
    if isinstance(currency, str) and CURRENCY.fullmatch(currency) and amount is not None:
        return currency, amount
    return None


def _resource(
    resource: object,
    env: str,
    index: int,
    today: date,
    blockers: list[str],
    errors: list[str],
    registries: ResourceIntentRegistries | None,
) -> Row | None:
    where = f"{env}[{index}]"
    required = RESOURCE_KEYS - {"neon", "binding", "retention", "cost", "requirements"}
    if not _shape(resource, RESOURCE_KEYS, required):
        errors.append(f"{where}: RESOURCE_INVALID")
        return None
    assert isinstance(resource, dict)
    provider, kind, name = resource["provider"], resource["kind"], resource["name"]
    if not isinstance(provider, str) or not isinstance(kind, str) or (provider, kind) not in {
        ("neon", "database"), ("cloudflare", "worker"),
        ("cloudflare", "queue"), ("cloudflare", "r2"),
    }:
        errors.append(f"{where}: VENDOR_KIND_INVALID")
        return None
    if not isinstance(name, str) or not NAME.fullmatch(name) or len(name) > 63:
        errors.append(f"{where}: RESOURCE_NAME_INVALID")
        return None
    for attribute in ("purpose", "owner", "approver", "region", "jurisdiction", "tier"):
        if not _safe_text(resource[attribute]):
            errors.append(f"{where}: RESOURCE_METADATA_INVALID")
            return None
    if (
        resource["purpose"] not in PURPOSES
        or resource["region"] not in REGIONS
        or resource["jurisdiction"] not in JURISDICTIONS
        or resource["tier"] not in TIERS
    ):
        errors.append(f"{where}: RESOURCE_METADATA_INVALID")
        return None
    if registries is not None and (
        resource["owner"] not in registries.owners
        or resource["approver"] not in registries.owners
    ):
        blockers.append(f"{where}: OWNER_UNAPPROVED")
    classification = resource["data_classification"]
    if not isinstance(classification, str) or classification not in {
        "public", "internal", "confidential", "restricted"
    }:
        errors.append(f"{where}: CLASSIFICATION_INVALID")
    if type(resource["minimum_tier"]) is not bool:
        errors.append(f"{where}: MINIMUM_TIER_INVALID")
    elif not resource["minimum_tier"]:
        blockers.append(f"{where}: MINIMUM_TIER_UNCONFIRMED")
    requirements = resource.get("requirements")
    if requirements is None or requirements == []:
        blockers.append(f"{where}: REQUIREMENT_MISSING")
    elif not isinstance(requirements, list) or not all(
        isinstance(r, str) and REQ.fullmatch(r) for r in requirements
    ):
        errors.append(f"{where}: REQUIREMENT_INVALID")
    elif registries is not None and not set(requirements) <= registries.requirement_ids:
        blockers.append(f"{where}: REQUIREMENT_UNMAPPED")
    aliases = resource["credential_aliases"]
    if not isinstance(aliases, list) or not aliases:
        blockers.append(f"{where}: CREDENTIAL_ALIAS_MISSING")
    else:
        expected_env = "live" if env == "live" else "development"
        expected_provider = (
            "neon" if provider == "neon" else "cloudflare-r2" if kind == "r2" else "cloudflare"
        )
        for alias in aliases:
            match = ALIAS.fullmatch(alias) if isinstance(alias, str) else None
            if (
                match is None
                or match.group(1) != expected_env
                or match.group(2) != expected_provider
            ):
                errors.append(f"{where}: CREDENTIAL_SCOPE_INVALID")
                break
    if provider == "neon":
        neon = resource.get("neon")
        if (
            "binding" in resource
            or "retention" in resource
            or not _shape(neon, NEON_KEYS, NEON_KEYS)
            or not all(
                isinstance(neon, dict)
                and isinstance(neon[field], str)
                and NAME.fullmatch(neon[field])
                for field in NEON_KEYS
            )
        ):
            errors.append(f"{where}: NEON_INTENT_INVALID")
    elif (
        "neon" in resource
        or not isinstance(resource.get("binding"), str)
        or not NAME.fullmatch(resource["binding"])
    ):
        errors.append(f"{where}: CLOUDFLARE_BINDING_INVALID")
    if kind == "r2":
        retention = resource.get("retention")
        if not _shape(retention, RETENTION_KEYS, RETENTION_KEYS):
            errors.append(f"{where}: RETENTION_INVALID")
        else:
            assert isinstance(retention, dict)
            lock = retention["lock_intent"]
            try:
                days = parse_int(
                    retention["days"], field="retention.days", min_value=0, max_value=365_000
                )
            except NumericError:
                days = None
            if (
                days is None
                or any(
                    type(retention[field]) is not bool
                    for field in ("legal_hold", "delete_on_destroy")
                )
                or not isinstance(lock, str)
                or lock not in {"required", "not_required"}
            ):
                errors.append(f"{where}: RETENTION_INVALID")
            elif retention["delete_on_destroy"] or (
                resource["purpose"] == "cold_archive"
                and (
                    days < 2557
                    or lock != "required"
                    or not retention["legal_hold"]
                )
            ):
                blockers.append(f"{where}: RETENTION_POLICY_BLOCKED")
    elif "retention" in resource:
        errors.append(f"{where}: RETENTION_INVALID")
    cost = _cost(resource, today, where, blockers, errors, registries)
    return env, kind, name, resource, cost


def _inspect(
    manifest: object, today: date, registries: ResourceIntentRegistries | None
) -> tuple[list[Row], list[str], list[str]]:
    errors: list[str] = []
    blockers: list[str] = []
    rows: list[Row] = []
    if not _shape(manifest, ROOT_KEYS, ROOT_KEYS):
        return rows, ["MANIFEST_INVALID"], blockers
    assert isinstance(manifest, dict)
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 1
        or manifest["project"] != "leviathan-ai"
    ):
        return rows, ["SCOPE_OR_VERSION_INVALID"], blockers
    if not _no_secret_fields(manifest):
        return rows, ["SECRET_OR_UNSAFE_FIELD"], blockers
    envs = manifest["environments"]
    if not isinstance(envs, dict) or set(envs) != set(ENVS):
        return rows, ["ENVIRONMENTS_INVALID"], blockers
    identities: set[str] = set()
    names: set[tuple[str, str]] = set()
    neon_branches: set[tuple[str, str]] = set()
    alias_owners: dict[str, str] = {}
    for env in ENVS:
        item = envs[env]
        if not _shape(item, ENV_KEYS, ENV_KEYS):
            errors.append(f"{env}: ENVIRONMENT_INVALID")
            continue
        identity = item["identity"]
        if (
            not isinstance(identity, str)
            or not NAME.fullmatch(identity)
            or env not in identity
            or identity in identities
        ):
            errors.append(f"{env}: ENVIRONMENT_IDENTITY_INVALID")
        else:
            identities.add(identity)
        resources = item["resources"]
        if not isinstance(resources, list) or not resources:
            errors.append(f"{env}: RESOURCES_INVALID")
            continue
        for index, candidate in enumerate(resources):
            row = _resource(candidate, env, index, today, blockers, errors, registries)
            if row is None:
                continue
            _, kind, name, resource, _ = row
            key = kind, name
            if key in names:
                errors.append(f"{env}[{index}]: RESOURCE_IDENTITY_REUSED")
            names.add(key)
            if kind == "database" and isinstance(resource.get("neon"), dict):
                branch = resource["neon"]
                pair = branch.get("project"), branch.get("branch")
                if all(isinstance(part, str) for part in pair) and pair in neon_branches:
                    errors.append(f"{env}[{index}]: NEON_BRANCH_REUSED")
                if all(isinstance(part, str) for part in pair):
                    neon_branches.add(pair)
            aliases = resource["credential_aliases"]
            if isinstance(aliases, list):
                for alias in aliases:
                    if not isinstance(alias, str) or not ALIAS.fullmatch(alias):
                        continue
                    owner_env = alias_owners.get(alias)
                    if owner_env is not None and owner_env != env:
                        errors.append(f"{env}[{index}]: CREDENTIAL_ALIAS_REUSED")
                    alias_owners[alias] = env
            rows.append(row)
        for kind in ("database", "worker"):
            if not any(
                row[0] == env and row[1] == kind and row[3]["purpose"] == "licensing"
                for row in rows
            ):
                blockers.append(f"{env}: LICENSING_{kind.upper()}_MISSING")
    return rows, errors, blockers


def _digest(row: Row) -> str:
    canonical = canonical_json(
        {"environment": row[0], "kind": row[1], "name": row[2]},
    )
    return hashlib.sha256(canonical).hexdigest()[:12]


def validate_resource_intent(
    manifest: object,
    *,
    today: date,
    previous: object | None = None,
    registries: ResourceIntentRegistries | None = None,
    historical: bool = False,
) -> ValidationResult:
    """Return a redacted preflight; historical evaluations cannot be ready."""
    if type(today) is not date or type(historical) is not bool:
        return ValidationResult(
            1,
            "RESOURCE INTENT PREFLIGHT\nevaluation_date (unavailable)\nINVALID\n- TODAY_INVALID",
            ("TODAY_INVALID",),
            (),
        )
    if registries is not None and type(registries) is not ResourceIntentRegistries:
        registries = None
    snapshot_lines = ["RESOURCE INTENT PREFLIGHT", f"evaluation_date {today.isoformat()}"]
    if historical:
        snapshot_lines.append("HISTORICAL")
    snapshot_lines.append("SNAPSHOTS")
    if registries is None:
        snapshot_lines.append("(unavailable)")
    else:
        snapshot_lines.extend((
            f"registries_sha256 {registries.registry_sha256}",
            f"owner_snapshot_id {registries.owner_snapshot_id}",
            f"price_source_snapshot_id {registries.price_source_snapshot_id}",
            f"requirements_map_sha256 {registries.requirements_map_sha256}",
        ))
    rows, errors, blockers = _inspect(manifest, today, registries)
    if historical:
        blockers.append("HISTORICAL_EVALUATION")
    if registries is None:
        blockers.append("REGISTRY_MISSING")
    previous_rows: list[Row] = []
    if previous is not None:
        previous_rows, previous_errors, _ = _inspect(previous, today, registries)
        if previous_errors:
            errors.append("PREVIOUS_INVALID")
    if errors:
        ordered = tuple(sorted(set(errors)))
        return ValidationResult(
            1,
            "\n".join((*snapshot_lines, "INVALID", *(f"- {code}" for code in ordered))),
            ordered,
            tuple(sorted(set(blockers))),
        )
    current = {(row[0], row[1], row[2]): row for row in rows}
    old = {(row[0], row[1], row[2]): row for row in previous_rows}
    diff: list[str] = []
    for key in sorted(current.keys() | old.keys()):
        new_row, old_row = current.get(key), old.get(key)
        if new_row is None:
            symbol, chosen = "-", old_row
        elif old_row is None:
            symbol, chosen = "+", new_row
        elif new_row[3] != old_row[3]:
            symbol, chosen = "~", new_row
        else:
            continue
        assert chosen is not None
        diff.append(f"{symbol} {chosen[0]} {chosen[1]} resource#{_digest(chosen)}")
    totals: dict[tuple[str, str], Decimal] = {}
    for env, _, _, _, cost in rows:
        if cost is None:
            continue
        currency, cap = cost
        cost_key = env, currency
        try:
            totals[cost_key] = exact_add(totals.get(cost_key, Decimal(0)), cap)
        except NumericError:
            return ValidationResult(
                1,
                "\n".join((*snapshot_lines, "INVALID", "- COST_TOTAL_INVALID")),
                ("COST_TOTAL_INVALID",),
                tuple(sorted(set(blockers))),
            )
    lines = list(snapshot_lines)
    lines.append("DIFF")
    lines.extend(diff or ["(no changes)"])
    lines.append("DECLARED MONTHLY CAPS (not provider quotes)")
    lines.extend(
        f"{env} {currency} {totals[(env, currency)]:.2f}"
        for env, currency in sorted(totals)
    )
    lines.append("BLOCKERS")
    ordered_blockers = tuple(sorted(set(blockers)))
    lines.extend(f"- {code}" for code in ordered_blockers)
    if not ordered_blockers:
        lines.append("(none)")
    return ValidationResult(2 if ordered_blockers else 0, "\n".join(lines), (), ordered_blockers)


def _cli_prefix(evaluation_date: str, historical: bool) -> str:
    lines = ["RESOURCE INTENT PREFLIGHT", f"evaluation_date {evaluation_date}"]
    if historical:
        lines.append("HISTORICAL")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline resource intent preflight")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--against", type=Path)
    parser.add_argument("--today")
    parser.add_argument("--historical", action="store_true")
    parser.add_argument("--registries", type=Path)
    parser.add_argument("--requirements-map", type=Path)
    args = parser.parse_args(argv)
    actual_today = datetime.now(UTC).date()
    if args.today is not None and not args.historical:
        print(
            _cli_prefix(actual_today.isoformat(), False)
            + "INVALID\n- TODAY_OVERRIDE_REQUIRES_HISTORICAL"
        )
        return 1
    if args.historical and args.today is None:
        print(_cli_prefix(actual_today.isoformat(), True) + "INVALID\n- HISTORICAL_DATE_REQUIRED")
        return 1
    try:
        today = date.fromisoformat(args.today) if args.today else actual_today
    except ValueError:
        print(_cli_prefix("(unavailable)", args.historical) + "INVALID\n- DOCUMENT_OR_DATE_INVALID")
        return 1
    try:
        current = load_manifest(args.manifest)
        previous = load_manifest(args.against) if args.against else None
    except ValueError:
        print(
            _cli_prefix(today.isoformat(), args.historical)
            + "INVALID\n- DOCUMENT_OR_DATE_INVALID"
        )
        return 1
    registries = None
    if args.registries is not None and args.requirements_map is not None:
        try:
            registries = load_registries(args.registries, args.requirements_map)
        except ValueError:
            print(_cli_prefix(today.isoformat(), args.historical) + "BLOCKERS\n- REGISTRY_INVALID")
            return 2
    result = validate_resource_intent(
        current, today=today, previous=previous, registries=registries,
        historical=args.historical,
    )
    print(result.report)
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
