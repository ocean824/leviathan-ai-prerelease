"""Pure CFG-001 semantic validation. No vault, risk, routing or OMS imports."""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Collection, Mapping
from decimal import Decimal, InvalidOperation
from typing import Any, Literal, NoReturn, cast
from urllib.parse import urlsplit

from leviathan_core.configuration.models import (
    EndpointRegistryV1,
    ParameterRuleV1,
    ParameterSetV1,
    ParameterType,
    ParameterValue,
    ProfileEnvironment,
    ProfileMode,
    ProfileValidationError,
    ReferenceCatalogV1,
    SecretReferenceV1,
    StrategyProfileV1,
    ValidationIssue,
    _canonical_number,
    _decimal,
)
from leviathan_core.configuration.parser import ParseFailureError, parse_document

_IDENTIFIER = re.compile(r"[a-z][a-z0-9_-]{1,63}\Z", re.ASCII)
_SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z",
    re.ASCII,
)
# Mirrors SEC-001's canonical provider slug: _provider() yields a 3..60 character
# uppercase alphanumeric/underscore name, stored as lowercase with hyphens.
_PROVIDER = r"[a-z0-9]+(?:-[a-z0-9]+)*"
_NAME = r"[A-Z][A-Z0-9_]{2,79}"
_VAULT_REF = re.compile(
    rf"vault://(?P<scope>[a-z][a-z0-9-]{{1,63}})/"
    rf"(?P<environment>[a-z][a-z0-9-]{{1,31}})/"
    rf"(?P<provider>{_PROVIDER})/(?P<name>{_NAME})\Z",
    re.ASCII,
)
_SENSITIVE_KEY = re.compile(
    r"(?:api[_-]?key|secret|password|passwd|token|credential|private[_-]?key|"
    r"access[_-]?key|auth[_-]?key)",
    re.IGNORECASE,
)
_CREDENTIAL_LABEL = (
    r"(?:api[_-]?key|secret|password|passwd|token|credential|private[_-]?key|"
    r"access[_-]?key|auth[_-]?key)"
)
_ASSIGNMENT = re.compile(rf"\b{_CREDENTIAL_LABEL}\s*[:=]\s*['\"]?\S+", re.IGNORECASE)
_QUOTED_ASSIGNMENT = re.compile(
    rf"['\"]{_CREDENTIAL_LABEL}['\"]\s*:\s*['\"]?\S+", re.IGNORECASE
)
_QUOTED_REPR = re.compile(
    rf"['\"]{_CREDENTIAL_LABEL}['\"]\s*,\s*['\"]\S+", re.IGNORECASE
)
_BEARER = re.compile(r"\bbearer\s+\S+", re.IGNORECASE)
_PEM = re.compile(r"-----BEGIN[^\n-]{0,80}(?:PRIVATE KEY|SECRET|TOKEN)[^\n-]{0,80}-----")
_TOKEN = re.compile(r"[A-Za-z0-9+/_=-]{20,}")
_NORMALIZED_ASSIGNMENT = re.compile(
    r"(?:api key|access token|client secret|authorization|token|password|passwd|"
    r"secret|credential|private key|auth key|access key)"
    r"(?: [a-z0-9]+){0,2}\s*[:=]\s*\S+",
    re.IGNORECASE,
)
_USER_PASS = re.compile(r"[A-Za-z0-9._-]+:[^@\s/]+@")
_IDENTIFIER_VALUE = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z", re.ASCII)
_SYMBOL_VALUE = re.compile(
    r"(?P<provider>[a-z0-9]+(?:-[a-z0-9]+)*):(?P<symbol>[A-Z][A-Z0-9._-]{0,31})\Z",
    re.ASCII,
)
_HOST = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z", re.ASCII
)
_URL_PATH = re.compile(r"[A-Za-z0-9/._-]*\Z", re.ASCII)
_DURATION = re.compile(r"P(?=.*[0-9])(?:[0-9]+D)?(?:T(?:[0-9]+H)?(?:[0-9]+M)?(?:[0-9]+S)?)?\Z")
_INTEGER_NS = re.compile(r"(?:0|[1-9][0-9]*)\Z", re.ASCII)
_STRING_KINDS = frozenset({
    "enum", "identifier", "symbol", "decimal_text", "duration", "url",
    "endpoint_id", "vault_ref"
})
_PROFILE_FIELDS = frozenset({
    "schema_version", "name", "version", "strategy_id", "strategy_version", "mode",
    "environment", "connectors", "data_feeds", "risk_guard", "parameter_schema",
    "parameters", "secret_refs", "published",
})
_PARAMETER_SET_FIELDS = frozenset({
    "schema_version", "name", "version", "strategy_id", "strategy_version", "schema",
    "values", "locked",
})
_RULE_FIELDS = frozenset({
    "type", "minimum", "maximum", "kind", "choices", "provider", "hosts"
})
def _fail(code: str, path: str) -> NoReturn:
    raise ProfileValidationError((ValidationIssue(code, path),))


def _secret_mismatch(code: str, path: str) -> NoReturn:
    raise ProfileValidationError((
        ValidationIssue(code, path), ValidationIssue("INVALID_SECRET_REFERENCE", path)
    ))


def _looks_like_credential(value: str) -> bool:
    normalized = re.sub(r"[\s._-]+", " ", value)
    if _NORMALIZED_ASSIGNMENT.search(normalized) or _USER_PASS.search(value):
        return True
    if any(pattern.search(value) for pattern in
           (_ASSIGNMENT, _QUOTED_ASSIGNMENT, _QUOTED_REPR, _BEARER, _PEM)):
        return True
    for match in _TOKEN.finditer(value):
        token = match.group()
        frequencies = Counter(token)
        entropy = -sum((count / len(token)) * math.log2(count / len(token))
                       for count in frequencies.values())
        if entropy >= 3.6 and len(frequencies) >= 10:
            return True
    return False


def _scan_string_values(root: dict[str, Any]) -> None:
    allowed_top = _PROFILE_FIELDS | _PARAMETER_SET_FIELDS
    stack: list[tuple[Any, str]] = [(root, "")]
    while stack:
        value, path = stack.pop()
        if isinstance(value, dict):
            entries = list(value.items())
            if path == "":
                entries.sort(key=lambda pair: pair[0] in ("parameters", "values"))
            for key, child in entries:
                child_path = f"/{key}" if path == "" and key in allowed_top else path
                stack.append((child, child_path))
        elif isinstance(value, list):
            stack.extend((child, f"{path}/{index}") for index, child in enumerate(value))
        elif (isinstance(value, str) and not (path == "/secret_refs" and "://" in value)
              and not value.startswith(("https://", "vault://"))
              and _looks_like_credential(value)):
            _fail("SECRET_PLAINTEXT", path)


def _reference_catalog(
    value: ReferenceCatalogV1 | Mapping[str, Collection[str]] | None,
) -> ReferenceCatalogV1:
    if value is None:
        return ReferenceCatalogV1(frozenset(), frozenset(), frozenset())
    if isinstance(value, ReferenceCatalogV1):
        return value
    if not isinstance(value, Mapping):
        _fail("INVALID_TYPE", "/available_references")
    fields = ("connectors", "data_feeds", "risk_guards")
    if set(value) != set(fields):
        _fail("INVALID_VALUE", "/available_references")
    normalized: dict[str, frozenset[str]] = {}
    for field in fields:
        entries = value[field]
        if not isinstance(entries, (tuple, list, set, frozenset)):
            _fail("INVALID_TYPE", f"/available_references/{field}")
        if any(not isinstance(item, str) or not _IDENTIFIER.fullmatch(item)
               for item in entries):
            _fail("INVALID_VALUE", f"/available_references/{field}")
        normalized[field] = frozenset(entries)
    return ReferenceCatalogV1(**normalized)


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("INVALID_TYPE", path)
    return cast(dict[str, Any], value)


def _fields(value: dict[str, Any], allowed: frozenset[str], path: str) -> None:
    for key in value:
        if key not in allowed:
            _fail("SECRET_PLAINTEXT" if _SENSITIVE_KEY.search(key) else "FORBIDDEN_FIELD", path)


def _required(value: dict[str, Any], key: str) -> Any:
    if key not in value:
        _fail("REQUIRED_FIELD", f"/{key}")
    return value[key]


def _string(value: Any, path: str, *, identifier: bool = False) -> str:
    if not isinstance(value, str):
        _fail("INVALID_TYPE", path)
    if not value or len(value) > 128 or (identifier and not _IDENTIFIER.fullmatch(value)):
        _fail("INVALID_VALUE", path)
    return value


def _version(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail("INVALID_TYPE", path)
    if value < 1 or value > 2_147_483_647:
        _fail("INVALID_VALUE", path)
    return value


def _identity(value: dict[str, Any]) -> tuple[str, int, str, str]:
    if _required(value, "schema_version") != 1 or type(value["schema_version"]) is not int:
        _fail("INVALID_VALUE", "/schema_version")
    name = _string(_required(value, "name"), "/name", identifier=True)
    version = _version(_required(value, "version"), "/version")
    strategy_id = _string(_required(value, "strategy_id"), "/strategy_id", identifier=True)
    strategy_version = _string(_required(value, "strategy_version"), "/strategy_version")
    if not _SEMVER.fullmatch(strategy_version):
        _fail("INVALID_VALUE", "/strategy_version")
    return name, version, strategy_id, strategy_version


def _names(value: Any, path: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        _fail("INVALID_TYPE", path)
    names = tuple(_string(item, f"{path}/{index}", identifier=True)
                  for index, item in enumerate(value))
    if len(names) != len(set(names)):
        _fail("INVALID_VALUE", path)
    return names


def _number(value: Any, path: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        _fail("INVALID_TYPE", path)
    failure: str | None = None
    try:
        result = _decimal(value)
    except (TypeError, ValueError) as exc:
        failure = ("PRECISION_EXCEEDED" if str(exc) == "PRECISION_EXCEEDED"
                   else "INVALID_VALUE")
    if failure is not None:
        _fail(failure, path)
    return result


def _kind_fields(
    rule: dict[str, Any], kind: str, path: str
) -> tuple[tuple[str, ...], str | None, tuple[str, ...]]:
    choices: tuple[str, ...] = ()
    provider: str | None = None
    hosts: tuple[str, ...] = ()
    if kind == "enum":
        raw_choices = rule.get("choices")
        if (not isinstance(raw_choices, list) or not raw_choices
                or any(not isinstance(item, str) or not item or len(item) > 128
                       for item in raw_choices)):
            _fail("INVALID_VALUE", path)
        choices = tuple(raw_choices)
        if len(choices) != len(set(choices)):
            _fail("INVALID_VALUE", path)
    elif kind == "symbol":
        raw_provider = rule.get("provider")
        if (not isinstance(raw_provider, str) or not 3 <= len(raw_provider) <= 60
                or not re.fullmatch(_PROVIDER, raw_provider, re.ASCII)):
            _fail("INVALID_VALUE", path)
        provider = raw_provider
    elif kind == "url":
        raw_hosts = rule.get("hosts")
        if (not isinstance(raw_hosts, list) or not raw_hosts
                or any(not isinstance(host, str) or len(host) > 253
                       or not _HOST.fullmatch(host) for host in raw_hosts)):
            _fail("INVALID_VALUE", path)
        hosts = tuple(raw_hosts)
        if len(hosts) != len(set(hosts)):
            _fail("INVALID_VALUE", path)
    expected = ({"choices"} if kind == "enum" else {"provider"} if kind == "symbol"
                else {"hosts"} if kind == "url" else set())
    if any(field in rule and field not in expected for field in ("choices", "provider", "hosts")):
        _fail("INVALID_VALUE", path)
    return choices, provider, hosts


def _rules(value: Any, path: str) -> tuple[ParameterRuleV1, ...]:
    schema = _object(value, path)
    rules: list[ParameterRuleV1] = []
    for name, raw in sorted(schema.items()):
        _string(name, path, identifier=True)
        rule = _object(raw, path)
        _fields(rule, _RULE_FIELDS, path)
        kind = rule.get("type")
        if kind not in ("string", "integer", "number", "boolean"):
            _fail("INVALID_VALUE", path)
        minimum = _number(rule["minimum"], path) if "minimum" in rule else None
        maximum = _number(rule["maximum"], path) if "maximum" in rule else None
        if kind in ("string", "boolean") and (minimum is not None or maximum is not None):
            _fail("INVALID_VALUE", path)
        if minimum is not None and maximum is not None and minimum > maximum:
            _fail("INVALID_VALUE", path)
        string_kind = rule.get("kind")
        if kind == "string":
            if string_kind not in _STRING_KINDS:
                _fail("PARAMETER_KIND_UNDECLARED", path)
            choices, provider, hosts = _kind_fields(rule, cast(str, string_kind), path)
        else:
            if any(field in rule for field in ("kind", "choices", "provider", "hosts")):
                _fail("INVALID_VALUE", path)
            choices, provider, hosts = (), None, ()
        if _SENSITIVE_KEY.search(name) and string_kind != "vault_ref":
            _fail("SECRET_PLAINTEXT", path)
        rules.append(ParameterRuleV1(
            name, cast(ParameterType, kind), minimum, maximum,
            cast(Any, string_kind) if kind == "string" else None,
            choices, provider, hosts,
        ))
    return tuple(rules)


def _vault_uri(uri: str, path: str, mode: ProfileMode | None) -> re.Match[str]:
    match = _VAULT_REF.fullmatch(uri)
    if match is None or not 3 <= len(match["provider"]) <= 60:
        _fail("INVALID_SECRET_REFERENCE", path)
    if match["scope"] != "leviathan-ai":
        _secret_mismatch("SECRET_SCOPE_MISMATCH", path)
    if match["environment"] not in ("development", "live"):
        _fail("INVALID_SECRET_REFERENCE", path)
    if mode is not None:
        expected = "live" if mode == "live" else "development"
        if match["environment"] != expected:
            _secret_mismatch("SECRET_ENVIRONMENT_MISMATCH", path)
    provider_prefix = match["provider"].upper().replace("-", "_") + "_"
    if not match["name"].startswith(provider_prefix):
        _fail("INVALID_SECRET_REFERENCE", path)
    return match


def _valid_endpoint_url(value: str, hosts: Collection[str] | None = None) -> bool:
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme == "https" and value.startswith("https://")
            and "?" not in value and "#" not in value
            and all(33 <= ord(char) <= 126 for char in value)
            and parsed.netloc == parsed.hostname
            and parsed.hostname is not None
            and (hosts is None or parsed.hostname in hosts)
            and not parsed.username and not parsed.password
            and _URL_PATH.fullmatch(parsed.path) is not None
        )
    except ValueError:
        return False


def _validate_string_kind(
    rule: ParameterRuleV1, value: str, path: str, mode: ProfileMode | None,
    endpoint_registry: EndpointRegistryV1 | None,
) -> None:
    kind = rule.kind
    if kind is None:
        _fail("PARAMETER_KIND_UNDECLARED", "/parameter_schema" if mode else "/schema")
    if "://" in value and (
        (kind != "vault_ref" and value.startswith("vault://"))
        or (kind != "url" and value.startswith("https://"))
        or not value.startswith(("vault://", "https://"))
    ):
        _fail("INVALID_VALUE", path)
    if kind == "enum":
        valid = value in rule.choices
    elif kind == "identifier":
        valid = _IDENTIFIER_VALUE.fullmatch(value) is not None
    elif kind == "symbol":
        match = _SYMBOL_VALUE.fullmatch(value)
        valid = match is not None and match["provider"] == rule.provider
    elif kind == "decimal_text":
        precision_exceeded = False
        try:
            valid = _canonical_number(_decimal(Decimal(value))) == value
        except ValueError as exc:
            precision_exceeded = str(exc) == "PRECISION_EXCEEDED"
            valid = False
        except (InvalidOperation, TypeError):
            valid = False
        if precision_exceeded:
            _fail("PRECISION_EXCEEDED", path)
    elif kind == "duration":
        valid = _DURATION.fullmatch(value) is not None or (
            _INTEGER_NS.fullmatch(value) is not None
            and len(value) <= 19 and int(value) <= 10**18
        )
    elif kind == "url":
        valid = _valid_endpoint_url(value, rule.hosts)
        if valid:
            if endpoint_registry is None:
                _fail("REQUIRED_FIELD", "/endpoint_registry")
            if value not in endpoint_registry.entries.values():
                _fail("UNRESOLVED_REFERENCE", path)
    elif kind == "endpoint_id":
        valid = _IDENTIFIER.fullmatch(value) is not None
        if valid:
            if endpoint_registry is None:
                _fail("REQUIRED_FIELD", "/endpoint_registry")
            if value not in endpoint_registry.entries:
                _fail("UNRESOLVED_REFERENCE", path)
    elif kind == "vault_ref":
        _vault_uri(value, path, mode)
        return
    else:
        _fail("PARAMETER_KIND_UNDECLARED", "/parameter_schema" if mode else "/schema")
    if not valid:
        _fail("INVALID_VALUE", path)


def _values(
    value: Any, rules: tuple[ParameterRuleV1, ...], path: str,
    mode: ProfileMode | None = None, *, endpoint_registry: EndpointRegistryV1 | None = None,
    frozen: bool = False,
) -> tuple[
    tuple[str, ParameterValue], ...
]:
    values = _object(value, path)
    rule_by_name = {rule.name: rule for rule in rules}
    if any(_SENSITIVE_KEY.search(name)
           and (name not in rule_by_name or rule_by_name[name].kind != "vault_ref")
           for name in values):
        _fail("SECRET_PLAINTEXT", path)
    if set(values) != {rule.name for rule in rules}:
        _fail("INVALID_VALUE", path)
    output: list[tuple[str, ParameterValue]] = []
    for rule in rules:
        item = values[rule.name]
        if rule.type == "string":
            valid = isinstance(item, str) and len(item) <= 8192
        elif rule.type == "boolean":
            valid = isinstance(item, bool)
        elif rule.type == "integer":
            valid = type(item) is int or (
                frozen and isinstance(item, Decimal) and item == item.to_integral_value()
            )
        else:
            valid = type(item) in (int, Decimal)
        if not valid:
            _fail("INVALID_TYPE", path)
        if rule.type == "string":
            _validate_string_kind(rule, cast(str, item), path, mode, endpoint_registry)
        if isinstance(item, (int, Decimal)) and not isinstance(item, bool):
            numeric = _number(item, path)
            if ((rule.minimum is not None and numeric < rule.minimum)
                    or (rule.maximum is not None and numeric > rule.maximum)):
                _fail("INVALID_VALUE", path)
            if rule.type == "number":
                item = numeric
        output.append((rule.name, cast(ParameterValue, item)))
    return tuple(output)


def _secret_refs(value: Any, mode: ProfileMode, path: str) -> tuple[SecretReferenceV1, ...]:
    refs = _object(value, path)
    output: list[SecretReferenceV1] = []
    for alias, uri in sorted(refs.items()):
        _string(alias, path, identifier=True)
        if not isinstance(uri, str):
            _fail("INVALID_SECRET_REFERENCE", path)
        match = _vault_uri(uri, path, mode)
        output.append(SecretReferenceV1(
            alias, match["scope"], match["environment"], match["provider"], match["name"]
        ))
    return tuple(output)


def _parsed(document: str | bytes, format: Literal["json", "yaml"]) -> dict[str, Any]:
    parsed: Any = None
    failure_code: str | None = None
    try:
        parsed = parse_document(document, format=format)
    except ParseFailureError as exc:
        failure_code = exc.code
    document = b""
    if failure_code is not None:
        _fail(failure_code, "")
    result = _object(parsed, "")
    return result


def load_strategy_profile(
    document: str | bytes,
    *,
    format: Literal["json", "yaml"],
    available_references: ReferenceCatalogV1 | Mapping[str, Collection[str]] | None = None,
    endpoint_registry: EndpointRegistryV1 | None = None,
) -> StrategyProfileV1:
    """Validate one inert profile against a caller-supplied reference inventory."""
    if endpoint_registry is not None and not isinstance(endpoint_registry, EndpointRegistryV1):
        _fail("INVALID_TYPE", "/endpoint_registry")
    try:
        raw = _parsed(document, format)
    finally:
        document = b""
    _fields(raw, _PROFILE_FIELDS, "")
    name, version, strategy_id, strategy_version = _identity(raw)
    mode = raw.get("mode")
    if mode not in ("backtest", "paper", "live"):
        _fail("INVALID_VALUE", "/mode")
    environment = raw.get("environment")
    if environment not in ("test", "staging", "production"):
        _fail("INVALID_VALUE", "/environment")
    if mode == "live" and environment != "production":
        _fail("INVALID_VALUE", "/environment")
    connectors = _names(raw.get("connectors", []), "/connectors")
    data_feeds = _names(raw.get("data_feeds", []), "/data_feeds")
    risk_guard = _string(_required(raw, "risk_guard"), "/risk_guard", identifier=True)
    inventory = _reference_catalog(available_references)
    for field, references in (("connectors", connectors), ("data_feeds", data_feeds)):
        known = getattr(inventory, field)
        for index, reference in enumerate(references):
            if reference not in known:
                _fail("UNRESOLVED_REFERENCE", f"/{field}/{index}")
    if risk_guard not in inventory.risk_guards:
        _fail("UNRESOLVED_REFERENCE", "/risk_guard")
    rules = _rules(raw.get("parameter_schema", {}), "/parameter_schema")
    _scan_string_values(raw)
    parameters = _values(raw.get("parameters", {}), rules, "/parameters", cast(ProfileMode, mode),
                         endpoint_registry=endpoint_registry)
    secret_refs = _secret_refs(raw.get("secret_refs", {}), cast(ProfileMode, mode), "/secret_refs")
    published = raw.get("published", False)
    if not isinstance(published, bool):
        _fail("INVALID_TYPE", "/published")
    result = StrategyProfileV1(
        1, name, version, strategy_id, strategy_version, cast(ProfileMode, mode),
        cast(ProfileEnvironment, environment), connectors, data_feeds, risk_guard,
        {rule.name: rule for rule in rules}, dict(parameters),
        {ref.alias: ref.uri for ref in secret_refs}, published, endpoint_registry,
    )
    _ = result.content_hash
    return result


def load_parameter_set(
    document: str | bytes, *, format: Literal["json", "yaml"],
    endpoint_registry: EndpointRegistryV1 | None = None,
) -> ParameterSetV1:
    """Validate scalar typed parameters as an immutable versioned value."""
    if endpoint_registry is not None and not isinstance(endpoint_registry, EndpointRegistryV1):
        _fail("INVALID_TYPE", "/endpoint_registry")
    try:
        raw = _parsed(document, format)
    finally:
        document = b""
    _fields(raw, _PARAMETER_SET_FIELDS, "")
    name, version, strategy_id, strategy_version = _identity(raw)
    rules = _rules(_required(raw, "schema"), "/schema")
    _scan_string_values(raw)
    values = _values(_required(raw, "values"), rules, "/values",
                     endpoint_registry=endpoint_registry)
    locked = raw.get("locked", False)
    if not isinstance(locked, bool):
        _fail("INVALID_TYPE", "/locked")
    result = ParameterSetV1(
        1, name, version, strategy_id, strategy_version, {rule.name: rule for rule in rules},
        dict(values), locked, endpoint_registry,
    )
    _ = result.content_hash
    return result


def enforce_immutable_version(
    previous: StrategyProfileV1 | ParameterSetV1,
    candidate: StrategyProfileV1 | ParameterSetV1,
) -> None:
    """Reject rewriting a version. A new version remains a separate value object."""
    if type(previous) is not type(candidate):
        _fail("INVALID_TYPE", "")
    if previous.strategy_id != candidate.strategy_id or previous.name != candidate.name:
        _fail("INVALID_VALUE", "")
    try:
        previous_hash = previous.content_hash
        candidate_hash = candidate.content_hash
    except (TypeError, ValueError, AttributeError, OverflowError):
        _fail("IMMUTABLE_VERSION_CONFLICT", "/version")
    if candidate.version < previous.version or (
        candidate.version == previous.version and candidate_hash != previous_hash
    ):
        _fail("IMMUTABLE_VERSION_CONFLICT", "/version")
