from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from leviathan_vault import InMemoryVault, VaultError, XyraVault
from leviathan_vault.client import store_reference
from leviathan_vault.import_keys import ParsedCredential, _broker_write

NAME = "DATABENTO_API_KEY"
SCOPE = "leviathan-ai"
ENVIRONMENT = "development"
VALUE = "synthetic-dpapi-雪-913804"


def _factory(root: Path) -> Path:
    (root / "registries").mkdir(parents=True)
    (root / "tools" / "secrets").mkdir(parents=True)
    document = {"schema_version": "1.0.0", "entries": [{
        "name": NAME, "scope": SCOPE, "environment": ENVIRONMENT,
        "inherit_to_projects": False,
        "store_reference": store_reference(NAME, SCOPE, ENVIRONMENT),
    }]}
    (root / "registries" / "SECRET_REGISTRY.yaml").write_text(
        json.dumps(document), encoding="utf-8"
    )
    return root


def _registry(root: Path) -> tuple[Path, dict[str, object]]:
    path = root / "registries" / "SECRET_REGISTRY.yaml"
    return path, json.loads(path.read_text(encoding="utf-8"))


def test_in_memory_vault_scope_and_masking() -> None:
    vault = InMemoryVault()
    vault.put(NAME, SCOPE, ENVIRONMENT, VALUE)
    assert vault.get(NAME, SCOPE, ENVIRONMENT).get_secret_value() == VALUE
    assert VALUE not in repr(vault.get(NAME, SCOPE, ENVIRONMENT))
    assert vault.status(NAME, SCOPE, ENVIRONMENT).provider_authentication == "NOT_TESTED"
    with pytest.raises(VaultError, match=r"^SECRET_SCOPE_DENIED$"):
        vault.get(NAME, SCOPE, "live")
    with pytest.raises(VaultError, match=r"^SECRET_SCOPE_DENIED$"):
        vault.get("bad-name", SCOPE, ENVIRONMENT)
    with pytest.raises(VaultError, match=r"^SECRET_SCOPE_DENIED$"):
        vault.get(NAME, "factory-admin", "administration")
    with pytest.raises(VaultError, match=r"^SECRET_SCOPE_DENIED$"):
        vault.get(NAME, SCOPE, "staging")
    with pytest.raises(VaultError, match=r"^SECRET_SCOPE_DENIED$"):
        vault.put(NAME, SCOPE, "staging", VALUE)


def test_broker_written_dpapi_roundtrip_and_policy(tmp_path: Path) -> None:
    broker_source = os.environ.get("XYRA_BROKER_MODULE")
    if os.name != "nt" or not broker_source or not Path(broker_source).is_file():
        pytest.skip("real XYRA broker path required for Windows DPAPI compatibility")
    factory = _factory(tmp_path / "factory")
    (factory / "tools" / "secrets" / "Xyra.Secrets.psm1").write_bytes(
        Path(broker_source).read_bytes()
    )
    _broker_write(factory, ParsedCredential("DATABENTO", NAME, ENVIRONMENT, VALUE), SCOPE, False)
    vault = XyraVault(factory)
    assert vault.get(NAME, SCOPE, ENVIRONMENT).get_secret_value() == VALUE
    assert vault.status(NAME, SCOPE, ENVIRONMENT).status == "ENCRYPTED_ROUNDTRIP_VERIFIED"
    registry_path, original = _registry(factory)
    entry = original["entries"][0]
    assert isinstance(entry, dict)

    for changed, code in [
        ({"inherit_to_projects": True}, "SECRET_SCOPE_DENIED"),
        ({"store_reference": "dpapi-current-user://wrong.dpapi"}, "SECRET_REFERENCE_DENIED"),
    ]:
        modified = json.loads(json.dumps(original))
        modified["entries"][0].update(changed)
        registry_path.write_text(json.dumps(modified), encoding="utf-8")
        with pytest.raises(VaultError, match=f"^{code}$"):
            vault.get(NAME, SCOPE, ENVIRONMENT)
    registry_path.write_text(json.dumps(original), encoding="utf-8")
    for scope, env in [("other-scope", ENVIRONMENT), (SCOPE, "live"),
                       (SCOPE, "staging")]:
        with pytest.raises(VaultError, match=r"^SECRET_SCOPE_DENIED$"):
            vault.get(NAME, scope, env)
    with pytest.raises(VaultError, match=r"^SECRET_SCOPE_DENIED$"):
        vault.get("bad-name", SCOPE, ENVIRONMENT)
    store = factory / ".local" / "secrets" / f"{SCOPE}--{ENVIRONMENT}--{NAME}.dpapi"
    store.write_bytes(b"tampered synthetic ciphertext")
    with pytest.raises(VaultError, match=r"^SECRET_READ_FAILED$"):
        vault.get(NAME, SCOPE, ENVIRONMENT)


def test_missing_file_is_not_configured(tmp_path: Path) -> None:
    vault = XyraVault(_factory(tmp_path / "factory"))
    with pytest.raises(VaultError, match=r"^SECRET_NOT_CONFIGURED$"):
        vault.get(NAME, SCOPE, ENVIRONMENT)


@pytest.mark.parametrize("component", [".local", "secrets"])
def test_windows_junction_is_denied(tmp_path: Path, component: str) -> None:
    if os.name != "nt":
        pytest.skip("Windows reparse-point policy")
    factory = _factory(tmp_path / "factory")
    outside = tmp_path / "outside-store"
    outside.mkdir()
    local = factory / ".local"
    if component == "secrets":
        local.mkdir()
    junction = local if component == ".local" else local / "secrets"
    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
                            capture_output=True, text=True, check=False)
    if result.returncode:
        pytest.skip("Windows host cannot create disposable junction")
    with pytest.raises(VaultError, match=r"^SECRET_READ_FAILED$"):
        XyraVault(factory).get(NAME, SCOPE, ENVIRONMENT)
