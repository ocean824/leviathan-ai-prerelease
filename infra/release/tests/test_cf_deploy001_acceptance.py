from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
LIVE_HOSTS = {
    "licensing": "leviathan-licensing-worker.ocean824.workers.dev",
    "release-feed": "leviathan-release-feed.ocean824.workers.dev",
    "data-gateway": "leviathan-data-gateway.ocean824.workers.dev",
}


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8-sig")


def test_wrangler_configs_bind_real_workers_dev_resources() -> None:
    licensing = tomllib.loads(_text("workers/licensing/wrangler.toml"))
    release = tomllib.loads(_text("workers/release-feed/wrangler.toml"))
    gateway = tomllib.loads(_text("workers/data-gateway/wrangler.toml"))
    assert licensing["workers_dev"] is True
    assert (
        licensing["vars"]["SIGNUP_SUCCESS_URL"]
        == f"https://{LIVE_HOSTS['licensing']}/v1/signup/success"
    )
    assert (
        licensing["vars"]["SIGNUP_CANCEL_URL"]
        == f"https://{LIVE_HOSTS['licensing']}/v1/signup/cancel"
    )
    assert release["workers_dev"] is True
    assert release["r2_buckets"] == [
        {"binding": "RELEASES", "bucket_name": "leviathan-release-feed"}
    ]
    assert release["vars"]["ALLOWED_ARTIFACT_HOSTS"] == LIVE_HOSTS["release-feed"]
    assert gateway["workers_dev"] is True
    assert gateway["services"] == [
        {"binding": "LICENSE_WORKER", "service": "leviathan-licensing-worker"}
    ]
    assert gateway["kv_namespaces"] == [{"binding": "RATE_LIMIT"}]


def test_every_client_default_points_to_workers_dev_and_keeps_local_overrides() -> None:
    feed = json.loads(_text("infra/release/feed.json"))
    license_config = json.loads(_text("infra/release/license_worker.json"))
    desktop = json.loads(_text("apps/desktop/src-tauri/tauri.conf.json"))
    admin = json.loads(_text("apps/admin/src-tauri/tauri.conf.json"))
    vite = _text("apps/admin/ui/vite.config.ts")
    admin_build = _text("apps/admin/scripts/build.ps1")
    gateway_client = _text(
        "packages/leviathan-market-data/src/leviathan_market_data/providers/gateway_client.py"
    )

    assert feed["base"] == f"https://{LIVE_HOSTS['release-feed']}"
    assert license_config == {"origin": f"https://{LIVE_HOSTS['licensing']}"}
    assert desktop["plugins"]["updater"]["endpoints"][0].startswith(
        f"https://{LIVE_HOSTS['release-feed']}/"
    )
    assert LIVE_HOSTS["licensing"] in admin["app"]["security"]["csp"]
    assert admin["plugins"]["updater"]["endpoints"][0].startswith(
        f"https://{LIVE_HOSTS['release-feed']}/"
    )
    assert LIVE_HOSTS["licensing"] in vite
    assert "VITE_ADMIN_WORKER_ORIGIN" in vite and "localhost" in vite
    assert (
        "loopback HTTP" in admin_build
        and "WorkerOrigin" in admin_build
        and "FeedOrigin" in admin_build
    )
    assert LIVE_HOSTS["data-gateway"] in gateway_client
    assert "LEVIATHAN_DATA_GATEWAY_URL" in gateway_client
    assert '"127.0.0.1"' in gateway_client and '"localhost"' in gateway_client


def test_signup_return_and_health_routes_exist_for_smoke_checks() -> None:
    signup = _text("workers/licensing/src/signup/routes.ts")
    licensing = _text("workers/licensing/src/worker/compose.ts")
    feed = _text("workers/release-feed/src/handler.ts")
    gateway = _text("workers/data-gateway/src/handler.ts")
    assert "/v1/signup/success" in signup and "/v1/signup/cancel" in signup
    assert 'url.pathname === "/health"' in licensing
    assert 'url.pathname === "/health"' in feed
    assert 'requestUrl.pathname === "/health"' in gateway
    assert "sk_test_" in licensing and "STRIPE_SECRET_KEY" in licensing


def test_runbook_uses_secure_store_stdin_and_child_token_env_only() -> None:
    script = _text("infra/release/cloudflare/Deploy-LeviathanWorkers.ps1")
    assert "Import-Module -Name $module" in script
    assert "Get-XyraSecret -Name" in script and "Set-XyraSecret -Name" in script
    assert "Start-Process" not in script
    assert "RedirectStandardInput" in script
    assert "StandardInput.Write($secretChars" in script
    assert "EnvironmentVariables['CLOUDFLARE_API_TOKEN']" in script
    assert "EnvironmentVariables.Remove('CLOUDFLARE_API_TOKEN')" in script
    assert (
        "--secrets-file" not in script and "Set-Content" not in script and "Out-File" not in script
    )
    assert (
        "SupportsShouldProcess" in script
        and "if ($WhatIfPreference) { Write-Plan; return }" in script
    )
    assert "wrangler login" not in script.casefold()
    assert "Invoke-WebRequest" in script
    assert 'Invoke-Smoke "$releaseOrigin/latest.json" @(200, 404) -AllowManifestBody' in script


def test_registry_fragment_has_full_entries_and_only_explicit_live_isolation() -> None:
    registry = json.loads(_text("infra/release/cloudflare/SECRET_REGISTRY.entries.json"))
    required = {
        "store_reference",
        "scope",
        "environment",
        "purpose",
        "owner",
        "name",
        "classification",
        "inherit_to_projects",
        "provider",
        "rotation",
        "validation",
    }
    entries = registry["entries"]
    names = {entry["name"] for entry in entries}
    assert len(names) == len(entries)
    assert all(required <= entry.keys() for entry in entries)
    assert all(
        entry["scope"] == "leviathan-ai" and entry["environment"] == "live" for entry in entries
    )
    assert {
        "LEVIATHAN_LICENSING_SIGNING_PRIVATE_KEY_PKCS8",
        "LEVIATHAN_LICENSING_SIGNING_PUBLIC_KEY_JWK",
        "LEVIATHAN_LICENSING_ADMIN_TOTP_ENCRYPTION_KEY",
        "LEVIATHAN_LICENSING_INTERNAL_SERVICE_TOKEN",
        "LEVIATHAN_LICENSING_LIVE_KEYSET_COMMIT",
    } <= names
    assert "LEVIATHAN_LICENSING_STRIPE_TEST_SECRET_KEY" in names
    assert "LEVIATHAN_LICENSING_STRIPE_TEST_WEBHOOK_SECRET" in names
    assert "LEVIATHAN_LICENSING_STRIPE_LIVE_WEBHOOK_SECRET" in names
    runbook = _text("infra/release/cloudflare/README.md")
    assert "https://leviathan-licensing-worker.ocean824.workers.dev/v1/signup/webhook" in runbook
    assert "STRIPE_WEBHOOK_SECRET" in runbook and "Test mode" in runbook
    assert "-StripeMode Live" in runbook
    script = _text("infra/release/cloudflare/Deploy-LeviathanWorkers.ps1")
    assert (
        "Invoke-StripeWebhookEnsure" in script and "api.stripe.com/v1/webhook_endpoints" in script
    )
    assert "enabled_events[]" in script and "Set-XyraSecret -Name $SecretRegistryName" in script


def test_stripe_webhook_enforces_livemode_before_any_ledger_mutation() -> None:
    webhook = _text("workers/licensing/src/signup/webhook.ts")
    models = _text("workers/licensing/src/signup/models.ts")
    compose = _text("workers/licensing/src/worker/compose.ts")
    unit = _text("workers/licensing/tests/signup.test.ts")
    assert 'parsed.livemode !== (deps.config.stripe_mode === "live")' in webhook
    assert 'console.warn("STRIPE_MODE_MISMATCH")' in webhook
    assert "STRIPE_MODE_MISMATCH" in models and "STRIPE_MODE_MISMATCH" in unit
    assert 'const mode = env.STRIPE_MODE ?? "test"' in compose
    assert "sk_test_" in compose and "sk_live_" in compose
    assert "livemode: true" in unit and "calls.events).toHaveLength(0)" in unit


def test_live_runtime_keyset_is_marker_committed_and_fail_closed() -> None:
    script = _text("infra/release/cloudflare/Deploy-LeviathanWorkers.ps1")
    helper = _text("infra/release/cloudflare/SigningKeyPair.psm1")
    pester = _text("infra/release/tests/SigningKeyPair.Tests.ps1")
    registry = json.loads(_text("infra/release/cloudflare/SECRET_REGISTRY.entries.json"))
    names = {entry["name"] for entry in registry["entries"]}
    required = {
        "LEVIATHAN_LICENSING_SIGNING_PRIVATE_KEY_PKCS8",
        "LEVIATHAN_LICENSING_SIGNING_PUBLIC_KEY_JWK",
        "LEVIATHAN_LICENSING_ADMIN_TOTP_ENCRYPTION_KEY",
        "LEVIATHAN_LICENSING_INTERNAL_SERVICE_TOKEN",
        "LEVIATHAN_LICENSING_LIVE_KEYSET_COMMIT",
    }
    assert required <= names
    marker = next(
        entry
        for entry in registry["entries"]
        if entry["name"] == "LEVIATHAN_LICENSING_LIVE_KEYSET_COMMIT"
    )
    assert marker["classification"] == "secret"
    assert "Invoke-AtomicLiveRuntimeKeyRegistration" in script and "-RotateLiveKeys" in script
    assert "Test-LiveRuntimeKeysetCommit" in script and "LIVE_RUNTIME_KEYSET_UNCOMMITTED" in script
    assert script.index("Test-LiveRuntimeKeysetCommit -Values") < script.index(
        "Invoke-R2BucketEnsure $apiToken"
    )
    assert "Invoke-AtomicLiveRuntimeKeyRegistration" in helper and "digest" in helper
    assert "rejects uncommitted partial writes" in pester
    assert "four values before the marker" in pester
    assert "unless rotation is explicit" in pester
