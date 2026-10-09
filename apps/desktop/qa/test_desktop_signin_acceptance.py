from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

DESKTOP = Path(__file__).resolve().parents[1]
REPO = DESKTOP.parents[1]
FIXTURES = DESKTOP / "qa" / "fixtures" / "license"
SIGNIN_JS = DESKTOP / "shell" / "signin.js"
SIGNIN_HTML = DESKTOP / "shell" / "signin.html"
LICENSE_RS = DESKTOP / "src-tauri" / "src" / "license.rs"
BRIDGE_JS = DESKTOP / "src" / "bridge_license.js"
MAIN_RS = DESKTOP / "src-tauri" / "src" / "main.rs"

OPENING_MAIN_BASELINE_SHA256 = "33c1a56b247fdc5936520d8878bd38046daa370349c88fe27e2394cdfbf35620"
FIXTURE_NAMES = {
    "active.json",
    "inactive.json",
    "device-mismatch.json",
    "malformed.json",
    "expired.json",
    "offline-cached.json",
}
REQUIRED_SNAPSHOT_FIELDS = {
    "schemaVersion",
    "orgId",
    "licenseId",
    "subscriptionRevision",
    "status",
    "termStartUtcNs",
    "termEndUtcNs",
    "issuedAtUtcNs",
    "lastOnlineVerifiedUtcNs",
    "features",
    "limits",
    "audience",
    "deviceId",
    "signingKeyId",
    "signature",
}


def _read(path: Path) -> str:
    assert path.is_file(), f"required source is missing: {path.relative_to(REPO)}"
    return path.read_text(encoding="utf-8")


def _node_assertions(
    script: str,
    source: Path = SIGNIN_JS,
    extra_env: dict[str, str] | None = None,
) -> None:
    node = shutil.which("node")
    assert node is not None, "Node.js is required for the pure signin.js acceptance checks"
    env = os.environ.copy()
    env["SIGNIN_JS_PATH"] = str(source)
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(
        [node, "-e", script],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=20,
    )
    assert result.returncode == 0, f"Node acceptance failed:\n{result.stderr}\n{result.stdout}"


def test_license_fixtures_are_synthetic_worker_envelopes() -> None:
    files = {path.name for path in FIXTURES.glob("*.json")}
    assert files == FIXTURE_NAMES
    for path in sorted(FIXTURES.glob("*.json")):
        envelope: Any = json.loads(path.read_text(encoding="utf-8"))
        assert set(envelope) == {
            "schema_version",
            "license",
            "observed_at_ns",
            "request_id",
            "entitlement_state",
        }
        assert envelope["schema_version"] == 1
        assert isinstance(envelope["observed_at_ns"], str)
        assert envelope["request_id"].startswith("acceptance-fixture-")
        assert envelope["entitlement_state"] in {
            "VERIFIED_ONLINE",
            "GRACE_OFFLINE",
            "DENIED",
            "UNKNOWN",
        }
        serialized = json.dumps(envelope, sort_keys=True)
        assert not re.search(r"(?:sk-[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{30,})", serialized)
        assert "PRIVATE KEY" not in serialized
        if path.name != "malformed.json":
            snapshot = envelope["license"]
            assert set(snapshot) == REQUIRED_SNAPSHOT_FIELDS
            assert snapshot["schemaVersion"] == 1
            assert set(snapshot["signature"]) == {"algorithm", "value"}
            assert snapshot["signature"]["algorithm"] == "ECDSA_P256_SHA256"


def test_signin_html_loads_signin_code_without_embedding_terminal_page() -> None:
    html = _read(SIGNIN_HTML).lower()
    signin = _read(SIGNIN_JS)
    assert "signin.js" in html
    assert "index.html" not in html
    assert "<iframe" not in html
    assert "terminal_url" not in html and "terminalurl" not in html
    assert re.search(r"deriveUnlockView\(view\.state", signin)
    assert "if (!unlock.unlocked)" in signin
    assert not re.search(
        r"(?:window\.)?location\.(?:href|assign|replace)|window\.open|loadURL\(", signin
    )


def test_signin_form_delegates_auth_to_native_commands_without_worker_http() -> None:
    signin = _read(SIGNIN_JS)
    bridge = _read(BRIDGE_JS)
    assert 'signIn: "license_sign_in"' in signin
    assert 'enrollTotp: "license_enroll_totp"' in signin
    assert 'status: "license_status"' in signin
    assert 'signOut: "license_sign_out"' in signin
    assert 'form.addEventListener("submit"' in signin
    assert "bridge.invoke(COMMANDS.signIn" in signin
    assert "bridge.invoke(COMMANDS.status)" in signin
    assert 'getElementById("signin-form")' in signin
    assert "native.invoke(name, args)" in bridge
    assert not re.search(r"\bfetch\s*\(|XMLHttpRequest|WebSocket", signin)
    assert not re.search(r"Authorization|session_token|worker_response_json|snapshot", signin)


def test_totp_enrollment_is_text_only_validated_one_time_material() -> None:
    html = _read(SIGNIN_HTML)
    signin = _read(SIGNIN_JS)
    assert '<section id="totp-enrollment" hidden>' in html
    assert '<p id="totp-uri"></p>' in html
    assert re.search(r'<input id="totp-secret" type="text" readonly[^>]*>', html)
    assert 'id="totp-secret" type="text" disabled' not in html
    assert '<form id="totp-confirm-form"' in html
    assert 'name="enrollment_code"' in html
    assert "enter the key below manually" in html.lower()
    assert not re.search(r"qr.?code|<canvas", html + signin, re.IGNORECASE)

    assert 'view.state === "TOTP_ENROLLMENT_REQUIRED"' in signin
    assert "displayEnrollment(view.otpauthUri)" in signin
    assert "api.extractTotpSecret(uri)" in signin
    assert "enrollmentUri.textContent = uri" in signin
    assert "enrollmentSecret.value = secret" in signin
    assert "enrollment.hidden = false" in signin
    assert signin.count("enrollmentUri.textContent = uri") == 1
    assert signin.count("view.otpauthUri") == 1

    assert 'confirmForm.addEventListener("submit"' in signin
    assert 'const code = confirmForm.elements.namedItem("enrollment_code").value' in signin
    assert "bridge.invoke(COMMANDS.enrollTotp, { code })" in signin
    assert 'showMessage("Authenticator confirmed. Sign in again' in signin
    confirmation_call = "await bridge.invoke(COMMANDS.enrollTotp, { code })"
    assert signin.index(confirmation_call) < signin.index(
        "clearEnrollmentMaterial();", signin.index(confirmation_call)
    )
    assert 'enrollmentUri.textContent = ""' in signin
    assert 'enrollmentSecret.value = ""' in signin
    assert 'confirmForm.elements.namedItem("enrollment_code").value = ""' in signin


def test_totp_secret_helper_only_extracts_valid_totp_base32() -> None:
    _node_assertions(
        r"""
        const assert = require('node:assert/strict');
        const api = require(process.env.SIGNIN_JS_PATH);
        assert.equal(typeof api.extractTotpSecret, 'function');
        assert.equal(
          api.extractTotpSecret('otpauth://totp/Leviathan:user?secret=abcd2345&issuer=Leviathan'),
          'ABCD2345',
        );
        for (const uri of [
          null,
          'not a URI',
          'https://totp.example.test/Leviathan?secret=ABCD2345',
          'otpauth://hotp/Leviathan?secret=ABCD2345',
          'otpauth://totp/Leviathan',
          'otpauth://totp/Leviathan?secret=ABCD2345&secret=EFGH2345',
          'otpauth://totp/Leviathan?secret=ABC01234',
          'otpauth://user@totp/Leviathan?secret=ABCD2345',
          'otpauth://totp:1234/Leviathan?secret=ABCD2345',
          'otpauth://totp/Leviathan?secret=ABCD2345#fragment',
          `otpauth://totp/Leviathan?secret=${'A'.repeat(4097)}`,
        ]) {
          assert.equal(api.extractTotpSecret(uri), null, String(uri));
        }
        """,
    )


def test_native_totp_result_is_bounded_and_confirmation_clears_pending_token() -> None:
    rust = _read(LICENSE_RS)
    sign_in_start = rust.index("pub async fn license_sign_in(")
    enroll_start = rust.index("pub async fn license_enroll_totp(")
    sign_in = rust[sign_in_start:enroll_start]
    enroll_end = rust.find("#[tauri::command]", enroll_start)
    enroll = rust[enroll_start : enroll_end if enroll_end >= 0 else len(rust)]

    assert '"state": "TOTP_ENROLLMENT_REQUIRED"' in sign_in
    assert '"otpauthUri": otpauth_uri' in sign_in
    assert '"features": {}' in sign_in
    assert '"unlocked": false' in sign_in
    assert '"readOnly": true' in sign_in
    assert '"session_token": session_token' not in sign_in

    assert '"state": "TOTP_ENROLLED"' in enroll
    assert '"requiresSignIn": true' in enroll
    assert "*token = None;" in enroll
    assert '"otpauthUri"' not in enroll
    assert '"secret"' not in enroll


def test_main_rust_integration_uses_the_opening_signin_gate() -> None:
    main = _read(MAIN_RS)
    assert 'WebviewUrl::App("signin.html"' in main
    assert "consume_verified_online_unlock" in main
    assert OPENING_MAIN_BASELINE_SHA256 == (
        "33c1a56b247fdc5936520d8878bd38046daa370349c88fe27e2394cdfbf35620"
    )
    _read(LICENSE_RS)
    _read(BRIDGE_JS)


def test_signin_origin_allowlist_is_exact_https_origin_only() -> None:
    _node_assertions(
        r"""
        const assert = require('node:assert/strict');
        const api = require(process.env.SIGNIN_JS_PATH);
        assert.equal(typeof api.isAllowedWorkerOrigin, 'function');
        const allowed = ['https://license.example.test'];
        assert.equal(api.isAllowedWorkerOrigin('https://license.example.test', allowed), true);
        for (const candidate of [
          'http://license.example.test',
          'https://license.example.test.attacker.invalid',
          'https://attacker-license.example.test',
          'https://license.example.test/path',
          'https://license.example.test?debug=true',
          'https://license.example.test#fragment',
          'https://user@license.example.test',
          'javascript:alert(1)',
          'not a URL',
          null,
        ]) {
          assert.equal(api.isAllowedWorkerOrigin(candidate, allowed), false, String(candidate));
        }
        """,
    )


def test_signin_entitlement_projection_fails_closed_and_grace_is_read_only() -> None:
    _node_assertions(
        r"""
        const assert = require('node:assert/strict');
        const api = require(process.env.SIGNIN_JS_PATH);
        assert.equal(typeof api.deriveUnlockView, 'function');
        const granted = { 'paper.read': true, 'paper.submit': false,
          'LIVE.orders': true, 'liveOrders': true };
        const online = api.deriveUnlockView('VERIFIED_ONLINE', granted);
        assert.equal(online.state, 'VERIFIED_ONLINE');
        assert.equal(online.unlocked, true);
        assert.equal(online.readOnly, false);
        assert.deepEqual(online.features, { 'paper.read': true,
          'LIVE.orders': true, 'liveOrders': true });

        const grace = api.deriveUnlockView('GRACE', granted);
        assert.equal(grace.state, 'GRACE');
        assert.equal(grace.unlocked, true);
        assert.equal(grace.readOnly, true);
        assert.deepEqual(grace.features, { 'paper.read': true });

        for (const outcome of ['UNKNOWN', 'DENIED', 'TRIAL', null, {}, 'verified_online']) {
          const locked = api.deriveUnlockView(outcome, granted);
          assert.equal(locked.state, 'LOCKED', String(outcome));
          assert.equal(locked.unlocked, false, String(outcome));
          assert.deepEqual(locked.features, {}, String(outcome));
        }
        for (const malformedFeatures of [null, [], 'LIVE']) {
          const locked = api.deriveUnlockView('VERIFIED_ONLINE', malformedFeatures);
          assert.equal(locked.state, 'LOCKED');
          assert.equal(locked.unlocked, false);
          assert.deepEqual(locked.features, {});
        }
        """,
    )


def test_security_sensitive_values_are_not_passed_to_log_calls() -> None:
    sources = [_read(LICENSE_RS), _read(BRIDGE_JS), _read(SIGNIN_JS)]
    log_start = re.compile(
        r"(?:console\.(?:log|info|warn|error)|(?:log|tracing)::(?:debug|info|warn|error)!|"
        r"(?:e?println)!)\s*\("
    )
    sensitive_value = re.compile(
        r"\b(?:token|access_token|refresh_token|credential|password|snapshot|authorization|"
        r"secret|otpauth_uri|otpauthuri|enrollmentsecret|totp_code|enrollment_code)\b"
        r"\s*(?:\.|,|\)|\}|\])"
        r"|\b(?:token|access_token|refresh_token|credential|password|snapshot|authorization)\s*="
    )
    for source in sources:
        for match in log_start.finditer(source):
            call = source[match.start() : min(len(source), match.start() + 500)]
            assert not sensitive_value.search(call), "a log call appears to include sensitive data"


def test_approved_grace_duration_is_explicit_and_unlock_is_disabled() -> None:
    license_source = _read(LICENSE_RS)
    main_source = _read(MAIN_RS)
    combined = license_source + "\n" + main_source
    assert re.search(r"GRACE_SECONDS\s*:\s*u64\s*=\s*72\s*\*\s*3600", combined)
    assert re.search(r"GRACE_UNLOCK_ENABLED\s*:\s*bool\s*=\s*false", combined)
    assert re.search(r"GRACE_UNLOCK_ENABLED\s*&&", combined), (
        "the false grace flag must guard the grace startup path"
    )
