from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

DESKTOP = Path(__file__).resolve().parents[1]
REPO = DESKTOP.parents[1]
MAIN_RS = DESKTOP / "src-tauri" / "src" / "main.rs"
LICENSE_RS = DESKTOP / "src-tauri" / "src" / "license.rs"
BUILD_PS1 = DESKTOP / "scripts" / "build.ps1"
SIGNIN_JS = DESKTOP / "shell" / "signin.js"
SIGNIN_HTML = DESKTOP / "shell" / "signin.html"
QR_JS = DESKTOP / "shell" / "qr.js"


def _read(path: Path) -> str:
    assert path.is_file(), f"required source is missing: {path.relative_to(REPO)}"
    return path.read_text(encoding="utf-8")


def test_terminal_and_supervisor_start_only_after_native_online_proof() -> None:
    main = _read(MAIN_RS)
    license = _read(LICENSE_RS)
    entry = main[main.index("fn main()") :]

    signin_window = entry.find('WebviewUrl::App("signin.html"')
    event_listener = entry.find('"license-unlocked"')
    consume_proof = entry.find("consume_verified_online_unlock")
    supervise_start = entry.find("supervise(")
    updater_start = entry.find("updater_worker(")
    assert min(signin_window, event_listener, consume_proof, supervise_start, updater_start) >= 0
    listener_start = entry.index('app.listen("license-unlocked"')
    listener_end = entry.index("\n            });", listener_start)
    bootstrap = entry[:listener_start]
    listener = entry[listener_start:listener_end]
    assert 'WebviewUrl::App("index.html"' not in bootstrap
    assert "supervise(" not in bootstrap and "updater_worker(" not in bootstrap
    assert listener_start < event_listener < consume_proof < supervise_start < listener_end
    assert supervise_start < updater_start < listener_end
    assert listener.index("consume_verified_online_unlock") < listener.index("supervise(")
    assert listener.index("consume_verified_online_unlock") < listener.index("updater_worker(")
    assert "|| !license::consume_verified_online_unlock(" in listener

    terminal_loads = [
        position
        for needle in ('WebviewUrl::App("index.html"', "navigate(url)")
        if (position := entry.find(needle)) >= 0
    ]
    assert terminal_loads, "the terminal needs a post-unlock load path"
    assert signin_window < min(terminal_loads)
    assert min(terminal_loads) > listener_start
    assert min(terminal_loads) < listener_end

    consume_start = license.index("pub fn consume_verified_online_unlock")
    consume_body = license[consume_start : license.index("\n}", consume_start) + 2]
    assert "consume_startup_proof" in consume_body
    assert "claimed_state" in consume_body and "claimed_read_only" in consume_body
    proof_start = license.index("fn consume_startup_proof")
    proof_end = license.index("\n}", proof_start) + 2
    proof_body = license[proof_start:proof_end]
    assert "issued.state == claimed_state" in proof_body
    assert "issued.read_only == claimed_read_only" in proof_body
    assert "proof.take()" in proof_body
    assert "fn forged_grace_event_cannot_consume_verified_online_proof" in license

    emit_start = license.index("fn emit_startup_unlock")
    emit_end = license.index("\n#[tauri::command]", emit_start)
    emit_body = license[emit_start:emit_end]
    assert "startup_unlock_allowed(view)" in emit_body
    assert "view.state" in emit_body and "view.read_only" in emit_body
    assert "VerifiedOnlineGate" in emit_body
    assert 'app.emit("license-unlocked"' in emit_body


def test_unlock_proof_is_bound_to_payload_and_forged_grace_cannot_race_online() -> None:
    main = _read(MAIN_RS)
    license = _read(LICENSE_RS)
    gate_start = license.index("pub fn consume_verified_online_unlock")
    gate_end = license.index("\n}", gate_start) + 2
    gate = license[gate_start:gate_end]
    assert "state" in gate and "read_only" in gate
    assert "consume_startup_proof" in gate
    proof_start = license.index("fn consume_startup_proof")
    proof_end = license.index("\n}", proof_start) + 2
    proof = license[proof_start:proof_end]
    assert "issued.state == claimed_state" in proof
    assert "issued.read_only == claimed_read_only" in proof
    assert "proof.take()" in proof

    regression_start = license.index("fn forged_grace_event_cannot_consume_verified_online_proof")
    regression_end = license.index("\n    }", regression_start) + 6
    regression = license[regression_start:regression_end]
    assert 'state: "VERIFIED_ONLINE"' in regression
    assert re.search(
        r'assert!\(!consume_startup_proof\(\s*&mut proof,\s*"GRACE",\s*true,\s*&valid_features',
        regression,
    )
    assert "proof,\n            Some(StartupUnlockProof {" in regression
    assert re.search(
        r'assert!\(consume_startup_proof\(\s*&mut proof,\s*"VERIFIED_ONLINE",'
        r"\s*false,\s*&valid_features",
        regression,
    )
    assert "proof.is_none()" in regression

    listener_start = main.index('app.listen("license-unlocked"')
    listener_end = main.index("\n            });", listener_start)
    listener = main[listener_start:listener_end]
    assert "consume_verified_online_unlock" in listener
    assert "state" in listener and "read_only" in listener
    assert "GRACE_UNLOCK_ENABLED" in listener
    assert '(state == "GRACE" && !license::GRACE_UNLOCK_ENABLED)' in listener
    assert listener.index("GRACE_UNLOCK_ENABLED") < listener.index("consume_verified_online_unlock")
    assert listener.index("consume_verified_online_unlock") < listener.index("GRACE_READ_ONLY")


def test_grace_is_display_only_while_unlock_flag_is_false() -> None:
    main = _read(MAIN_RS)
    license = _read(LICENSE_RS)
    combined = main + "\n" + license
    assert "GRACE_UNLOCK_ENABLED: bool = false" in combined
    assert re.search(r"GRACE_SECONDS:\s*u64\s*=\s*72\s*\*\s*(?:3600|60\s*\*\s*60)", combined)
    assert "GRACE_READ_ONLY" in combined
    policy_start = license.index("fn startup_unlock_allowed")
    policy_end = license.index("\nfn emit_startup_unlock", policy_start)
    policy = license[policy_start:policy_end]
    assert '"VERIFIED_ONLINE" => !view.read_only' in policy
    assert '"GRACE" => GRACE_UNLOCK_ENABLED && view.read_only' in policy

    regression = license.index("fn disabled_grace_gate_allows_only_verified_online_startup")
    regression_body = license[regression : license.index("\n    }", regression) + 6]
    assert "assert!(!GRACE_UNLOCK_ENABLED)" in regression_body
    assert "assert!(startup_unlock_allowed(&online))" in regression_body
    assert "assert!(!startup_unlock_allowed(&grace))" in regression_body


def test_window_close_and_app_exit_still_stop_the_sidecar() -> None:
    main = _read(MAIN_RS)
    assert ".on_window_event(" in main
    assert "tauri::WindowEvent::CloseRequested" in main
    assert "kill_sidecar(&window_runtime)" in main
    assert "tauri::RunEvent::Exit" in main
    assert "kill_sidecar(&exit_runtime)" in main


def test_build_rejects_public_http_worker_origin_before_building() -> None:
    powershell = shutil.which("pwsh") or shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("PowerShell is required to exercise build.ps1 input validation")

    with tempfile.TemporaryDirectory(prefix="signin-wire-build-") as temporary:
        sandbox = Path(temporary)
        script = sandbox / "apps" / "desktop" / "scripts" / "build.ps1"
        script.parent.mkdir(parents=True)
        shutil.copy2(BUILD_PS1, script)
        config = sandbox / "license-worker.json"
        config.write_text(
            json.dumps({"origin": "http://license.example.invalid:8080"}),
            encoding="utf-8",
        )

        result = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script),
                "-LicenseWorkerConfig",
                str(config),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        output = (result.stdout + "\n" + result.stderr).lower()
        assert result.returncode != 0
        assert "license worker origin is invalid" in output
        assert "cargo.exe is not installed" not in output
        assert not (sandbox / "apps" / "terminal" / "node_modules").exists()


def test_worker_origin_environment_is_scoped_to_tauri_build_and_restored() -> None:
    build = _read(BUILD_PS1)
    assert "LicenseWorkerConfig" in build
    assert "LEVIATHAN_LICENSE_WORKER_CONFIG" in build
    assert r"localhost|127\.0\.0\.1" in build
    assert r".Scheme -ceq 'https'" in build
    scoped_start = build.index("function Invoke-WithLicenseWorkerConfig")
    scoped_end = build.index("\nfunction Invoke-NativeLogged", scoped_start)
    scoped = build[scoped_start:scoped_end]
    assert "[Environment]::GetEnvironmentVariable($name, 'Process')" in scoped
    assert "[Environment]::SetEnvironmentVariable($name, $ConfigPath, 'Process')" in scoped
    assert "finally" in scoped
    assert "[Environment]::SetEnvironmentVariable($name, $previous, 'Process')" in scoped
    build_call = build[build.index("Invoke-WithLicenseWorkerConfig -ConfigPath") :]
    assert "npx --yes '@tauri-apps/cli@2.12.0' build" in build_call


def test_enrollment_qr_is_rendered_and_cleared_after_confirmation() -> None:
    html = _read(SIGNIN_HTML)
    signin = _read(SIGNIN_JS)
    qr = _read(QR_JS)

    assert 'id="totp-qr"' in html
    assert html.index('<script src="qr.js"></script>') < html.index(
        '<script src="signin.js"></script>'
    )
    assert "root.SigninQr = Object.freeze(api)" in qr
    assert "renderOtpauthQr" in qr and "clearOtpauthQr" in qr
    assert 'document.getElementById("totp-qr")' in signin

    display_start = signin.index("function displayEnrollment(")
    display_end = signin.index("\n  }", display_start) + 4
    display = signin[display_start:display_end]
    assert "window.SigninQr.renderOtpauthQr(enrollmentQr, uri)" in display
    assert "enrollmentUri.textContent = uri" in display

    clear_start = signin.index("function clearEnrollmentMaterial()")
    clear_end = signin.index("\n  }", clear_start) + 4
    clear = signin[clear_start:clear_end]
    assert "window.SigninQr.clearOtpauthQr(enrollmentQr)" in clear
    assert 'enrollmentUri.textContent = ""' in clear
    assert 'enrollmentSecret.value = ""' in clear

    confirm_start = signin.index('confirmForm.addEventListener("submit"')
    confirm_end = signin.index("\n  });", confirm_start) + 6
    confirm = signin[confirm_start:confirm_end]
    confirm_call = (
        "await bridge.invoke(googleEnrollmentPending ? COMMANDS.googleEnrollTotp "
        ": COMMANDS.enrollTotp, { code });"
    )
    assert confirm_call in confirm
    assert confirm.index(confirm_call) < confirm.index("clearEnrollmentMaterial()")


def test_enrollment_qr_dom_flow_renders_then_clears() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to exercise the sign-in DOM flow")

    script = r"""
const assert = require("node:assert/strict");
const submitHandlers = {};
const value = (initial = "") => ({ value: initial });
const named = (entries) => ({ namedItem: (name) => entries[name] });
const email = value("synthetic@example.test");
const password = value("synthetic-password");
const totpCode = value("");
const enrollmentCode = value("123456");
const googleButton = {
  disabled: false,
  addEventListener: (event, handler) => { submitHandlers.google = handler; },
};
const form = {
  hidden: false,
  querySelector: () => ({ disabled: false }),
  addEventListener: (event, handler) => { submitHandlers.signin = handler; },
  elements: named({ email, password, totp_code: totpCode }),
};
const confirmForm = {
  querySelector: () => ({ disabled: false }),
  addEventListener: (event, handler) => { submitHandlers.confirm = handler; },
  elements: named({ enrollment_code: enrollmentCode }),
};
const enrollment = { hidden: true };
const uriNode = { textContent: "" };
const secretNode = value("");
const status = { textContent: "" };
const qr = { children: [], replaceChildren(...children) { this.children = children; } };
const nodes = new Map([
  ["signin-form", form], ["totp-confirm-form", confirmForm],
  ["google-signin", googleButton],
  ["totp-enrollment", enrollment], ["totp-uri", uriNode],
  ["totp-secret", secretNode], ["totp-qr", qr], ["status", status],
]);
global.window = {
  __TAURI_INTERNALS__: {
    invoke: async (command) => command === "license_sign_in"
      ? {
          state: "TOTP_ENROLLMENT_REQUIRED",
          otpauthUri: "otpauth://totp/Leviathan:synthetic?"
            + "secret=JBSWY3DPEHPK3PXP&issuer=Leviathan",
        }
      : { state: "TOTP_ENROLLED", requiresSignIn: true },
  },
  addEventListener() {},
};
global.document = {
  getElementById: (id) => nodes.get(id),
  createElementNS: (_namespace, tagName) => ({
    tagName, attributes: {}, children: [],
    setAttribute(name, item) { this.attributes[name] = item; },
    appendChild(child) { this.children.push(child); },
  }),
};
require("./shell/qr.js");
require("./shell/signin.js");
(async () => {
  await submitHandlers.signin({ preventDefault() {} });
  assert.equal(enrollment.hidden, false);
  assert.equal(uriNode.textContent.startsWith("otpauth://totp/"), true);
  assert.equal(secretNode.value, "JBSWY3DPEHPK3PXP");
  assert.equal(qr.children.length, 1);
  assert.equal(qr.children[0].tagName, "svg");
  await submitHandlers.confirm({ preventDefault() {} });
  assert.equal(qr.children.length, 0);
  assert.equal(uriNode.textContent, "");
  assert.equal(secretNode.value, "");
  assert.equal(enrollmentCode.value, "");
  assert.equal(enrollment.hidden, true);
  assert.equal(form.hidden, false);
})().catch((error) => { console.error(error); process.exitCode = 1; });
"""
    result = subprocess.run(
        [node, "-e", script],
        cwd=DESKTOP,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_sidecar_feature_env_is_bound_to_the_verified_or_cached_snapshot() -> None:
    main = _read(MAIN_RS)
    license = _read(LICENSE_RS)

    proof_start = license.index("struct StartupUnlockProof")
    proof_end = license.index("\n}", proof_start) + 2
    proof = license[proof_start:proof_end]
    assert "features: BTreeMap<String, bool>" in proof

    consume_start = license.index("fn consume_startup_proof(")
    consume_end = license.index("\n}", consume_start) + 2
    consume = license[consume_start:consume_end]
    assert "claimed_features" in consume
    assert (
        "issued.features == *claimed_features" in consume
        or "&issued.features == claimed_features" in consume
    )
    assert "proof.take()" in consume

    emit_start = license.index("fn emit_startup_unlock(")
    emit_end = license.index("\n#[tauri::command]", emit_start)
    emit = license[emit_start:emit_end]
    assert "startup_unlock_allowed(view)" in emit
    assert "features: view.features.clone()" in emit
    assert re.search(r"let\s+mut\s+value\s*=\s*view\.json\(\)", emit)
    assert '"principalId".to_owned()' in emit
    assert '"entitlementDigest".to_owned()' in emit

    regression_start = license.index("fn forged_grace_event_cannot_consume_verified_online_proof")
    regression_end = license.index("\n    }", regression_start) + 6
    regression = license[regression_start:regression_end]
    assert "let forged_features" in regression
    assert re.search(
        r'assert!\(!consume_startup_proof\(\s*&mut proof,\s*"VERIFIED_ONLINE",'
        r"\s*false,\s*&forged_features",
        regression,
    )
    assert "features: valid_features.clone()" in regression

    online_start = license.index("fn verified_online_view(")
    online_end = license.index("\nfn worker_url(", online_start)
    assert "validate_snapshot(snapshot, device_id, now_ns)" in license[online_start:online_end]
    cached_start = license.index("fn offline_view_from_cache(")
    cached_end = license.index("\nfn startup_unlock_allowed(", cached_start)
    assert "validate_snapshot(snapshot, device_id, now_ns)" in license[cached_start:cached_end]

    listener_start = main.index('app.listen("license-unlocked"')
    listener_end = main.index("\n            });", listener_start)
    listener = main[listener_start:listener_end]
    assert re.search(r'payload\s*\.get\("features"\)', listener)
    assert "collect::<Option<BTreeMap<_, _>>>()" in listener
    assert "consume_verified_online_unlock" in listener
    assert listener.index("consume_verified_online_unlock") < listener.index("supervise(")
    assert re.search(r'payload\s*\.get\("features"\)', listener)
    assert "&features" in listener
    assert listener.index("consume_verified_online_unlock") < listener.index(
        "license::enabled_feature_csv(&features)"
    )
    assert "let sidecar_license_features = license::enabled_feature_csv(&features)" in listener
    assert "let supervise_features = sidecar_license_features" in listener
    supervise_call_start = listener.index("supervise(")
    supervise_call_end = listener.index("startup_receiver,", supervise_call_start)
    assert "supervise_features" in listener[supervise_call_start:supervise_call_end]

    supervise_start = main.index("fn supervise(")
    supervise_end = main.index("\nfn main()", supervise_start)
    supervise = main[supervise_start:supervise_end]
    assert re.search(
        r'\.env\(\s*"LEVIATHAN_LICENSE_FEATURES"\s*,\s*&license_features\s*\)',
        supervise,
    )
    assert "let mut command = Command::new(&executable);" in supervise
    assert 'std::env::set_var("LEVIATHAN_LICENSE_FEATURES"' not in main
    feature_csv_start = license.index("pub fn enabled_feature_csv(")
    feature_csv_end = license.index("\n}", feature_csv_start) + 2
    feature_csv = license[feature_csv_start:feature_csv_end]
    assert "enabled.then_some(name.as_str())" in feature_csv
    assert '.join(",")' in feature_csv


def test_sidecar_feature_value_is_never_written_to_logs() -> None:
    main = _read(MAIN_RS)
    license = _read(LICENSE_RS)
    source = main + "\n" + license
    logging_calls = re.findall(
        r"(?:append_log|println!|eprintln!|(?:log|tracing)::[A-Za-z_]+!)\s*\((.*?)\);",
        source,
        flags=re.DOTALL,
    )
    for call in logging_calls:
        assert not re.search(
            r"LEVIATHAN_LICENSE_FEATURES|feature",
            call,
            flags=re.IGNORECASE,
        )


def test_tauri_binary_compiles_with_locked_offline_dependencies() -> None:
    cargo = shutil.which("cargo")
    assert cargo is not None, "cargo is required for the frozen binary compile gate"
    env = os.environ.copy()
    env["CARGO_BUILD_JOBS"] = "1"
    env["TAURI_CONFIG"] = json.dumps({"bundle": {"resources": []}})
    result = subprocess.run(
        [cargo, "check", "--locked", "--offline", "--bin", "leviathan-desktop-shell"],
        cwd=DESKTOP / "src-tauri",
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
