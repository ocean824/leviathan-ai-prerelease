from __future__ import annotations

import json
import subprocess
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
QR_MODULE = REPOSITORY_ROOT / "apps" / "desktop" / "shell" / "qr.js"
SYNTHETIC_TOTP_URI = "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP"
SYNTHETIC_SECRET = "JBSWY3DPEHPK3PXP"

# Independent QR Model 2 known-answer vector: byte mode, version 3, ECC M, mask 2.
# The frozen 29x29 matrix catches accidental changes to ECC or mask selection.
EXPECTED_MATRIX = """\
11111110000010100001101111111
10000010000001011000101000001
10111010111110100010101011101
10111010100110100110001011101
10111010110110111101101011101
10000010101110010000001000001
11111110101010101010101111111
00000000111010010001000000000
10111110001110111000101111100
10010101011011111111101110011
01000011111000010110100101000
01001100100110010011010101010
01100011010010100000000001110
10101000110010111011101111001
11011111011100011110110011000
01100101101110011010110111010
01101110000000010000010101100
10101001011011011001111111001
10111011001001110110101100000
10010101101101010001001101001
10111110111100111000111110101
00000000101000011001100010111
11111110001010010101101010000
10000010101110111001100010010
10111010111100010000111111111
10111010110101111101100000111
10111010111101011011111010110
10000010010001100001110100010
11111110100111111110000100100""".splitlines()


NODE_PROBE = r"""
const modulePath = process.argv[1];
const uri = process.argv[2];
const storageCalls = [];
const storage = new Proxy({}, {
  get(_target, key) {
    if (key === "setItem") return (...args) => storageCalls.push(["setItem", ...args]);
    if (key === "getItem") return (...args) => {
      storageCalls.push(["getItem", ...args]);
      return null;
    };
    if (key === "removeItem") return (...args) => storageCalls.push(["removeItem", ...args]);
    if (key === "clear") return (...args) => storageCalls.push(["clear", ...args]);
    storageCalls.push(["get", String(key)]);
    return null;
  },
  set(_target, key, value) { storageCalls.push(["set", String(key), String(value)]); return true; },
  deleteProperty(_target, key) { storageCalls.push(["delete", String(key)]); return true; },
});
const logs = [];
for (const level of ["log", "info", "warn", "error", "debug"]) {
  console[level] = (...args) => logs.push([level, ...args.map(String)]);
}

global.window = { localStorage: storage, sessionStorage: storage };
global.localStorage = storage;
global.sessionStorage = storage;
class Element {
  constructor(name) { this.name = name; this.attributes = {}; this.children = []; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  appendChild(child) { this.children.push(child); return child; }
}
global.document = {
  createElementNS(_namespace, name) { return new Element(name); },
};

const api = require(modulePath);
const container = {
  children: [],
  replaceChildren(...children) { this.children = children; },
};
const rendered = api.renderOtpauthQr(container, uri);
const svg = container.children[0];
const path = svg && svg.children.find((child) => child.name === "path");
let matrix = [];
if (svg && path) {
  const viewSize = Number(svg.attributes.viewBox.split(" ")[2]);
  const size = viewSize - 8;
  matrix = Array.from({ length: size }, () => Array(size).fill("0"));
  for (const match of path.attributes.d.matchAll(/M(\d+),(\d+)h1v1h-1z/g)) {
    const x = Number(match[1]) - 4;
    const y = Number(match[2]) - 4;
    if (x >= 0 && x < size && y >= 0 && y < size) matrix[y][x] = "1";
  }
}
const invalidContainer = {
  children: [],
  replaceChildren(...children) { this.children = children; },
};
const invalidRejected = api.renderOtpauthQr(
  invalidContainer,
  "https://example.invalid/not-an-otp-uri",
) === false;
api.clearOtpauthQr(container);
const cleared = container.children.length === 0;
api.clearOtpauthQr(container);
process.stdout.write(JSON.stringify({
  rendered,
  matrix: matrix.map((row) => row.join("")),
  renderedTree: JSON.stringify(container.children),
  invalidRejected,
  invalidContainerEmpty: invalidContainer.children.length === 0,
  cleared,
  logs,
  storageCalls,
  browserGlobalPublished: window.SigninQr === api,
}));
"""


NODE_SIGNIN_PROBE = r"""
const [bridgePath, qrPath, signinPath, uri] = process.argv.slice(1);
const secret = "JBSWY3DPEHPK3PXP";
const logs = [];
const storageCalls = [];
for (const level of ["log", "info", "warn", "error", "debug"]) {
  console[level] = (...args) => logs.push([level, ...args.map(String)]);
}
const storage = new Proxy({}, {
  get(_target, key) {
    if (key === "setItem") return (...args) => storageCalls.push(["setItem", ...args]);
    if (key === "removeItem") return (...args) => storageCalls.push(["removeItem", ...args]);
    if (key === "getItem") return (...args) => {
      storageCalls.push(["getItem", ...args]);
      return null;
    };
    storageCalls.push(["get", String(key)]);
    return null;
  },
  set(_target, key, value) { storageCalls.push(["set", String(key), String(value)]); return true; },
});

class Element {
  constructor(name) {
    this.name = name;
    this.children = [];
    this.attributes = {};
    this.listeners = {};
    this.textContent = "";
    this.value = "";
    this.hidden = false;
    this.disabled = false;
  }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; }
  addEventListener(name, listener) { this.listeners[name] = listener; }
  querySelector(selector) { return selector === "button" ? this.button : null; }
}
class Form extends Element {
  constructor(name, fields) {
    super(name);
    this.fields = fields;
    this.button = new Element("button");
    this.elements = { namedItem: (field) => this.fields[field] || null };
  }
}
const signInForm = new Form("signin-form", {
  email: new Element("email"),
  password: new Element("password"),
  totp_code: new Element("totp_code"),
});
signInForm.fields.email.value = "synthetic@example.invalid";
signInForm.fields.password.value = "synthetic-password";
const confirmForm = new Form("totp-confirm-form", {
  enrollment_code: new Element("enrollment_code"),
});
confirmForm.fields.enrollment_code.value = "123456";
const elements = {
  "signin-form": signInForm,
  status: new Element("status"),
  "totp-enrollment": new Element("totp-enrollment"),
  "totp-uri": new Element("totp-uri"),
  "totp-secret": new Element("totp-secret"),
  "totp-qr": new Element("totp-qr"),
  "totp-confirm-form": confirmForm,
};
const bridgeCalls = [];
global.window = {
  localStorage: storage,
  sessionStorage: storage,
  addEventListener() {},
  __TAURI_INTERNALS__: {
    async invoke(command, args) {
      bridgeCalls.push(command);
      if (command === "license_sign_in") {
        return { state: "TOTP_ENROLLMENT_REQUIRED", otpauthUri: uri };
      }
      if (command === "license_enroll_totp") return { state: "ENROLLED" };
      if (command === "license_status") return { state: "LOCKED", features: {} };
      throw new Error("UNEXPECTED_COMMAND");
    },
  },
};
global.localStorage = storage;
global.sessionStorage = storage;
global.document = {
  getElementById(id) { return elements[id] || null; },
  createElementNS(_namespace, name) { return new Element(name); },
};

require(bridgePath);
require(qrPath);
require(signinPath);
(async () => {
  await signInForm.listeners.submit({ preventDefault() {} });
  const enrollmentShown = elements["totp-enrollment"].hidden === false
    && signInForm.hidden === true;
  const qrRendered = elements["totp-qr"].children.length === 1
    && elements["totp-qr"].children[0].name === "svg";
  const manualFallbackPresent = elements["totp-secret"].value === secret;
  const uriVisibleOnlyInEnrollment = elements["totp-uri"].textContent === uri;
  await confirmForm.listeners.submit({ preventDefault() {} });
  const clearedOnConfirm = elements["totp-qr"].children.length === 0
    && elements["totp-uri"].textContent === ""
    && elements["totp-secret"].value === ""
    && confirmForm.fields.enrollment_code.value === ""
    && elements["totp-enrollment"].hidden === true;
  process.stdout.write(JSON.stringify({
    enrollmentShown,
    qrRendered,
    manualFallbackPresent,
    uriVisibleOnlyInEnrollment,
    clearedOnConfirm,
    logs,
    storageCalls,
    bridgeCalls,
  }));
})().catch(() => { process.exitCode = 1; });
"""


def _probe_qr_module() -> tuple[dict[str, object], str, str]:
    completed = subprocess.run(
        ["node", "-e", NODE_PROBE, str(QR_MODULE), SYNTHETIC_TOTP_URI],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert completed.returncode == 0, "Node QR probe failed"
    return json.loads(completed.stdout), completed.stdout, completed.stderr


def _probe_signin_ui() -> tuple[dict[str, object], str, str]:
    completed = subprocess.run(
        [
            "node",
            "-e",
            NODE_SIGNIN_PROBE,
            str(REPOSITORY_ROOT / "apps/desktop/src/bridge_license.js"),
            str(REPOSITORY_ROOT / "apps/desktop/shell/qr.js"),
            str(REPOSITORY_ROOT / "apps/desktop/shell/signin.js"),
            SYNTHETIC_TOTP_URI,
        ],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert completed.returncode == 0, "Node sign-in UI probe failed"
    return json.loads(completed.stdout), completed.stdout, completed.stderr


def test_totp_svg_matches_known_answer_qr_matrix() -> None:
    result, stdout, stderr = _probe_qr_module()

    assert result["rendered"] is True
    assert result["matrix"] == EXPECTED_MATRIX
    assert SYNTHETIC_TOTP_URI not in stdout + stderr
    assert SYNTHETIC_SECRET not in stdout + stderr


def test_invalid_uri_is_rejected_and_clear_removes_rendered_qr() -> None:
    result, _, _ = _probe_qr_module()

    assert result["invalidRejected"] is True
    assert result["invalidContainerEmpty"] is True
    assert result["cleared"] is True


def test_uri_is_never_logged_or_written_to_browser_storage() -> None:
    result, stdout, stderr = _probe_qr_module()

    assert result["logs"] == []
    assert result["storageCalls"] == []
    assert result["browserGlobalPublished"] is True
    assert SYNTHETIC_TOTP_URI not in stdout + stderr
    assert SYNTHETIC_SECRET not in stdout + stderr


def test_enrollment_page_renders_qr_and_clears_setup_material_on_confirm() -> None:
    html = (REPOSITORY_ROOT / "apps/desktop/shell/signin.html").read_text(encoding="utf-8")
    assert html.index('<script src="qr.js"></script>') < html.index(
        '<script src="signin.js"></script>'
    )

    result, stdout, stderr = _probe_signin_ui()
    assert result["enrollmentShown"] is True
    assert result["qrRendered"] is True
    assert result["manualFallbackPresent"] is True
    assert result["uriVisibleOnlyInEnrollment"] is True
    assert result["clearedOnConfirm"] is True
    assert result["logs"] == []
    assert result["storageCalls"] == []
    assert result["bridgeCalls"] == ["license_sign_in", "license_enroll_totp"]
    assert SYNTHETIC_TOTP_URI not in stdout + stderr
    assert SYNTHETIC_SECRET not in stdout + stderr
