"""Exercise the installed sidecar's durable halt lifecycle in one local profile."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import secrets
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path


def entry_digest(profile: Path) -> str:
    hasher = hashlib.sha256()
    for directory, label in ((profile, b"root/"), (profile / "data", b"data/")):
        if not directory.is_dir():
            continue
        names = []
        for path in directory.iterdir():
            encoded = path.name.encode("utf-16le", "surrogatepass")
            units = tuple(
                int.from_bytes(encoded[i : i + 2], "little") for i in range(0, len(encoded), 2)
            )
            names.append((units, encoded))
        for _, encoded in sorted(names):
            hasher.update(label)
            hasher.update(encoded)
            hasher.update(b"\x00\x00")
    return hasher.hexdigest()


class Sidecar:
    def __init__(self, executable: Path, local_app_data: Path, capability: str) -> None:
        profile = local_app_data / "LeviathanAI"
        existed = (profile / "data").exists()
        digest = entry_digest(profile)
        env = os.environ.copy()
        env.update(
            LOCALAPPDATA=str(local_app_data),
            LEVIATHAN_DESKTOP_CAPABILITY=capability,
            LEVIATHAN_DATA_ROOT_PREEXISTED="1" if existed else "0",
            LEVIATHAN_DATA_ROOT_ENTRY_SHA256=digest,
        )
        self.process = subprocess.Popen(
            [str(executable)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self.lines: list[str] = []
        self.output: queue.Queue[str] = queue.Queue()
        assert self.process.stdout is not None
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            self.lines.append(line.rstrip())
            self.output.put(line)

    def ready_port(self, *, timeout: float = 25) -> int | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                line = self.output.get(timeout=0.2)
            except queue.Empty:
                if self.process.poll() is not None:
                    return None
                continue
            matched = re.fullmatch(r"LEVIATHAN_READY port=(\d+)\s*", line)
            if matched:
                return int(matched.group(1))
        return None

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=10)


def probe_status(port: int, path: str, *, headers: dict[str, str] | None = None) -> int:
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def require_status(actual: int, expected: int, label: str) -> None:
    if actual != expected:
        raise RuntimeError(f"{label} returned HTTP {actual}, expected {expected}")


def expect_api_error(
    port: int,
    capability: str,
    path: str,
    expected_status: int,
    expected_detail: str,
    *,
    body: dict[str, str],
) -> int:
    origin = f"http://127.0.0.1:{port}"
    payload = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        origin + path,
        data=payload,
        headers={
            "X-Leviathan-Capability": capability,
            "Origin": origin,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status = response.status
            document = json.load(response)
    except urllib.error.HTTPError as error:
        status = error.code
        document = json.loads(error.read().decode("utf-8"))
    if status != expected_status or document.get("detail") != expected_detail:
        raise RuntimeError(f"{path} returned an unexpected error response")
    return status


def api(port: int, capability: str, path: str, *, body: dict[str, str] | None = None) -> dict:
    origin = f"http://127.0.0.1:{port}"
    headers = {"X-Leviathan-Capability": capability}
    payload = None
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        headers.update({"Origin": origin, "Content-Type": "application/json"})
    request = urllib.request.Request(origin + path, data=payload, headers=headers)
    with urllib.request.urlopen(request, timeout=5) as response:
        assert response.status == 200, (path, response.status)
        return json.load(response)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sidecar", type=Path, required=True)
    parser.add_argument("--local-app-data", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.sidecar.is_file():
        raise RuntimeError("Installed sidecar executable is missing")
    capability = secrets.token_hex(32)
    profile = args.local_app_data / "LeviathanAI"
    store = profile / "data/halt-state.sqlite3"
    observations = []

    first = Sidecar(args.sidecar, args.local_app_data, capability)
    try:
        port = first.ready_port()
        if port is None:
            raise RuntimeError("Initial installed sidecar was not ready")
        require_status(probe_status(port, "/api/health"), 200, "health")
        terminal_status = probe_status(port, "/")
        require_status(terminal_status, 200, "terminal")
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as response:
            terminal_marker_present = b'<div id="root"></div>' in response.read()
        if not terminal_marker_present:
            raise RuntimeError("Terminal HTML root marker is missing")
        missing_capability_status = probe_status(port, "/api/risk/status")
        require_status(missing_capability_status, 403, "missing capability")
        wrong_capability_status = probe_status(
            port, "/api/risk/status", headers={"X-Leviathan-Capability": "0" * 64}
        )
        require_status(wrong_capability_status, 403, "wrong capability")
        foreign_host_status = probe_status(
            port, "/api/risk/status", headers={"Host": f"localhost:{port}"}
        )
        require_status(foreign_host_status, 421, "foreign host")
        omega_unavailable_status = expect_api_error(
            port,
            capability,
            "/api/omega/kill",
            503,
            "OMEGA_ADAPTER_UNAVAILABLE",
            body={},
        )
        before = api(port, capability, "/api/risk/status")
        if before["halted"]:
            raise RuntimeError("Expected an unhalted profile before the test")
        foreign_origin_request = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/omega/kill",
            data=b"{}",
            headers={"Origin": "https://untrusted.example", "Content-Type": "application/json",
                "X-Leviathan-Capability": capability},
            method="POST",
        )
        try:
            with urllib.request.urlopen(foreign_origin_request, timeout=5) as response:
                foreign_origin_status = response.status
        except urllib.error.HTTPError as error:
            foreign_origin_status = error.code
        require_status(foreign_origin_status, 403, "foreign origin")
        missing_origin_request = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/omega/kill",
            data=b"{}",
            headers={"Content-Type": "application/json", "X-Leviathan-Capability": capability},
            method="POST",
        )
        try:
            with urllib.request.urlopen(missing_origin_request, timeout=5) as response:
                missing_origin_status = response.status
        except urllib.error.HTTPError as error:
            missing_origin_status = error.code
        require_status(missing_origin_status, 403, "missing origin")
        engaged = api(port, capability, "/api/risk/halt", body={"reason": "operator_halt"})
        if not engaged["halted"] or "operator_halt" not in engaged["active_halts"]:
            raise RuntimeError("Operator halt was not committed")
        observations.append(
            {"phase": "engaged", "port": port, "halted": True, "reasons": engaged["active_halts"]}
        )
    finally:
        first.stop()

    restarted = Sidecar(args.sidecar, args.local_app_data, capability)
    try:
        port = restarted.ready_port()
        if port is None:
            raise RuntimeError("Restart after engaged halt was not ready")
        # First HTTP route after readiness must observe the persisted halt.
        status = api(port, capability, "/api/risk/status")
        if not status["halted"] or "operator_halt" not in status["active_halts"]:
            raise RuntimeError("Restart silently cleared the operator halt")
        observations.append(
            {"phase": "restored", "port": port, "halted": True, "reasons": status["active_halts"]}
        )
        origin = f"http://127.0.0.1:{port}"
        request = urllib.request.Request(
            origin + "/api/risk/halt/lift",
            data=json.dumps({"reason": "operator_halt"}).encode("utf-8"),
            headers={
                "X-Leviathan-Capability": capability,
                "Origin": origin,
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                lift_status = response.status
        except urllib.error.HTTPError as error:
            lift_status = error.code
        require_status(lift_status, 401, "halt lift without a signed-in operator")
        observations.append(
            {"phase": "unauthenticated_lift_denied", "port": port, "status": lift_status}
        )
    finally:
        restarted.stop()

    after_denied_lift = Sidecar(args.sidecar, args.local_app_data, capability)
    try:
        port = after_denied_lift.ready_port()
        if port is None:
            raise RuntimeError("Restart after denied lift was not ready")
        status = api(port, capability, "/api/risk/status")
        if not status["halted"] or "operator_halt" not in status["active_halts"]:
            raise RuntimeError("Unauthenticated lift changed the durable halt")
        observations.append(
            {
                "phase": "denied_lift_preserved_halt",
                "port": port,
                "halted": True,
                "reasons": status["active_halts"],
            }
        )
    finally:
        after_denied_lift.stop()

    if not store.is_file():
        raise RuntimeError("Durable halt store is missing after lifecycle trial")
    store.write_bytes(b"intentionally corrupt acceptance copy")
    corrupt = Sidecar(args.sidecar, args.local_app_data, capability)
    try:
        port = corrupt.ready_port(timeout=15)
        if port is not None or corrupt.process.poll() is None:
            raise RuntimeError("Corrupt halt store incorrectly reached readiness")
        observations.append(
            {"phase": "corrupt_store", "ready": False, "exit": corrupt.process.returncode}
        )
    finally:
        corrupt.stop()
    result = {
        "installedSidecar": str(args.sidecar),
        "httpProbes": {
            "health": 200,
            "terminal": terminal_status,
            "terminalRootMarker": terminal_marker_present,
            "missingCapability": missing_capability_status,
            "wrongCapability": wrong_capability_status,
            "foreignOrigin": foreign_origin_status,
            "missingOrigin": missing_origin_status,
            "foreignHost": foreign_host_status,
            "unconfiguredOmegaKill": omega_unavailable_status,
        },
        "isolatedProfile": str(profile),
        "profileMarkerPresent": (profile / "data/profile.json").is_file(),
        "observations": observations,
        "capabilityRecorded": False,
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
