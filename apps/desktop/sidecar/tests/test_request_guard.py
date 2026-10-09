"""Adversarial checks for the desktop-only loopback request boundary."""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from request_guard import reject_request

PORT = 49123
ORIGIN = f"http://127.0.0.1:{PORT}"
CAPABILITY = "a" * 64


def make_client() -> TestClient:
    app = FastAPI()

    @app.middleware("http")
    async def guard(request: Request, call_next):
        denied = reject_request(request, capability=CAPABILITY, port=PORT)
        return denied if denied is not None else await call_next(request)

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.get("/api/risk/status")
    def risk():
        return {"halted": False}

    @app.post("/api/omega/kill")
    def kill():
        return {"halted": True}

    return TestClient(app, base_url=ORIGIN)


def test_public_health_keeps_local_readiness() -> None:
    with make_client() as client:
        assert client.get("/api/health").status_code == 200


def test_api_requires_the_per_launch_capability() -> None:
    with make_client() as client:
        assert client.get("/api/risk/status").status_code == 403
        assert (
            client.get("/api/risk/status", headers={"X-Leviathan-Capability": "b" * 64}).status_code
            == 403
        )
        assert (
            client.get(
                "/api/risk/status", headers={"X-Leviathan-Capability": CAPABILITY}
            ).status_code
            == 200
        )
        assert client.post("/api/omega/kill", headers={"Origin": ORIGIN}).status_code == 403
        assert (
            client.post(
                "/api/omega/kill", headers={"Origin": ORIGIN, "X-Leviathan-Capability": CAPABILITY}
            ).status_code
            == 200
        )


def test_cross_origin_simple_post_and_missing_origin_are_rejected() -> None:
    with make_client() as client:
        form = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Leviathan-Capability": CAPABILITY,
        }
        assert (
            client.post(
                "/api/omega/kill", headers={**form, "Origin": "https://untrusted.example"}
            ).status_code
            == 403
        )
        assert client.post("/api/omega/kill", headers=form).status_code == 403
        assert client.post("/api/omega/kill", headers={**form, "Origin": "null"}).status_code == 403


def test_exact_host_and_origin_required() -> None:
    with make_client() as client:
        token = {"X-Leviathan-Capability": CAPABILITY}
        for host in ("localhost:49123", "127.0.0.1:49124", "127.0.0.1:49123.evil.test"):
            assert (
                client.get("/api/risk/status", headers={**token, "Host": host}).status_code == 421
            )
        assert (
            client.get("/api/risk/status", headers={**token, "Origin": ORIGIN + "/"}).status_code
            == 403
        )
        assert (
            client.get(
                "/api/risk/status", headers={**token, "Origin": "http://localhost:49123"}
            ).status_code
            == 403
        )


def test_duplicate_headers_rejected() -> None:
    with make_client() as client:
        assert (
            client.get(
                "/api/risk/status",
                headers=[
                    ("Host", "127.0.0.1:49123"),
                    ("Host", "127.0.0.1:49123"),
                    ("X-Leviathan-Capability", CAPABILITY),
                ],
            ).status_code
            == 421
        )
        assert (
            client.get(
                "/api/risk/status",
                headers=[
                    ("Origin", ORIGIN),
                    ("Origin", ORIGIN),
                    ("X-Leviathan-Capability", CAPABILITY),
                ],
            ).status_code
            == 403
        )
        assert (
            client.get(
                "/api/risk/status",
                headers=[
                    ("X-Leviathan-Capability", CAPABILITY),
                    ("X-Leviathan-Capability", CAPABILITY),
                ],
            ).status_code
            == 403
        )
