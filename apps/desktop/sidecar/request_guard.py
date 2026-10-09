"""Per-launch HTTP boundary for the desktop shell's loopback server."""

from __future__ import annotations

import hmac

from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response


def reject_request(request: Request, *, capability: str, port: int) -> Response | None:
    expected_host = f"127.0.0.1:{port}"
    expected_origin = f"http://{expected_host}"
    hosts = request.headers.getlist("host")
    origins = request.headers.getlist("origin")
    if hosts != [expected_host]:
        return PlainTextResponse("Invalid Host", status_code=421)
    if len(origins) > 1 or (origins and origins != [expected_origin]):
        return PlainTextResponse("Invalid Origin", status_code=403)
    protected = request.url.path.startswith("/api/") and request.url.path != "/api/health"
    protected = protected or request.url.path == "/desktop/update-readiness"
    if protected:
        if request.method not in {"GET", "HEAD", "OPTIONS"} and origins != [expected_origin]:
            return PlainTextResponse("Origin required", status_code=403)
        provided = request.headers.getlist("x-leviathan-capability")
        if len(provided) != 1 or not hmac.compare_digest(provided[0], capability):
            return PlainTextResponse("Forbidden", status_code=403)
    return None
