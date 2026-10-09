"""Focused unit checks for the public CHAT-002 result boundary."""

import hashlib
import json

from leviathan_api.chat.tool_bridge import (
    ChatToolResultV1,
    ToolDecisionCodeV1,
    _bounded_output,
)


def test_result_redacts_caller_controlled_request_identifier() -> None:
    secret_request_id = "SECRET-canary-request-id"

    result = ChatToolResultV1(
        request_id=secret_request_id,
        status=ToolDecisionCodeV1.DENIED,
    )

    assert secret_request_id not in result.model_dump_json()
    assert (
        result.request_id == "req_" + hashlib.sha256(secret_request_id.encode("utf-8")).hexdigest()
    )


def test_tool_output_redacts_sensitive_fields_and_bounds_size() -> None:
    redacted = json.loads(_bounded_output({"status": "ok", "api_token": "secret-value"}))
    oversized = _bounded_output({"payload": "x" * 20_000})

    assert redacted == {"api_token": "[REDACTED]", "status": "ok"}
    assert "secret-value" not in json.dumps(redacted)
    assert json.loads(oversized) == {"output": "[UNAVAILABLE]"}
