from __future__ import annotations

import json

from boundari import AuditEvent, Boundary, JSONLAuditLog, Redactor, ToolPolicy


def test_redactor_masks_common_sensitive_values() -> None:
    redactor = Redactor()
    text = "alice@example.com +1 415-555-0101 4242 4242 4242 4242 sk-test-secret123"

    redacted = redactor.redact_text(text)

    assert "alice@example.com" not in redacted
    assert "415-555-0101" not in redacted
    assert "4242 4242" not in redacted
    assert "sk-test" not in redacted
    assert "[REDACTED:email]" in redacted
    assert "[REDACTED:phone]" in redacted
    assert "[REDACTED:credit_card]" in redacted
    assert "[REDACTED:api_key]" in redacted


def test_tool_outputs_are_redacted_before_return() -> None:
    boundary = Boundary(tools=[ToolPolicy("profile.read")])
    safe_read = boundary.wrap_tool(
        "profile.read",
        lambda: {
            "email": "alice@example.com",
            "api_key": "secret-token-value",
            "nested": [{"token": "opaque-token"}, "sk-test-secret123"],
        },
    )

    assert safe_read() == {
        "email": "[REDACTED:email]",
        "api_key": "[REDACTED:api_key]",
        "nested": [{"token": "[REDACTED:api_key]"}, "[REDACTED:api_key]"],
    }


def test_jsonl_audit_log_writes_redacted_metadata(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    audit = JSONLAuditLog(path)

    audit.emit(
        AuditEvent(
            run_id="run_1",
            event="tool_call_denied",
            tool="email.send",
            reason="approval_denied",
            decision="denied",
            metadata={"to": "alice@example.com", "token": "opaque-token"},
        )
    )

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["metadata"] == {
        "to": "[REDACTED:email]",
        "token": "[REDACTED:api_key]",
    }
