from __future__ import annotations

import pytest
from pydantic import BaseModel

from boundari import (
    ApprovalRequest,
    Boundary,
    BoundaryDenied,
    MemoryAuditLog,
    ToolPolicy,
    boundary_tool,
)


class EmailInput(BaseModel):
    to: str
    subject: str
    body: str


class EmailResult(BaseModel):
    message_id: str
    status: str
    to: str


def send_email(to: str, subject: str, body: str) -> dict[str, str]:
    return {"message_id": "msg_1", "status": "sent", "to": to, "body": body}


def test_denies_unknown_and_explicitly_denied_tools() -> None:
    boundary = Boundary(tools=[ToolPolicy("shell.run").deny()])

    assert boundary.decide("missing.tool").reason == "tool_not_allowed"
    assert boundary.decide("shell.run").reason == "tool_not_allowed"


def test_conditional_approval_allows_internal_domain_without_callback() -> None:
    boundary = Boundary(
        tools=[
            ToolPolicy("email.send").require_approval("recipient_domain not in trusted_domains")
        ],
        trusted_domains=["example.com"],
    )
    safe_send = boundary.wrap_tool("email.send", send_email)

    result = safe_send("teammate@example.com", "Hi", "Body")

    assert result["status"] == "sent"


def test_external_domain_requires_approval_and_denies_without_callback() -> None:
    audit = MemoryAuditLog()
    boundary = Boundary(
        tools=[
            ToolPolicy("email.send").require_approval("recipient_domain not in trusted_domains")
        ],
        trusted_domains=["example.com"],
        auditor=audit,
    )
    safe_send = boundary.wrap_tool("email.send", send_email)

    decision = safe_send("person@outside.test", "Hi", "Body")

    assert decision.allowed is False
    assert decision.reason == "approval_denied"
    assert [event.event for event in audit.events] == [
        "approval_requested",
        "approval_denied",
        "tool_call_denied",
    ]


def test_approval_callback_can_allow_risky_call() -> None:
    seen: list[ApprovalRequest] = []

    def approve(request: ApprovalRequest) -> bool:
        seen.append(request)
        return request.tool_name == "email.send"

    boundary = Boundary(
        tools=[ToolPolicy("email.send").require_approval()],
        approver=approve,
    )
    safe_send = boundary.wrap_tool("email.send", send_email)

    result = safe_send("person@outside.test", "Hi", "Body")

    assert result["message_id"] == "msg_1"
    assert seen[0].args_summary["to"] == "person@outside.test"


def test_invalid_approval_condition_fails_closed() -> None:
    boundary = Boundary(
        tools=[ToolPolicy("email.send").require_approval("unknown_name == true")],
    )
    safe_send = boundary.wrap_tool("email.send", send_email)

    decision = safe_send("person@example.com", "Hi", "Body")

    assert decision.allowed is False
    assert decision.reason == "approval_denied"


@pytest.mark.parametrize(
    ("condition", "args"),
    [
        ("amount > 100", {"amount": "101"}),
        ("amount >", {"amount": "101"}),
    ],
)
def test_approval_condition_evaluation_errors_fail_closed(
    condition: str,
    args: dict[str, str],
) -> None:
    boundary = Boundary(
        tools=[ToolPolicy("stripe.refund").require_approval(condition)],
    )

    decision = boundary.decide("stripe.refund", args)

    assert decision.allowed is False
    assert decision.reason == "approval_denied"


def test_pydantic_input_and_output_validation() -> None:
    boundary = Boundary(
        tools=[ToolPolicy("email.send").input(EmailInput).output(EmailResult)],
    )
    safe_send = boundary.wrap_tool("email.send", send_email)

    valid = safe_send("a@example.com", "Hi", "Body")
    invalid = safe_send("a@example.com", "Hi")

    assert valid == {"message_id": "msg_1", "status": "sent", "to": "[REDACTED:email]"}
    assert invalid.reason == "input_validation_failed"


def test_raise_on_denied_uses_boundary_denied() -> None:
    boundary = Boundary(tools=[ToolPolicy("shell.run").deny()])
    safe_shell = boundary.wrap_tool("shell.run", lambda command: command, raise_on_denied=True)

    with pytest.raises(BoundaryDenied) as exc_info:
        safe_shell("whoami")

    assert exc_info.value.decision.reason == "tool_not_allowed"


def test_table_and_amount_constraints() -> None:
    boundary = Boundary(
        tools=[
            ToolPolicy("db.query").allow_tables(["customers", "orders"]),
            ToolPolicy("stripe.refund").max_amount("100.00"),
        ]
    )

    assert boundary.decide("db.query", {"query": "select * from customers"}).allowed
    assert (
        boundary.decide("db.query", {"query": "select * from payroll"}).reason
        == "table_not_allowed"
    )
    assert (
        boundary.decide("db.query", {"query": 'select * from "payroll"'}).reason
        == "table_not_allowed"
    )
    assert (
        boundary.decide("db.query", {"query": "select * from `payroll`"}).reason
        == "table_not_allowed"
    )
    assert (
        boundary.decide("db.query", {"query": "select * from [payroll]"}).reason
        == "table_not_allowed"
    )
    assert boundary.decide("stripe.refund", {"amount": "101.00"}).reason == "amount_exceeds_limit"


def test_decorator_attaches_policy_metadata() -> None:
    @boundary_tool(name="email.send", risk="high", scopes=["email:send"], require_approval=True)
    def tool() -> None:
        return None

    policy = tool.__boundari_tool_policy__

    assert tool.__boundari_tool_name__ == "email.send"
    assert policy.risk == "high"
    assert policy.scopes == ("email:send",)
    assert policy.approval_required is True
