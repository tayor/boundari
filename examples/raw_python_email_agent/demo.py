from __future__ import annotations

from boundari import ApprovalRequest, Boundary, Budget, ToolPolicy


def approve_internal_only(request: ApprovalRequest) -> bool:
    return str(request.args_summary.get("to", "")).endswith("@example.com")


def send_email(to: str, subject: str, body: str) -> dict[str, str]:
    return {"message_id": "msg_demo", "status": "sent", "to": to, "body": body}


boundary = Boundary(
    name="raw_python_email_agent",
    budget=Budget(max_tool_calls=3),
    tools=[
        ToolPolicy("email.send")
        .require_approval(when="recipient_domain not in trusted_domains")
        .output_schema("EmailResult"),
        ToolPolicy("shell.run").deny(),
    ],
    trusted_domains=["example.com"],
    approver=approve_internal_only,
)

safe_send_email = boundary.wrap_tool("email.send", send_email)


if __name__ == "__main__":
    print(safe_send_email("teammate@example.com", "Internal note", "Looks good."))
    print(safe_send_email("customer@outside.test", "Refund", "Approval required."))
