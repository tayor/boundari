from __future__ import annotations

from boundari import ApprovalRequest, Boundary, ToolPolicy


async def async_tool(value: str) -> dict[str, str]:
    return {"value": value}


async def test_async_tool_and_async_approver() -> None:
    async def approve(request: ApprovalRequest) -> bool:
        return request.tool_name == "tool.async"

    boundary = Boundary(tools=[ToolPolicy("tool.async").require_approval()], approver=approve)
    wrapped = boundary.wrap_tool("tool.async", async_tool)

    result = await wrapped("ok")

    assert result == {"value": "ok"}
