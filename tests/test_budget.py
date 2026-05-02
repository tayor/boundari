from __future__ import annotations

from decimal import Decimal

from boundari import Boundary, Budget, ToolPolicy


def noop() -> str:
    return "ok"


def test_tool_call_budget_blocks_next_call() -> None:
    boundary = Boundary(budget=Budget(max_tool_calls=1), tools=[ToolPolicy("tool.noop")])
    safe_noop = boundary.wrap_tool("tool.noop", noop)

    assert safe_noop() == "ok"
    decision = safe_noop()

    assert decision.allowed is False
    assert decision.reason == "budget_exceeded"
    assert decision.metadata["budget_reason"] == "tool_call_budget_exceeded"


def test_cost_budget_blocks_when_context_is_already_spent() -> None:
    boundary = Boundary(
        budget=Budget(max_cost_usd=Decimal("0.10")),
        tools=[ToolPolicy("tool.noop")],
    )
    context = boundary.new_run_context()
    context.record_tool_call(cost_usd=Decimal("0.10"))

    decision = boundary.decide("tool.noop", context=context)

    assert decision.reason == "budget_exceeded"
    assert decision.metadata["budget_reason"] == "cost_budget_exceeded"
