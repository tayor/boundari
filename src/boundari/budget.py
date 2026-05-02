"""Per-run budget tracking."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from decimal import Decimal
from time import monotonic
from uuid import uuid4


@dataclass(frozen=True)
class Budget:
    """Runtime limits for a boundary contract."""

    max_tool_calls: int | None = None
    max_runtime_seconds: float | None = None
    max_cost_usd: Decimal | None = None
    max_tokens: int | None = None

    def copy_with(
        self,
        *,
        max_tool_calls: int | None = None,
        max_runtime_seconds: float | None = None,
        max_cost_usd: Decimal | str | float | None = None,
        max_tokens: int | None = None,
    ) -> Budget:
        """Return a budget with only provided values replaced."""

        cost = self.max_cost_usd if max_cost_usd is None else Decimal(str(max_cost_usd))
        return replace(
            self,
            max_tool_calls=self.max_tool_calls if max_tool_calls is None else max_tool_calls,
            max_runtime_seconds=(
                self.max_runtime_seconds if max_runtime_seconds is None else max_runtime_seconds
            ),
            max_cost_usd=cost,
            max_tokens=self.max_tokens if max_tokens is None else max_tokens,
        )


@dataclass
class RunContext:
    """Mutable accounting state for one agent run."""

    budget: Budget = field(default_factory=Budget)
    run_id: str = field(default_factory=lambda: f"run_{uuid4().hex}")
    started_at: float = field(default_factory=monotonic)
    tool_calls: int = 0
    cost_usd: Decimal = field(default_factory=lambda: Decimal("0"))
    tokens: int = 0

    @property
    def runtime_seconds(self) -> float:
        return monotonic() - self.started_at

    def check_before_tool_call(self) -> str | None:
        """Return a specific budget failure reason, or None when still in budget."""

        if (
            self.budget.max_runtime_seconds is not None
            and self.runtime_seconds > self.budget.max_runtime_seconds
        ):
            return "runtime_budget_exceeded"

        if self.budget.max_tool_calls is not None and self.tool_calls >= self.budget.max_tool_calls:
            return "tool_call_budget_exceeded"

        if self.budget.max_cost_usd is not None and self.cost_usd >= self.budget.max_cost_usd:
            return "cost_budget_exceeded"

        if self.budget.max_tokens is not None and self.tokens >= self.budget.max_tokens:
            return "token_budget_exceeded"

        return None

    def record_tool_call(
        self,
        *,
        cost_usd: Decimal | str | float | None = None,
        tokens: int | None = None,
    ) -> None:
        """Record an executed tool call and optional usage counters."""

        self.tool_calls += 1
        if cost_usd is not None:
            self.cost_usd += Decimal(str(cost_usd))
        if tokens is not None:
            self.tokens += tokens
