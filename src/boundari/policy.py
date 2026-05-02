"""Tool policy objects and decorator metadata."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, TypeVar

from pydantic import BaseModel

F = TypeVar("F", bound=Callable[..., Any])


@dataclass
class ToolPolicy:
    """Policy for one named tool."""

    name: str
    allowed: bool = True
    approval_required: bool = False
    approval_condition: str | None = None
    risk: str = "medium"
    scopes: tuple[str, ...] = ()
    input_model: type[BaseModel] | None = None
    output_model: type[BaseModel] | None = None
    input_schema_name: str | None = None
    output_schema_name: str | None = None
    allowed_tables_value: tuple[str, ...] | None = None
    max_amount_value: Decimal | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def allow(self) -> ToolPolicy:
        self.allowed = True
        return self

    def deny(self) -> ToolPolicy:
        self.allowed = False
        return self

    def require_approval(self, when: str | None = None) -> ToolPolicy:
        self.approval_required = True
        self.approval_condition = when
        return self

    def with_risk(self, risk: str) -> ToolPolicy:
        self.risk = risk
        return self

    def with_scopes(self, scopes: Iterable[str]) -> ToolPolicy:
        self.scopes = tuple(scopes)
        return self

    def input(self, model: type[BaseModel]) -> ToolPolicy:
        self.input_model = model
        self.input_schema_name = model.__name__
        return self

    def output(self, model: type[BaseModel]) -> ToolPolicy:
        self.output_model = model
        self.output_schema_name = model.__name__
        return self

    def input_schema(self, name: str) -> ToolPolicy:
        self.input_schema_name = name
        return self

    def output_schema(self, name: str) -> ToolPolicy:
        self.output_schema_name = name
        return self

    def allow_tables(self, tables: Iterable[str]) -> ToolPolicy:
        self.allowed_tables_value = tuple(tables)
        return self

    def max_amount(self, amount: Decimal | str | float | int) -> ToolPolicy:
        self.max_amount_value = Decimal(str(amount))
        return self

    @property
    def has_output_schema(self) -> bool:
        return self.output_model is not None or self.output_schema_name is not None


def boundary_tool(
    *,
    name: str,
    risk: str = "medium",
    scopes: Iterable[str] | None = None,
    require_approval: bool = False,
) -> Callable[[F], F]:
    """Attach Boundari policy metadata to a callable."""

    def decorate(func: F) -> F:
        policy = ToolPolicy(name=name, risk=risk, scopes=tuple(scopes or ()))
        if require_approval:
            policy.require_approval()
        func.__boundari_tool_name__ = name  # type: ignore[attr-defined]
        func.__boundari_tool_policy__ = policy  # type: ignore[attr-defined]
        return func

    return decorate
