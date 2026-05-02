"""YAML policy loading."""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from typing import Any

import yaml as pyyaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from boundari.approval import Approver
from boundari.audit import AuditSink
from boundari.boundary import Boundary
from boundari.budget import Budget
from boundari.exceptions import PolicyValidationError
from boundari.policy import ToolPolicy
from boundari.redact import Redactor


class ApprovalCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    when: str


class BudgetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_tool_calls: int | None = None
    max_runtime_seconds: float | None = None
    max_cost_usd: Decimal | None = None
    max_tokens: int | None = None


class ToolConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allow: bool = True
    require_approval: bool | ApprovalCondition = False
    scopes: list[str] = Field(default_factory=list)
    risk: str = "medium"
    allowed_tables: list[str] | None = None
    max_amount: Decimal | None = None
    input_schema: str | None = None
    output_schema: str | None = None

    def to_policy(self, name: str) -> ToolPolicy:
        policy = ToolPolicy(
            name=name,
            allowed=self.allow,
            risk=self.risk,
            scopes=tuple(self.scopes),
        )
        if isinstance(self.require_approval, ApprovalCondition):
            policy.require_approval(when=self.require_approval.when)
        elif self.require_approval:
            policy.require_approval()
        if self.allowed_tables is not None:
            policy.allow_tables(self.allowed_tables)
        if self.max_amount is not None:
            policy.max_amount(self.max_amount)
        if self.input_schema is not None:
            policy.input_schema(self.input_schema)
        if self.output_schema is not None:
            policy.output_schema(self.output_schema)
        return policy


class DataConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    redact: list[str] = Field(default_factory=lambda: ["api_key", "credit_card", "email", "phone"])
    trusted_domains: list[str] = Field(default_factory=list)


class OutputsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    require_schema: bool = False
    block_if_contains: list[str] = Field(default_factory=list)


class PolicyTestsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    forbidden_tools: list[str] = Field(default_factory=list)
    golden_traces: list[str] = Field(default_factory=list)


class BoundaryFileConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent: str | None = None
    name: str | None = None
    budgets: BudgetConfig = Field(default_factory=BudgetConfig)
    tools: dict[str, ToolConfig] = Field(default_factory=dict)
    data: DataConfig = Field(default_factory=DataConfig)
    outputs: OutputsConfig = Field(default_factory=OutputsConfig)
    policy_tests: PolicyTestsConfig = Field(default_factory=PolicyTestsConfig)

    @field_validator("tools")
    @classmethod
    def require_tools(cls, value: dict[str, ToolConfig]) -> dict[str, ToolConfig]:
        if not value:
            raise ValueError("At least one tool policy is required")
        return value

    @property
    def boundary_name(self) -> str:
        return self.name or self.agent or "boundari_agent"


def load_config(path: str | Path) -> BoundaryFileConfig:
    policy_path = Path(path)
    try:
        raw = pyyaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
        return BoundaryFileConfig.model_validate(raw)
    except (OSError, ValidationError, pyyaml.YAMLError) as exc:
        raise PolicyValidationError(f"Invalid Boundari policy {policy_path}: {exc}") from exc


def boundary_from_config(
    config: BoundaryFileConfig,
    *,
    approver: Approver | None = None,
    auditor: AuditSink | None = None,
) -> Boundary:
    budget = Budget(
        max_tool_calls=config.budgets.max_tool_calls,
        max_runtime_seconds=config.budgets.max_runtime_seconds,
        max_cost_usd=config.budgets.max_cost_usd,
        max_tokens=config.budgets.max_tokens,
    )
    return Boundary(
        name=config.boundary_name,
        budget=budget,
        tools=[tool_config.to_policy(name) for name, tool_config in config.tools.items()],
        approver=approver,
        auditor=auditor,
        redactor=Redactor(config.data.redact),
        trusted_domains=config.data.trusted_domains,
        outputs_require_schema=config.outputs.require_schema,
        block_if_contains=config.outputs.block_if_contains,
    )


def load_boundary(
    path: str | Path,
    *,
    approver: Approver | None = None,
    auditor: AuditSink | None = None,
) -> Boundary:
    return boundary_from_config(load_config(path), approver=approver, auditor=auditor)


def sample_policy() -> str:
    return """agent: support_agent

budgets:
  max_tool_calls: 20
  max_runtime_seconds: 180
  max_cost_usd: "0.50"

tools:
  docs.search:
    allow: true
    scopes: ["docs:read"]
    output_schema: SearchResult

  email.send:
    allow: true
    require_approval:
      when: "recipient_domain not in trusted_domains"
    scopes: ["email:send"]
    risk: high
    input_schema: EmailInput
    output_schema: EmailResult

  stripe.refund:
    allow: true
    require_approval: true
    scopes: ["stripe:refund"]
    risk: high
    max_amount: "100.00"
    output_schema: RefundResult

  shell.run:
    allow: false

data:
  redact:
    - api_key
    - credit_card
    - email
    - phone
  trusted_domains:
    - example.com

outputs:
  require_schema: true
  block_if_contains:
    - "{{SECRET}}"

policy_tests:
  forbidden_tools:
    - shell.run
"""


def dump_yaml(data: dict[str, Any]) -> str:
    return pyyaml.safe_dump(data, sort_keys=False)
