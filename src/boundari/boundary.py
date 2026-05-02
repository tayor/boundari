"""Boundary contract enforcement."""

from __future__ import annotations

import ast
import asyncio
import inspect
import re
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from functools import wraps
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from boundari.approval import (
    ApprovalRequest,
    ApprovalResult,
    Approver,
    normalize_approval_result,
)
from boundari.audit import AuditEvent, AuditSink, MemoryAuditLog
from boundari.budget import Budget, RunContext
from boundari.exceptions import BoundaryDenied
from boundari.policy import ToolPolicy
from boundari.redact import Redactor


class Decision(BaseModel):
    """Structured result for an allowed or denied tool call decision."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    tool_name: str
    reason: str
    message: str
    run_id: str | None = None
    requires_approval: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    def raise_if_denied(self) -> None:
        if not self.allowed:
            raise BoundaryDenied(self)


@dataclass(frozen=True)
class WrappedAgent:
    """Lightweight proxy used by framework adapters."""

    agent: Any
    boundary: Boundary

    def __getattr__(self, name: str) -> Any:
        return getattr(self.agent, name)


class Boundary:
    """A runtime policy contract around agent tool calls."""

    def __init__(
        self,
        *,
        name: str = "boundari_agent",
        tools: Iterable[ToolPolicy] | Mapping[str, ToolPolicy] | None = None,
        budget: Budget | None = None,
        max_tool_calls: int | None = None,
        max_runtime_seconds: float | None = None,
        max_cost_usd: Decimal | str | float | None = None,
        max_tokens: int | None = None,
        approver: Approver | None = None,
        auditor: AuditSink | None = None,
        redactor: Redactor | None = None,
        trusted_domains: Iterable[str] | None = None,
        outputs_require_schema: bool = False,
        block_if_contains: Iterable[str] | None = None,
    ) -> None:
        self.name = name
        self.tools = self._normalize_tools(tools)
        configured_budget = budget or Budget()
        self.budget = configured_budget.copy_with(
            max_tool_calls=max_tool_calls,
            max_runtime_seconds=max_runtime_seconds,
            max_cost_usd=max_cost_usd,
            max_tokens=max_tokens,
        )
        self.approver = approver
        self.redactor = redactor or Redactor()
        self.auditor = auditor or MemoryAuditLog()
        self.trusted_domains = {domain.lower() for domain in trusted_domains or ()}
        self.outputs_require_schema = outputs_require_schema
        self.block_if_contains = tuple(block_if_contains or ())

    @classmethod
    def from_file(
        cls,
        path: str,
        *,
        approver: Approver | None = None,
        auditor: AuditSink | None = None,
    ) -> Boundary:
        from boundari.yaml import load_boundary

        return load_boundary(path, approver=approver, auditor=auditor)

    def new_run_context(self, *, run_id: str | None = None) -> RunContext:
        context = RunContext(budget=self.budget)
        if run_id is not None:
            context.run_id = run_id
        return context

    def wrap(self, agent: Any) -> WrappedAgent:
        return WrappedAgent(agent=agent, boundary=self)

    def wrap_tool(
        self,
        name: str,
        func: Callable[..., Any] | None = None,
        *,
        context: RunContext | None = None,
        raise_on_denied: bool = False,
    ) -> Callable[..., Any]:
        """Wrap a sync or async Python callable with boundary checks."""

        def decorate(inner: Callable[..., Any]) -> Callable[..., Any]:
            run_context = context or self.new_run_context()

            if inspect.iscoroutinefunction(inner):

                @wraps(inner)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    return await self._invoke_async(
                        name,
                        inner,
                        run_context,
                        raise_on_denied,
                        *args,
                        **kwargs,
                    )

                return async_wrapper

            @wraps(inner)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                return self._invoke_sync(
                    name,
                    inner,
                    run_context,
                    raise_on_denied,
                    *args,
                    **kwargs,
                )

            return sync_wrapper

        if func is not None:
            return decorate(func)
        return decorate

    def decide(
        self,
        tool_name: str,
        args: Mapping[str, Any] | None = None,
        context: RunContext | None = None,
    ) -> Decision:
        run_context = context or self.new_run_context()
        decision = self._precheck(tool_name, args or {}, run_context)
        if not decision.requires_approval:
            self._emit_decision(decision)
            return decision

        request = self._approval_request(tool_name, args or {}, run_context, decision)
        self._emit(
            "approval_requested",
            run_context,
            tool_name,
            reason=decision.reason,
            metadata={"risk": request.risk},
        )
        approval = self._approve_sync(request)
        return self._decision_from_approval(tool_name, run_context, approval)

    async def adecide(
        self,
        tool_name: str,
        args: Mapping[str, Any] | None = None,
        context: RunContext | None = None,
    ) -> Decision:
        run_context = context or self.new_run_context()
        decision = self._precheck(tool_name, args or {}, run_context)
        if not decision.requires_approval:
            self._emit_decision(decision)
            return decision

        request = self._approval_request(tool_name, args or {}, run_context, decision)
        self._emit(
            "approval_requested",
            run_context,
            tool_name,
            reason=decision.reason,
            metadata={"risk": request.risk},
        )
        approval = await self._approve_async(request)
        return self._decision_from_approval(tool_name, run_context, approval)

    def _invoke_sync(
        self,
        tool_name: str,
        func: Callable[..., Any],
        context: RunContext,
        raise_on_denied: bool,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        bound_args = self._bind_arguments(func, args, kwargs)
        input_decision = self._validate_input(tool_name, bound_args, context)
        if input_decision is not None:
            return self._handle_denial(input_decision, raise_on_denied)

        decision = self.decide(tool_name, bound_args, context)
        if not decision.allowed:
            return self._handle_denial(decision, raise_on_denied)

        context.record_tool_call()
        result = func(*args, **kwargs)
        return self._finalize_result(tool_name, result, context, raise_on_denied)

    async def _invoke_async(
        self,
        tool_name: str,
        func: Callable[..., Awaitable[Any]],
        context: RunContext,
        raise_on_denied: bool,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        bound_args = self._bind_arguments(func, args, kwargs)
        input_decision = self._validate_input(tool_name, bound_args, context)
        if input_decision is not None:
            return self._handle_denial(input_decision, raise_on_denied)

        decision = await self.adecide(tool_name, bound_args, context)
        if not decision.allowed:
            return self._handle_denial(decision, raise_on_denied)

        context.record_tool_call()
        result = await func(*args, **kwargs)
        return self._finalize_result(tool_name, result, context, raise_on_denied)

    def _validate_input(
        self,
        tool_name: str,
        args: Mapping[str, Any],
        context: RunContext,
    ) -> Decision | None:
        policy = self.tools.get(tool_name)
        if policy is None or policy.input_model is None:
            return None
        try:
            policy.input_model.model_validate(dict(args))
        except ValidationError as exc:
            decision = Decision(
                allowed=False,
                tool_name=tool_name,
                reason="input_validation_failed",
                message=f"Tool input failed schema validation for {tool_name}",
                run_id=context.run_id,
                metadata={"errors": exc.errors(include_url=False)},
            )
            self._emit_decision(decision)
            return decision
        return None

    def _finalize_result(
        self,
        tool_name: str,
        result: Any,
        context: RunContext,
        raise_on_denied: bool,
    ) -> Any:
        policy = self.tools.get(tool_name)
        if policy is not None and policy.output_model is not None:
            try:
                result = policy.output_model.model_validate(result).model_dump(mode="json")
            except ValidationError as exc:
                decision = Decision(
                    allowed=False,
                    tool_name=tool_name,
                    reason="output_validation_failed",
                    message=f"Tool output failed schema validation for {tool_name}",
                    run_id=context.run_id,
                    metadata={"errors": exc.errors(include_url=False)},
                )
                self._emit_decision(decision)
                return self._handle_denial(decision, raise_on_denied)

        if self._contains_blocked_output(result):
            decision = Decision(
                allowed=False,
                tool_name=tool_name,
                reason="output_blocked",
                message=f"Tool output for {tool_name} matched a blocked output marker",
                run_id=context.run_id,
            )
            self._emit_decision(decision)
            return self._handle_denial(decision, raise_on_denied)

        redacted = self.redactor.redact_value(result)
        self._emit(
            "tool_result_returned",
            context,
            tool_name,
            decision="allowed",
            metadata={"result_type": type(result).__name__},
        )
        return redacted

    def _precheck(
        self,
        tool_name: str,
        args: Mapping[str, Any],
        context: RunContext,
    ) -> Decision:
        policy = self.tools.get(tool_name)
        if policy is None or not policy.allowed:
            return self._deny(tool_name, context, "tool_not_allowed", "Tool is not allowed")

        if self.outputs_require_schema and not policy.has_output_schema:
            return self._deny(
                tool_name,
                context,
                "output_schema_required",
                "Tool is missing a required output schema",
            )

        budget_reason = context.check_before_tool_call()
        if budget_reason is not None:
            return self._deny(
                tool_name,
                context,
                "budget_exceeded",
                "Tool call budget has been exceeded",
                metadata={"budget_reason": budget_reason},
            )

        table_reason = self._table_violation(policy, args)
        if table_reason is not None:
            return self._deny(
                tool_name,
                context,
                table_reason,
                "Tool tried to access a blocked table",
            )

        if self._amount_exceeds_limit(policy, args):
            return self._deny(
                tool_name,
                context,
                "amount_exceeds_limit",
                "Tool amount exceeds configured maximum",
            )

        if self._requires_approval(policy, args):
            return Decision(
                allowed=True,
                tool_name=tool_name,
                reason="approval_required",
                message="Tool call requires approval",
                run_id=context.run_id,
                requires_approval=True,
            )

        return Decision(
            allowed=True,
            tool_name=tool_name,
            reason="allowed",
            message="Tool call allowed",
            run_id=context.run_id,
        )

    def _approve_sync(self, request: ApprovalRequest) -> ApprovalResult:
        if self.approver is None:
            return ApprovalResult(approved=False, reason="no_approver_configured")
        value = self.approver(request)
        if inspect.isawaitable(value):
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                value = asyncio.run(_await_approval_value(value))
            else:
                raise RuntimeError("Use adecide or an async wrapped tool with an async approver")
        return normalize_approval_result(value)

    async def _approve_async(self, request: ApprovalRequest) -> ApprovalResult:
        if self.approver is None:
            return ApprovalResult(approved=False, reason="no_approver_configured")
        value = self.approver(request)
        if inspect.isawaitable(value):
            value = await value
        return normalize_approval_result(value)

    def _decision_from_approval(
        self,
        tool_name: str,
        context: RunContext,
        approval: ApprovalResult,
    ) -> Decision:
        if approval.approved:
            decision = Decision(
                allowed=True,
                tool_name=tool_name,
                reason="approved",
                message="Tool call approved",
                run_id=context.run_id,
                metadata=approval.metadata,
            )
            self._emit("approval_approved", context, tool_name, decision="allowed")
            self._emit_decision(decision)
            return decision

        decision = Decision(
            allowed=False,
            tool_name=tool_name,
            reason="approval_denied",
            message=approval.reason or "Tool call approval was denied",
            run_id=context.run_id,
            metadata=approval.metadata,
        )
        self._emit("approval_denied", context, tool_name, decision="denied", reason=decision.reason)
        self._emit_decision(decision)
        return decision

    def _requires_approval(self, policy: ToolPolicy, args: Mapping[str, Any]) -> bool:
        if not policy.approval_required:
            return False
        if not policy.approval_condition:
            return True
        variables = dict(args)
        recipient = str(args.get("to") or args.get("recipient") or args.get("email") or "")
        variables["recipient_domain"] = (
            recipient.rsplit("@", 1)[-1].lower() if "@" in recipient else ""
        )
        variables["trusted_domains"] = self.trusted_domains
        try:
            return bool(_safe_eval(policy.approval_condition, variables))
        except Exception:
            return True

    def _approval_request(
        self,
        tool_name: str,
        args: Mapping[str, Any],
        context: RunContext,
        decision: Decision,
    ) -> ApprovalRequest:
        policy = self.tools[tool_name]
        return ApprovalRequest(
            run_id=context.run_id,
            tool_name=tool_name,
            args_summary=dict(args),
            risk=policy.risk,
            reason=decision.reason,
            metadata={"scopes": list(policy.scopes)},
        )

    def _table_violation(self, policy: ToolPolicy, args: Mapping[str, Any]) -> str | None:
        if policy.allowed_tables_value is None:
            return None
        allowed = {table.lower() for table in policy.allowed_tables_value}
        tables, parse_failed = _tables_from_args(args)
        if parse_failed or any(table.lower() not in allowed for table in tables):
            return "table_not_allowed"
        return None

    def _amount_exceeds_limit(self, policy: ToolPolicy, args: Mapping[str, Any]) -> bool:
        if policy.max_amount_value is None:
            return False
        for key in ("amount", "amount_usd", "value"):
            if key not in args:
                continue
            try:
                return Decimal(str(args[key])) > policy.max_amount_value
            except (InvalidOperation, ValueError):
                return True
        return False

    def _contains_blocked_output(self, value: Any) -> bool:
        if not self.block_if_contains:
            return False
        text = str(value)
        return any(marker in text for marker in self.block_if_contains)

    def _deny(
        self,
        tool_name: str,
        context: RunContext,
        reason: str,
        message: str,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> Decision:
        return Decision(
            allowed=False,
            tool_name=tool_name,
            reason=reason,
            message=f"{message}: {tool_name}",
            run_id=context.run_id,
            metadata=metadata or {},
        )

    def _emit_decision(self, decision: Decision) -> None:
        self._emit(
            "tool_call_allowed" if decision.allowed else "tool_call_denied",
            RunContext(run_id=decision.run_id or "run_unknown", budget=self.budget),
            decision.tool_name,
            decision="allowed" if decision.allowed else "denied",
            reason=decision.reason,
            metadata=decision.metadata,
        )

    def _emit(
        self,
        event: str,
        context: RunContext,
        tool_name: str,
        *,
        decision: str | None = None,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.auditor.emit(
            AuditEvent(
                run_id=context.run_id,
                event=event,
                tool=tool_name,
                reason=reason,
                decision=decision,
                metadata=self.redactor.redact_value(metadata or {}),
            )
        )

    @staticmethod
    def _bind_arguments(
        func: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            signature = inspect.signature(func)
            bound = signature.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            return dict(bound.arguments)
        except (TypeError, ValueError):
            return {"args": args, "kwargs": dict(kwargs)}

    @staticmethod
    def _normalize_tools(
        tools: Iterable[ToolPolicy] | Mapping[str, ToolPolicy] | None,
    ) -> dict[str, ToolPolicy]:
        if tools is None:
            return {}
        if isinstance(tools, Mapping):
            return dict(tools)
        return {tool.name: tool for tool in tools}

    @staticmethod
    def _handle_denial(decision: Decision, raise_on_denied: bool) -> Decision:
        if raise_on_denied:
            raise BoundaryDenied(decision)
        return decision


_SQL_TABLE_CLAUSE_PATTERN = re.compile(r"\b(?:from|join|update|into)\b", re.I)
_SQL_UNQUOTED_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z_][\w$]*")


def _tables_from_args(args: Mapping[str, Any]) -> tuple[set[str], bool]:
    tables: set[str] = set()
    parse_failed = False
    table = args.get("table")
    if isinstance(table, str):
        tables.add(table)
    table_list = args.get("tables")
    if isinstance(table_list, Iterable) and not isinstance(table_list, (str, bytes)):
        tables.update(str(item) for item in table_list)
    query = args.get("query")
    if isinstance(query, str):
        query_tables, parse_failed = _tables_from_query(query)
        tables.update(query_tables)
    return tables, parse_failed


def _tables_from_query(query: str) -> tuple[set[str], bool]:
    tables: set[str] = set()
    parse_failed = False
    for match in _SQL_TABLE_CLAUSE_PATTERN.finditer(query):
        identifier = _read_sql_identifier(query, match.end())
        if identifier is None:
            parse_failed = True
            continue
        tables.add(identifier)
    return tables, parse_failed


def _read_sql_identifier(query: str, start: int) -> str | None:
    index = start
    length = len(query)
    while index < length and query[index].isspace():
        index += 1
    if index >= length:
        return None

    parts: list[str] = []
    while True:
        part, index = _read_sql_identifier_part(query, index)
        if part is None:
            return None
        parts.append(part)
        while index < length and query[index].isspace():
            index += 1
        if index >= length or query[index] != ".":
            break
        index += 1
        while index < length and query[index].isspace():
            index += 1
    return ".".join(parts)


def _read_sql_identifier_part(query: str, start: int) -> tuple[str | None, int]:
    if start >= len(query):
        return None, start

    opener = query[start]
    if opener == '"':
        return _read_quoted_sql_identifier(query, start, '"', doubled_quotes=True)
    if opener == "`":
        return _read_quoted_sql_identifier(query, start, "`")
    if opener == "[":
        return _read_bracket_sql_identifier(query, start)

    match = _SQL_UNQUOTED_IDENTIFIER_PATTERN.match(query, start)
    if match is None:
        return None, start
    return match.group(0), match.end()


def _read_quoted_sql_identifier(
    query: str,
    start: int,
    quote: str,
    *,
    doubled_quotes: bool = False,
) -> tuple[str | None, int]:
    characters: list[str] = []
    index = start + 1
    while index < len(query):
        character = query[index]
        if character == quote:
            if doubled_quotes and index + 1 < len(query) and query[index + 1] == quote:
                characters.append(quote)
                index += 2
                continue
            identifier = "".join(characters)
            return (identifier or None), index + 1
        characters.append(character)
        index += 1
    return None, len(query)


def _read_bracket_sql_identifier(query: str, start: int) -> tuple[str | None, int]:
    end = query.find("]", start + 1)
    if end == -1:
        return None, len(query)
    identifier = query[start + 1 : end]
    return (identifier or None), end + 1


def _safe_eval(expression: str, variables: Mapping[str, Any]) -> Any:
    tree = ast.parse(expression, mode="eval")
    return _eval_node(tree.body, variables)


async def _await_approval_value(value: Awaitable[bool | ApprovalResult]) -> bool | ApprovalResult:
    return await value


def _eval_node(node: ast.AST, variables: Mapping[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id not in variables:
            raise ValueError(f"Unknown name in policy condition: {node.id}")
        return variables[node.id]
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return [_eval_node(item, variables) for item in node.elts]
    if isinstance(node, ast.BoolOp):
        values = [_eval_node(item, variables) for item in node.values]
        if isinstance(node.op, ast.And):
            return all(values)
        if isinstance(node.op, ast.Or):
            return any(values)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _eval_node(node.operand, variables)
    if isinstance(node, ast.Compare):
        left = _eval_node(node.left, variables)
        for operator, comparator in zip(node.ops, node.comparators, strict=False):
            right = _eval_node(comparator, variables)
            if not _compare(left, operator, right):
                return False
            left = right
        return True
    raise ValueError(f"Unsupported policy condition expression: {expression_dump(node)}")


def _compare(left: Any, operator: ast.cmpop, right: Any) -> bool:
    if isinstance(operator, ast.Eq):
        return left == right
    if isinstance(operator, ast.NotEq):
        return left != right
    if isinstance(operator, ast.In):
        return left in right
    if isinstance(operator, ast.NotIn):
        return left not in right
    if isinstance(operator, ast.Lt):
        return left < right
    if isinstance(operator, ast.LtE):
        return left <= right
    if isinstance(operator, ast.Gt):
        return left > right
    if isinstance(operator, ast.GtE):
        return left >= right
    raise ValueError("Unsupported comparison operator in policy condition")


def expression_dump(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - Python parser fallback
        return node.__class__.__name__
