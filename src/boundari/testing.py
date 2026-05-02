"""Policy validation and golden-trace testing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from boundari.boundary import Boundary, Decision
from boundari.exceptions import PolicyValidationError
from boundari.yaml import boundary_from_config, load_config


class PolicyTestResult(BaseModel):
    """Result returned by policy test helpers and the CLI."""

    passed: bool
    errors: list[str] = Field(default_factory=list)
    checked_traces: int = 0


def validate_policy_file(path: str | Path) -> PolicyTestResult:
    try:
        config = load_config(path)
    except PolicyValidationError as exc:
        return PolicyTestResult(passed=False, errors=[str(exc)])

    errors = _static_policy_errors(
        boundary_from_config(config),
        config.policy_tests.forbidden_tools,
    )
    return PolicyTestResult(passed=not errors, errors=errors)


def run_policy_tests(
    path: str | Path = "boundari.yaml",
    *,
    traces: list[str | Path] | None = None,
) -> PolicyTestResult:
    policy_path = Path(path)
    try:
        config = load_config(policy_path)
        boundary = boundary_from_config(config)
    except PolicyValidationError as exc:
        return PolicyTestResult(passed=False, errors=[str(exc)])

    errors = _static_policy_errors(boundary, config.policy_tests.forbidden_tools)
    checked_traces = 0
    if traces is None:
        trace_paths = [
            _resolve_policy_trace_path(policy_path, item)
            for item in config.policy_tests.golden_traces
        ]
    else:
        trace_paths = [Path(item) for item in traces]
    for trace_path in trace_paths:
        trace_result = replay_trace(boundary, trace_path)
        checked_traces += trace_result.checked_traces
        errors.extend(trace_result.errors)

    return PolicyTestResult(passed=not errors, errors=errors, checked_traces=checked_traces)


def _resolve_policy_trace_path(policy_path: Path, trace_path: str | Path) -> Path:
    candidate = Path(trace_path)
    if candidate.is_absolute():
        return candidate
    return policy_path.parent / candidate


def replay_trace(boundary: Boundary, trace_path: str | Path) -> PolicyTestResult:
    errors: list[str] = []
    checked = 0
    context = boundary.new_run_context(run_id=f"replay_{Path(trace_path).stem}")
    try:
        lines = Path(trace_path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return PolicyTestResult(passed=False, errors=[str(exc)])

    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        checked += 1
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{trace_path}:{line_number}: invalid JSON: {exc.msg}")
            continue
        decision = _decision_for_event(boundary, event, context)
        expected = event.get("expected_allowed", event.get("allowed"))
        if expected is None and not decision.allowed:
            errors.append(
                f"{trace_path}:{line_number}: {decision.tool_name} denied: {decision.reason}"
            )
        elif expected is not None and bool(expected) != decision.allowed:
            errors.append(
                f"{trace_path}:{line_number}: expected allowed={expected} for "
                f"{decision.tool_name}, got {decision.allowed} ({decision.reason})"
            )
        if decision.allowed:
            context.record_tool_call()

    return PolicyTestResult(passed=not errors, errors=errors, checked_traces=checked)


def _decision_for_event(boundary: Boundary, event: dict[str, Any], context: Any) -> Decision:
    tool_name = str(event.get("tool") or event.get("tool_name") or "")
    args = event.get("args") or event.get("arguments") or {}
    if not isinstance(args, dict):
        args = {"value": args}
    return boundary.decide(tool_name, args, context)


def _static_policy_errors(boundary: Boundary, forbidden_tools: list[str]) -> list[str]:
    errors: list[str] = []
    for tool_name in forbidden_tools:
        policy = boundary.tools.get(tool_name)
        if policy is not None and policy.allowed:
            errors.append(f"Forbidden tool is allowed: {tool_name}")

    if boundary.outputs_require_schema:
        for policy in boundary.tools.values():
            if policy.allowed and not policy.has_output_schema:
                errors.append(f"Allowed tool is missing an output schema: {policy.name}")
    return errors
