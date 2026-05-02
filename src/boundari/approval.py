"""Human approval request helpers."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ApprovalRequest(BaseModel):
    """Information presented to a human or approval service."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    tool_name: str
    args_summary: dict[str, Any]
    risk: str
    reason: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class ApprovalResult(BaseModel):
    """Approval callback result."""

    approved: bool
    reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


ApprovalValue = bool | ApprovalResult
ApprovalMaybeAwaitable = ApprovalValue | Awaitable[ApprovalValue]
Approver = Callable[[ApprovalRequest], ApprovalMaybeAwaitable]


def normalize_approval_result(value: ApprovalValue) -> ApprovalResult:
    if isinstance(value, ApprovalResult):
        return value
    return ApprovalResult(approved=bool(value))


def console_approver(request: ApprovalRequest) -> ApprovalResult:
    """Prompt in the console for local approval demos."""

    print(f"Boundari approval required for {request.tool_name}")
    print(f"Reason: {request.reason}")
    print(f"Risk: {request.risk}")
    print(f"Args: {request.args_summary}")
    answer = input("Approve? [y/N] ").strip().lower()
    return ApprovalResult(approved=answer in {"y", "yes"})


def fastapi_approval_router(approver: Approver) -> Any:
    """Create a small FastAPI router for approval callbacks.

    FastAPI is optional and imported only when this helper is used.
    """

    try:
        from fastapi import APIRouter  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - optional dependency path
        raise RuntimeError("Install boundari[web] to use fastapi_approval_router") from exc

    router = APIRouter()

    @router.post("/boundari/approve")
    async def approve(request: ApprovalRequest) -> ApprovalResult:
        value = approver(request)
        if inspect.isawaitable(value):
            value = await value
        return normalize_approval_result(value)

    return router
