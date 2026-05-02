"""Exception types raised by Boundari."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from boundari.boundary import Decision


class BoundariError(Exception):
    """Base exception for Boundari."""


class PolicyValidationError(BoundariError):
    """Raised when a policy file or policy object is invalid."""


class PolicyViolation(BoundariError):
    """Raised when a tool call violates a boundary contract."""


class BudgetExceeded(PolicyViolation):
    """Raised when a run exceeds a configured budget."""


class ApprovalDenied(PolicyViolation):
    """Raised when a required approval is denied."""


class BoundaryDenied(PolicyViolation):
    """Raised when a denied decision is configured to raise."""

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(decision.message)
