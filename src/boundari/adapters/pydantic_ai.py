"""Pydantic AI adapter helpers.

This module intentionally avoids importing pydantic-ai at import time so the core
package stays lightweight unless the optional extra is installed.
"""

from __future__ import annotations

from typing import Any

from boundari.boundary import Boundary, WrappedAgent


def wrap_agent(agent: Any, *, boundary: Boundary) -> WrappedAgent:
    """Return a lightweight proxy carrying a Boundary next to a Pydantic AI agent."""

    return boundary.wrap(agent)
