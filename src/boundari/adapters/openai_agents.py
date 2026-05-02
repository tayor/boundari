"""OpenAI Agents SDK adapter helpers."""

from __future__ import annotations

from typing import Any

from boundari.boundary import Boundary, WrappedAgent


def wrap_agent(agent: Any, *, boundary: Boundary) -> WrappedAgent:
    """Return a lightweight proxy carrying a Boundary next to an OpenAI agent."""

    return boundary.wrap(agent)
