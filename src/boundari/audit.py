"""Audit event models and sinks."""

from __future__ import annotations

import json
from collections.abc import MutableSequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from boundari.redact import Redactor


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class AuditEvent(BaseModel):
    """A structured policy decision event."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    event: str
    timestamp: str = Field(default_factory=utc_timestamp)
    tool: str | None = None
    reason: str | None = None
    decision: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None:
        """Store or forward an audit event."""


class MemoryAuditLog:
    """In-memory audit sink useful for tests and embedded apps."""

    def __init__(self, events: MutableSequence[AuditEvent] | None = None) -> None:
        self.events: MutableSequence[AuditEvent] = events if events is not None else []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


class JSONLAuditLog:
    """Append audit events to a local JSONL file."""

    def __init__(
        self,
        path: str | Path = "boundari_audit.jsonl",
        *,
        redactor: Redactor | None = None,
        store_raw: bool = False,
    ) -> None:
        self.path = Path(path)
        self.redactor = redactor or Redactor()
        self.store_raw = store_raw

    def emit(self, event: AuditEvent) -> None:
        payload = event.model_dump(mode="json")
        if not self.store_raw:
            payload["metadata"] = self.redactor.redact_value(payload.get("metadata", {}))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
