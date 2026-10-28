"""Append-only audit logger supporting in-memory and JSONL persistence.

Every audit event is captured with:
- event ID (id)
- incident ID (incident_id)
- timestamp (timestamp)
- component name (component_name)
- event type (event_type)
- action or decision details (details)
- success or failure (success)
- human-readable explanation (explanation)
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from app.models import AuditEvent, AuditEventType, AuditRecord, IncidentResponse

_DEFAULT_LOG_DIR = Path("audit_logs")
_DEFAULT_LOG_FILE = _DEFAULT_LOG_DIR / "audit.jsonl"


class AuditLogger:
    """Thread-safe, append-only audit logger recording individual pipeline events."""

    def __init__(self, path: Optional[Union[Path, str]] = None) -> None:
        self._path = Path(path) if path else _DEFAULT_LOG_FILE
        self._lock = threading.Lock()
        self._events: List[AuditEvent] = []
        self._pipeline_records: List[Union[AuditRecord, IncidentResponse]] = []
        if self._path.parent:
            self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def record_event(
        self,
        incident_id: str,
        component_name: str,
        event_type: Union[AuditEventType, str],
        success: bool,
        explanation: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Create, append, and persist a single audit event."""
        event_type_str = event_type.value if hasattr(event_type, "value") else str(event_type)
        event = AuditEvent(
            incident_id=incident_id,
            component_name=component_name,
            event_type=event_type_str,
            success=success,
            explanation=explanation,
            details=details or {},
        )
        return self.log_event(event)

    def log_event(self, event: AuditEvent) -> AuditEvent:
        """Append an AuditEvent to the in-memory log and JSONL file."""
        with self._lock:
            self._events.append(event)
            line = event.model_dump_json() + "\n"
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line)
        return event

    def log_pipeline_record(self, record: Union[AuditRecord, IncidentResponse]) -> None:
        """Record an end-to-end incident response / audit record."""
        with self._lock:
            self._pipeline_records.append(record)

    def log(self, record: Union[AuditEvent, AuditRecord, IncidentResponse]) -> None:
        """Backwards compatibility for logging AuditEvent or legacy AuditRecord."""
        if isinstance(record, AuditEvent):
            self.log_event(record)
            return

        with self._lock:
            self._pipeline_records.append(record)
            line = record.model_dump_json() + "\n"
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line)

    def get_events_for_incident(self, incident_id: str) -> List[AuditEvent]:
        """Return all audit events for a given incident in the order they were recorded."""
        with self._lock:
            in_mem = [e for e in self._events if e.incident_id == incident_id]
            if in_mem:
                return list(in_mem)

        all_events = self.read_events()
        return [e for e in all_events if e.incident_id == incident_id]

    def read_events(self) -> List[AuditEvent]:
        """Read all AuditEvents from the in-memory store or JSONL log file."""
        with self._lock:
            if self._events:
                return list(self._events)

        if not self._path.exists():
            return []

        events: List[AuditEvent] = []
        with self._lock:
            with open(self._path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if "component_name" in data or "event_type" in data:
                            events.append(AuditEvent.model_validate(data))
                    except Exception:
                        pass
        return events

    def read_all(self) -> List[Any]:
        """Return pipeline-level records if present, or all recorded events."""
        with self._lock:
            if self._pipeline_records:
                return list(self._pipeline_records)

        # Fallback to file
        if not self._path.exists():
            with self._lock:
                return list(self._events)

        records: List[Any] = []
        with self._lock:
            with open(self._path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if "pipeline_status" in data:
                            records.append(AuditRecord.model_validate(data))
                        elif "component_name" in data:
                            records.append(AuditEvent.model_validate(data))
                    except Exception:
                        pass
        return records

    def clear(self) -> None:
        """Clear both in-memory and persisted audit logs."""
        with self._lock:
            self._events.clear()
            self._pipeline_records.clear()
            if self._path.exists():
                os.remove(self._path)


# Module-level singleton
audit_logger = AuditLogger()
