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

import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from app.models import AuditEvent, AuditEventType, AuditRecord, IncidentResponse

_DEFAULT_LOG_DIR = Path("audit_logs")
_DEFAULT_LOG_FILE = _DEFAULT_LOG_DIR / "audit.jsonl"
_ZERO_HASH = "0" * 64
_INTEGRITY_FIELD = "_audit_integrity"


def _canonical_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _record_hash(payload: Dict[str, Any], sequence: int, previous_hash: str) -> str:
    body = _canonical_json(payload)
    material = f"{sequence}:{previous_hash}:{body}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


class AuditLogger:
    """Thread-safe append-only audit logger with a verifiable JSONL hash chain."""

    def __init__(self, path: Optional[Union[Path, str]] = None) -> None:
        self._path = Path(path) if path else _DEFAULT_LOG_FILE
        self._lock = threading.Lock()
        self._events: List[AuditEvent] = []
        self._pipeline_records: List[Union[AuditRecord, IncidentResponse]] = []
        if self._path.parent:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self._sequence, self._last_hash = self._load_integrity_state()

    def _load_integrity_state(self) -> tuple[int, str]:
        if not self._path.exists():
            return 0, _ZERO_HASH

        sequence = 0
        last_hash = _ZERO_HASH
        chain_started = False
        with open(self._path, "r", encoding="utf-8") as fh:
            for line_number, raw_line in enumerate(fh, start=1):
                line = raw_line.rstrip("\r\n")
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid audit JSON on line {line_number}") from exc
                if not isinstance(data, dict):
                    raise ValueError(f"Invalid audit record on line {line_number}")

                sequence += 1
                integrity = data.pop(_INTEGRITY_FIELD, None)
                if integrity is None:
                    if chain_started:
                        raise ValueError(
                            f"Unchained audit record after hash chain on line {line_number}"
                        )
                    # Preserve a verifiable anchor when extending a pre-chain JSONL log.
                    seed_material = f"{last_hash}\0{line}".encode("utf-8")
                    last_hash = hashlib.sha256(seed_material).hexdigest()
                    continue

                if not isinstance(integrity, dict):
                    raise ValueError(f"Invalid audit integrity metadata on line {line_number}")
                if integrity.get("sequence") != sequence:
                    raise ValueError(f"Invalid audit sequence on line {line_number}")
                if integrity.get("previous_hash") != last_hash:
                    raise ValueError(f"Broken audit hash chain on line {line_number}")
                expected_hash = _record_hash(
                    data, sequence, last_hash
                )
                if integrity.get("hash") != expected_hash:
                    raise ValueError(f"Audit record hash mismatch on line {line_number}")
                last_hash = expected_hash
                chain_started = True
        return sequence, last_hash

    def _append_record(self, record: Union[AuditEvent, AuditRecord, IncidentResponse]) -> None:
        payload = json.loads(record.model_dump_json())
        sequence = self._sequence + 1
        digest = _record_hash(payload, sequence, self._last_hash)
        payload[_INTEGRITY_FIELD] = {
            "sequence": sequence,
            "previous_hash": self._last_hash,
            "hash": digest,
        }
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n")
        self._sequence = sequence
        self._last_hash = digest

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
            self._append_record(event)
        return event

    def log_pipeline_record(self, record: Union[AuditRecord, IncidentResponse]) -> None:
        """Record an end-to-end incident response / audit record."""
        with self._lock:
            self._pipeline_records.append(record)
            self._append_record(record)

    def log(self, record: Union[AuditEvent, AuditRecord, IncidentResponse]) -> None:
        """Backwards compatibility for logging AuditEvent or legacy AuditRecord."""
        if isinstance(record, AuditEvent):
            self.log_event(record)
            return

        with self._lock:
            self._pipeline_records.append(record)
            self._append_record(record)

    def verify_integrity(self) -> bool:
        """Return whether persisted audit entries form a valid hash chain."""
        with self._lock:
            try:
                self._load_integrity_state()
            except (OSError, ValueError):
                return False
            if not self._path.exists() or self._path.stat().st_size == 0:
                return True
            with open(self._path, "r", encoding="utf-8") as fh:
                return any(
                    _INTEGRITY_FIELD in json.loads(line)
                    for line in fh
                    if line.strip()
                )

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

        pipeline_records: List[AuditRecord] = []
        events: List[AuditEvent] = []
        with self._lock:
            with open(self._path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if "pipeline_status" in data:
                            pipeline_records.append(AuditRecord.model_validate(data))
                        elif "component_name" in data:
                            events.append(AuditEvent.model_validate(data))
                    except Exception:
                        pass
        return pipeline_records if pipeline_records else events

    def clear(self) -> None:
        """Clear both in-memory and persisted audit logs."""
        with self._lock:
            self._events.clear()
            self._pipeline_records.clear()
            if self._path.exists():
                os.remove(self._path)
            self._sequence = 0
            self._last_hash = _ZERO_HASH


# Module-level singleton
audit_logger = AuditLogger()
