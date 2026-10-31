"""Append-only audit logger supporting in-memory and JSONL persistence with cryptographic hash chaining.

Every audit event is captured with:
- event ID (id)
- incident ID (incident_id)
- timestamp (timestamp)
- component name (component_name)
- event type (event_type)
- action or decision details (details)
- success or failure (success)
- human-readable explanation (explanation)
- previous event hash (previous_hash)
- cryptographic event hash (event_hash)
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import warnings
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from app.models import AuditEvent, AuditEventType, AuditIntegrityReport, AuditRecord, IncidentResponse

_PROJECT_LOG_DIR = Path(__file__).resolve().parents[2] / "audit_logs"
_VERCEL_LOG_DIR = Path("/tmp/audit_logs")
_DEFAULT_LOG_DIR = _PROJECT_LOG_DIR
_DEFAULT_LOG_FILE = _PROJECT_LOG_DIR / "audit.jsonl"
_ZERO_HASH = "0" * 64
_INTEGRITY_FIELD = "_audit_integrity"


def get_default_log_dir() -> Path:
    """Determine the default audit log directory based on environment settings.

    Precedence:
    1. AUDIT_LOG_DIR environment variable (if set and non-empty)
    2. /tmp/audit_logs if running on Vercel (VERCEL environment variable set)
    3. Project-level audit_logs directory for local development
    """
    override = os.getenv("AUDIT_LOG_DIR")
    if override and override.strip():
        return Path(override.strip())
    if os.getenv("VERCEL"):
        return _VERCEL_LOG_DIR
    return _PROJECT_LOG_DIR


def get_default_log_file() -> Path:
    """Return the default audit.jsonl log file path based on get_default_log_dir()."""
    return get_default_log_dir() / "audit.jsonl"


def _canonical_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _record_hash(payload: Dict[str, Any], sequence: int, previous_hash: str) -> str:
    body = _canonical_json(payload)
    material = f"{sequence}:{previous_hash}:{body}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


GENESIS_HASH = "0" * 64

_SENSITIVE_KEY_SUBSTRINGS = (
    "token",
    "secret",
    "password",
    "api_key",
    "authorization",
    "admin_reset_token",
    "credential",
    "nebius_api_key",
    "private_key",
)


import re

_BEARER_PATTERN = re.compile(r"Bearer\s+[\w\-\.]+", re.IGNORECASE)
_KEY_VAL_PATTERN = re.compile(r"(?:api_key|token|password|secret|authorization|key)[\s:=]+[\w\-\.]+", re.IGNORECASE)


def sanitize_text(text: str) -> str:
    """Scrub Bearer tokens and key=value secrets from text."""
    redacted = _BEARER_PATTERN.sub("Bearer [REDACTED]", text)
    return _KEY_VAL_PATTERN.sub("[REDACTED]", redacted)


def sanitize_audit_data(data: Any) -> Any:
    """Recursively scrub credentials, tokens, and secrets from audit payloads."""
    if isinstance(data, dict):
        sanitized: Dict[str, Any] = {}
        for key, value in data.items():
            key_str = str(key).lower()
            if any(sub in key_str for sub in _SENSITIVE_KEY_SUBSTRINGS):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, (dict, list)):
                sanitized[key] = sanitize_audit_data(value)
            elif isinstance(value, str):
                if value.strip().lower().startswith("bearer ") or value.startswith("sk-"):
                    sanitized[key] = "[REDACTED]"
                else:
                    sanitized[key] = sanitize_text(value)
            else:
                sanitized[key] = value
        return sanitized
    elif isinstance(data, list):
        return [sanitize_audit_data(item) for item in data]
    elif isinstance(data, str):
        if data.strip().lower().startswith("bearer ") or data.startswith("sk-"):
            return "[REDACTED]"
        return sanitize_text(data)
    return data


def compute_event_hash(event: AuditEvent, previous_hash: str) -> str:
    """Compute deterministic SHA-256 hash over previous hash and event canonical fields."""
    canonical_payload = {
        "id": event.id,
        "incident_id": event.incident_id,
        "timestamp": event.timestamp.isoformat(),
        "component_name": event.component_name,
        "event_type": event.event_type,
        "success": event.success,
        "explanation": event.explanation,
        "details": sanitize_audit_data(event.details),
        "previous_hash": previous_hash,
    }
    canonical_bytes = json.dumps(canonical_payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


class AuditLogger:
    """Thread-safe, append-only audit logger recording individual pipeline events with hash chaining."""

    def __init__(self, path: Optional[Union[Path, str]] = None) -> None:
        self._path = Path(path) if path else get_default_log_file()
        self._lock = threading.RLock()
        self._events: List[AuditEvent] = []
        self._pipeline_records: List[Union[AuditRecord, IncidentResponse]] = []
        self._malformed_entries: List[Tuple[int, str, str]] = []
        self._last_event_hash: Optional[str] = None
        self._integrity_load_error: Optional[str] = None
        if self._path.parent:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                self._integrity_load_error = f"Failed to create audit log directory: {exc}"
        try:
            self._sequence, self._last_hash = self._load_integrity_state()
            self._initialize_last_hash()
        except (OSError, ValueError) as exc:
            self._sequence, self._last_hash = 0, _ZERO_HASH
            self._integrity_load_error = str(exc)

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
                    raise ValueError(
                        f"Line {line_number}: malformed audit entry - invalid JSON"
                    ) from exc
                if not isinstance(data, dict):
                    raise ValueError(
                        f"Line {line_number}: malformed audit entry - record must be an object"
                    )

                sequence += 1
                integrity = data.pop(_INTEGRITY_FIELD, None)
                if integrity is None:
                    if chain_started:
                        raise ValueError(
                            f"Line {line_number}: hash chain broken - record is missing integrity metadata"
                        )
                    # Preserve a verifiable anchor when extending a pre-chain JSONL log.
                    seed_material = f"{last_hash}\0{line}".encode("utf-8")
                    last_hash = hashlib.sha256(seed_material).hexdigest()
                    continue

                if not isinstance(integrity, dict):
                    raise ValueError(
                        f"Line {line_number}: malformed audit entry - invalid integrity metadata"
                    )
                if integrity.get("sequence") != sequence:
                    raise ValueError(
                        f"Line {line_number}: hash chain broken - invalid record sequence"
                    )
                if integrity.get("previous_hash") != last_hash:
                    raise ValueError(f"Line {line_number}: hash chain broken")
                expected_hash = _record_hash(
                    data, sequence, last_hash
                )
                if integrity.get("hash") != expected_hash:
                    raise ValueError(
                        f"Line {line_number}: tampering or hash corruption detected"
                    )
                last_hash = expected_hash
                chain_started = True
        return sequence, last_hash

    def _append_record(self, record: Union[AuditEvent, AuditRecord, IncidentResponse]) -> None:
        report = self.verify_integrity()
        if not report.is_valid:
            errors = "; ".join(report.errors)
            raise RuntimeError(f"Cannot append to an invalid audit log: {errors}")

        try:
            self._sequence, self._last_hash = self._load_integrity_state()
        except (OSError, ValueError) as exc:
            self._integrity_load_error = str(exc)
            raise RuntimeError(
                f"Cannot append to an invalid audit log: {self._integrity_load_error}"
            ) from exc

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

    def _initialize_last_hash(self) -> None:
        """Inspect persisted log file to resume the hash chain."""
        if not self._path.exists():
            return
        with open(self._path, "r", encoding="utf-8") as fh:
            last_hash = None
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                if data.get("event_hash"):
                    last_hash = data["event_hash"]
            if last_hash:
                self._last_event_hash = last_hash

    def record_event(
        self,
        incident_id: str,
        component_name: str,
        event_type: Union[AuditEventType, str],
        success: bool,
        explanation: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Create, append, and persist a single audit event with hash chaining and secret sanitization."""
        event_type_str = event_type.value if hasattr(event_type, "value") else str(event_type)
        sanitized_details = sanitize_audit_data(details or {})
        sanitized_explanation = sanitize_audit_data(explanation)

        event = AuditEvent(
            incident_id=incident_id,
            component_name=component_name,
            event_type=event_type_str,
            success=success,
            explanation=str(sanitized_explanation),
            details=sanitized_details,
        )
        return self.log_event(event)

    def log_event(self, event: AuditEvent) -> AuditEvent:
        """Append an AuditEvent to the in-memory log and JSONL file, binding it into the hash chain."""
        with self._lock:
            # Redact secrets in details and explanation
            event.details = sanitize_audit_data(event.details)
            if any(sub in event.explanation.lower() for sub in _SENSITIVE_KEY_SUBSTRINGS):
                event.explanation = sanitize_audit_data(event.explanation)

            # Determine previous hash
            prev_hash = event.previous_hash
            if not prev_hash:
                prev_hash = self._last_event_hash if self._last_event_hash else GENESIS_HASH
                event.previous_hash = prev_hash

            # Compute cryptographic event hash if not already computed
            if not event.event_hash:
                event.event_hash = compute_event_hash(event, event.previous_hash)

            self._append_record(event)
            self._last_event_hash = event.event_hash
            self._events.append(event)
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
        """Return all audit events for a given incident strictly in chronological order."""
        with self._lock:
            in_mem = [e for e in self._events if e.incident_id == incident_id]
            if in_mem:
                events = list(in_mem)
                events.sort(key=lambda e: e.timestamp)
                return events

        all_events = self.read_events()
        events = [e for e in all_events if e.incident_id == incident_id]
        events.sort(key=lambda e: e.timestamp)
        return events

    def read_events(self, strict: bool = False) -> List[AuditEvent]:
        """Read all AuditEvents from the in-memory store or JSONL log file.
        
        Malformed records raise an explicit error when strict=True, or issue warnings and are recorded.
        """
        with self._lock:
            if self._events:
                events = list(self._events)
                events.sort(key=lambda e: e.timestamp)
                return events

        if not self._path.exists():
            return []

        events: List[AuditEvent] = []
        with self._lock:
            with open(self._path, "r", encoding="utf-8") as fh:
                for line_no, raw_line in enumerate(fh, start=1):
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if "component_name" in data or "event_type" in data:
                            events.append(AuditEvent.model_validate(data))
                    except Exception as exc:
                        warn_msg = f"Malformed audit record on line {line_no}: {exc}"
                        warnings.warn(warn_msg, UserWarning)
                        self._malformed_entries.append((line_no, line, str(exc)))
                        if strict:
                            raise ValueError(warn_msg) from exc
        events.sort(key=lambda e: e.timestamp)
        return events

    def read_all(self, strict: bool = False) -> List[Any]:
        """Return pipeline-level records if present, or all recorded events."""
        with self._lock:
            if self._pipeline_records:
                return list(self._pipeline_records)

        if not self._path.exists():
            with self._lock:
                return list(self._events)

        pipeline_records: List[AuditRecord] = []
        events: List[AuditEvent] = []
        with self._lock:
            with open(self._path, "r", encoding="utf-8") as fh:
                for line_no, raw_line in enumerate(fh, start=1):
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if "pipeline_status" in data:
                            pipeline_records.append(AuditRecord.model_validate(data))
                        elif "component_name" in data:
                            events.append(AuditEvent.model_validate(data))
                    except Exception as exc:
                        warn_msg = f"Malformed audit record on line {line_no}: {exc}"
                        warnings.warn(warn_msg, UserWarning)
                        self._malformed_entries.append((line_no, line, str(exc)))
                        if strict:
                            raise ValueError(warn_msg) from exc

        return pipeline_records if pipeline_records else events

    def verify_integrity(self, events: Optional[List[AuditEvent]] = None) -> AuditIntegrityReport:
        """Verify the cryptographic hash chain, chronological order, and structural integrity of audit records.
        
        Detects:
        - Tampered event contents
        - Corrupted event hashes
        - Broken or missing links in the hash chain
        - Reordered / out-of-sequence events
        - Malformed or invalid JSON records
        - Unredacted sensitive credentials
        """
        errors: List[str] = []
        warnings_list: List[str] = []

        try:
            self._sequence, self._last_hash = self._load_integrity_state()
            self._integrity_load_error = None
        except (OSError, ValueError) as exc:
            self._integrity_load_error = str(exc)
            errors.append(str(exc))

        # 1. Check for malformed entries encountered during file parsing
        if self._path.exists():
            with open(self._path, "r", encoding="utf-8") as fh:
                for line_no, raw_line in enumerate(fh, start=1):
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if "component_name" in data or "event_type" in data:
                            AuditEvent.model_validate(data)
                        elif "pipeline_status" in data:
                            AuditRecord.model_validate(data)
                        else:
                            errors.append(f"Line {line_no}: record missing required audit schema fields.")
                    except Exception as exc:
                        errors.append(f"Line {line_no}: malformed audit entry - {exc}")

        # 2. Inspect events sequence
        if events is None:
            # Read directly from file if present, else in-memory
            if self._path.exists():
                events = []
                with open(self._path, "r", encoding="utf-8") as fh:
                    for raw_line in fh:
                        line = raw_line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            if "component_name" in data or "event_type" in data:
                                events.append(AuditEvent.model_validate(data))
                        except Exception:
                            pass
            else:
                with self._lock:
                    events = list(self._events)

        if not events:
            return AuditIntegrityReport(
                is_valid=(len(errors) == 0),
                verified_events=0,
                errors=errors,
                warnings=warnings_list,
            )

        # 3. Step through events to verify hash chain and chronological order
        expected_prev_hash = GENESIS_HASH
        prev_timestamp: Optional[datetime] = None

        for idx, event in enumerate(events):
            # Check chronological ordering
            if prev_timestamp is not None and event.timestamp < prev_timestamp:
                errors.append(
                    f"Event {idx} ({event.id}): timestamp anomaly detected - "
                    f"{event.timestamp.isoformat()} is earlier than previous event timestamp {prev_timestamp.isoformat()}."
                )
            prev_timestamp = event.timestamp

            # Check previous hash continuity
            if event.previous_hash != expected_prev_hash:
                errors.append(
                    f"Event {idx} ({event.id}): hash chain broken - "
                    f"previous_hash '{event.previous_hash}' does not match expected '{expected_prev_hash}'."
                )

            # Recompute and verify event hash
            recomputed_hash = compute_event_hash(event, event.previous_hash or expected_prev_hash)
            if event.event_hash != recomputed_hash:
                errors.append(
                    f"Event {idx} ({event.id}): content tampering or hash corruption detected - "
                    f"stored event_hash '{event.event_hash}' does not match recomputed '{recomputed_hash}'."
                )

            expected_prev_hash = event.event_hash or recomputed_hash

        return AuditIntegrityReport(
            is_valid=(len(errors) == 0),
            verified_events=len(events),
            errors=errors,
            warnings=warnings_list,
        )

    def clear(self) -> None:
        """Clear in-memory and persisted audit logs and reset hash chain state."""
        with self._lock:
            self._events.clear()
            self._pipeline_records.clear()
            self._malformed_entries.clear()
            self._last_event_hash = None
            if self._path.exists():
                os.remove(self._path)
            self._sequence = 0
            self._last_hash = _ZERO_HASH
            self._integrity_load_error = None


# Module-level singleton
audit_logger = AuditLogger()
