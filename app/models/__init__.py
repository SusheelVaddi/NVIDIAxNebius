"""Pydantic data models for the Incident Recovery System.

All shared models live here so they remain **independent of the API
framework**. Every model uses explicit fields with types, validation
constraints, stable identifiers, and UTC timestamps.

Models
------
- ``Incident``           – a detected or injected IT incident
- ``SystemState``        – snapshot of a simulated service's health metrics
- ``RecoveryAction``     – describes *what* recovery will be attempted
- ``PolicyDecision``     – the decision (approve / reject / manual-review) + rationale
- ``RecoveryResult``     – outcome of executing a recovery action
- ``VerificationResult`` – outcome of the independent post-recovery check
- ``AuditEvent``         – immutable audit-trail entry for one pipeline step
- ``IncidentResponse``   – end-to-end response bundling every pipeline stage
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, ClassVar, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator, model_validator


# ═══════════════════════════════════════════════════════════════════════════
# Enumerations
# ═══════════════════════════════════════════════════════════════════════════

class ServiceStatus(str, enum.Enum):
    """Possible health states of a simulated service."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DOWN = "down"


class IncidentSeverity(str, enum.Enum):
    """How severe the detected incident is."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, enum.Enum):
    """Lifecycle status of an incident as it flows through the pipeline."""
    DETECTED = "detected"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    VERIFIED = "verified"
    FAILED = "failed"


class DecisionVerdict(str, enum.Enum):
    """Outcome of the policy engine evaluation."""
    APPROVE = "approve"
    DENY = "deny"
    MANUAL_REVIEW = "manual_review"


class RecoveryActionType(str, enum.Enum):
    """Available simulated recovery actions."""
    RESTART_SERVICE = "restart_service"
    CLEAR_QUEUE = "clear_queue"
    SCALE_SERVICE = "scale_service"
    SCALE_UP = "scale_up"
    FAILOVER = "failover"


class VerificationOutcome(str, enum.Enum):
    """Result of the independent post-recovery check."""
    PASS = "pass"
    FAIL = "fail"


class AuditEventType(str, enum.Enum):
    """Classifies what kind of audit event was recorded."""
    INCIDENT_RECEIVED = "incident_received"
    INCIDENT_DETECTED = "incident_detected"
    STATE_LOADED = "state_loaded"
    ACTION_PROPOSED = "action_proposed"
    ACTION_RECOMMENDED = "action_recommended"
    POLICY_EVALUATED = "policy_evaluated"
    RECOVERY_EXECUTED = "recovery_executed"
    RECOVERY_SKIPPED = "recovery_skipped"
    VERIFICATION_COMPLETED = "verification_completed"
    PIPELINE_COMPLETED = "pipeline_completed"


class PipelineStatus(str, enum.Enum):
    """Overall outcome of one run of the recovery pipeline."""
    SUCCESS = "success"
    RECOVERY_DENIED = "recovery_denied"
    RECOVERY_FAILED = "recovery_failed"
    VERIFICATION_FAILED = "verification_failed"


# ═══════════════════════════════════════════════════════════════════════════
# Helper – deterministic 12-char hex IDs
# ═══════════════════════════════════════════════════════════════════════════

def _new_id() -> str:
    """Generate a stable, URL-safe 12-character hex identifier."""
    return uuid.uuid4().hex[:12]


def _utcnow() -> datetime:
    """Return the current UTC time (timezone-aware)."""
    return datetime.now(timezone.utc)


# ═══════════════════════════════════════════════════════════════════════════
# Core models
# ═══════════════════════════════════════════════════════════════════════════

class Incident(BaseModel):
    """A detected or injected IT incident."""

    id: str = Field(default_factory=_new_id, min_length=1, max_length=64,
                    description="Stable unique identifier")
    service_name: str = Field(..., min_length=1, max_length=128,
                              description="Name of the affected service")
    severity: IncidentSeverity
    title: str = Field(default="", max_length=256,
                       description="Short human-readable summary")
    description: str = Field(default="",
                             description="Detailed description of the incident")
    status: IncidentStatus = Field(default=IncidentStatus.DETECTED,
                                   description="Current lifecycle status")
    detected_at: datetime = Field(default_factory=_utcnow,
                                  description="UTC timestamp of detection")
    resolved_at: Optional[datetime] = Field(default=None,
                                            description="UTC timestamp when resolved (if applicable)")

    @model_validator(mode="before")
    @classmethod
    def _default_title_if_missing(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if not data.get("title") and data.get("service_name") and data.get("severity"):
                sev = data["severity"]
                sev_val = sev.value if hasattr(sev, "value") else str(sev)
                data["title"] = f"{sev_val.upper()} incident on {data['service_name']}"
            elif not data.get("title"):
                data["title"] = "Incident"
        return data

    @field_validator("service_name")
    @classmethod
    def _service_name_no_whitespace(cls, v: str) -> str:
        if " " in v:
            raise ValueError("service_name must not contain spaces")
        return v


class SystemState(BaseModel):
    """Snapshot of a simulated service's health metrics."""

    service_name: str = Field(..., min_length=1, max_length=128)
    status: ServiceStatus
    cpu_percent: float = Field(ge=0.0, le=100.0,
                               description="CPU utilisation 0–100 %")
    memory_percent: float = Field(ge=0.0, le=100.0,
                                  description="Memory utilisation 0–100 %")
    error_rate: float = Field(ge=0.0, le=1.0,
                              description="Error ratio 0.0 – 1.0")
    request_latency_ms: float = Field(default=0.0, ge=0.0,
                                      description="P99 latency in ms")
    queue_size: int = Field(default=0, ge=0,
                            description="Simulated queue backlog size")
    instances: int = Field(default=1, ge=1,
                           description="Active replica count")
    last_updated: datetime = Field(default_factory=_utcnow,
                                   description="When this snapshot was taken")

    @model_validator(mode="before")
    @classmethod
    def _handle_name_alias(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "service_name" not in data and "name" in data:
                data["service_name"] = data["name"]
        return data

    @property
    def name(self) -> str:
        return self.service_name


class RecoveryAction(BaseModel):
    """Describes *what* recovery action will be attempted."""

    id: str = Field(default_factory=_new_id, min_length=1, max_length=64)
    incident_id: str = Field(..., min_length=1, max_length=64,
                             description="The incident this action targets")
    action_type: RecoveryActionType
    target_service: str = Field(..., min_length=1, max_length=128)
    parameters: Dict[str, Any] = Field(default_factory=dict,
                                       description="Action-specific key-value parameters")
    safe_for_simulation: bool = Field(default=True,
                                      description="Whether the action is safe for simulation")
    risk_level: int = Field(default=1, ge=1, le=10,
                            description="Risk assessment (1 = low, 10 = extreme)")
    retry_count: int = Field(default=0, ge=0,
                             description="Number of retries already attempted for this recovery")
    created_at: datetime = Field(default_factory=_utcnow)


class PolicyDecision(BaseModel):
    """The outcome of the deterministic policy gate evaluation."""

    id: str = Field(default_factory=_new_id, min_length=1, max_length=64)
    incident_id: str = Field(default="", max_length=64)
    verdict: DecisionVerdict = Field(default=DecisionVerdict.DENY)
    reason: str = Field(default="", max_length=1024,
                        description="Human-readable rationale for the decision")
    decided_by: str = Field(default="DeterministicPolicyGate",
                            description="Component that made the decision")
    decided_at: datetime = Field(default_factory=_utcnow)

    # ClassVar shortcuts to DecisionVerdict for enum-like access
    APPROVE: ClassVar[DecisionVerdict] = DecisionVerdict.APPROVE
    DENY: ClassVar[DecisionVerdict] = DecisionVerdict.DENY
    MANUAL_REVIEW: ClassVar[DecisionVerdict] = DecisionVerdict.MANUAL_REVIEW

    @model_validator(mode="before")
    @classmethod
    def _coerce_verdict(cls, data: Any) -> Any:
        if isinstance(data, DecisionVerdict):
            return {"verdict": data, "reason": data.value}
        if isinstance(data, str) and data in ("approve", "deny", "manual_review"):
            return {"verdict": DecisionVerdict(data), "reason": data}
        return data

    @property
    def is_approved(self) -> bool:
        return self.verdict == DecisionVerdict.APPROVE

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, DecisionVerdict):
            return self.verdict == other
        if isinstance(other, str):
            return self.verdict.value == other
        if isinstance(other, PolicyDecision):
            return self.verdict == other.verdict
        return False


class RecoveryResult(BaseModel):
    """Outcome of executing a recovery action."""

    id: str = Field(default_factory=_new_id, min_length=1, max_length=64)
    action_id: str = Field(default_factory=_new_id, min_length=1, max_length=64,
                           description="ID of the RecoveryAction that was executed")
    incident_id: str = Field(default="", max_length=64)
    action_type: RecoveryActionType = Field(default=RecoveryActionType.RESTART_SERVICE)
    target_service: str = Field(default="", max_length=128)
    success: bool
    message: str = Field(default="", max_length=1024)
    started_at: datetime = Field(default_factory=_utcnow)
    completed_at: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="before")
    @classmethod
    def _backwards_compatibility(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "action" in data and "action_type" not in data:
                data["action_type"] = data["action"]
            if "service_name" in data and "target_service" not in data:
                data["target_service"] = data["service_name"]
            if "action_id" not in data:
                data["action_id"] = _new_id()
            if "incident_id" not in data:
                data["incident_id"] = "unknown"
        return data

    @property
    def action(self) -> RecoveryActionType:
        return self.action_type

    @property
    def service_name(self) -> str:
        return self.target_service

    def model_dump(self, *args, **kwargs) -> Dict[str, Any]:
        d = super().model_dump(*args, **kwargs)
        d["action"] = self.action_type.value if hasattr(self.action_type, "value") else str(self.action_type)
        d["service_name"] = self.target_service
        return d


class VerificationResult(BaseModel):
    """Outcome of the independent post-recovery health check."""

    id: str = Field(default_factory=_new_id, min_length=1, max_length=64)
    incident_id: str = Field(default="", max_length=64)
    service_name: str = Field(..., min_length=1, max_length=128)
    outcome: VerificationOutcome
    details: str = Field(default="", max_length=1024)
    checks_performed: List[str] = Field(
        default_factory=list,
        description="List of checks that were run",
    )
    checked_at: datetime = Field(default_factory=_utcnow)


class AuditEvent(BaseModel):
    """Immutable audit-trail entry for one pipeline step."""

    id: str = Field(default_factory=_new_id, min_length=1, max_length=64,
                    description="Event ID")
    incident_id: str = Field(..., min_length=1, max_length=64,
                             description="Incident ID")
    timestamp: datetime = Field(default_factory=_utcnow,
                                description="Timestamp")
    component_name: str = Field(default="system", max_length=128,
                                description="Component name")
    event_type: str = Field(..., description="Event type")
    details: Dict[str, Any] = Field(default_factory=dict,
                                    description="Action or decision details")
    success: bool = Field(default=True,
                          description="Success or failure")
    explanation: str = Field(default="", max_length=1024,
                             description="Human-readable explanation")

    @model_validator(mode="before")
    @classmethod
    def _backwards_compatibility(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "actor" in data and "component_name" not in data:
                data["component_name"] = data["actor"]
            if "summary" in data and "explanation" not in data:
                data["explanation"] = data["summary"]
            if hasattr(data.get("event_type"), "value"):
                data["event_type"] = data["event_type"].value
        return data

    @property
    def actor(self) -> str:
        return self.component_name

    @property
    def summary(self) -> str:
        return self.explanation


class IncidentResponse(BaseModel):
    """End-to-end response returned after the full pipeline completes."""

    incident: Incident
    system_state_before: Optional[SystemState] = None
    policy_decision: Optional[Union[PolicyDecision, DecisionVerdict]] = None
    recovery_action: Optional[RecoveryAction] = None
    recovery_result: Optional[RecoveryResult] = None
    verification_result: Optional[VerificationResult] = None
    system_state_after: Optional[SystemState] = None
    audit_events: List[AuditEvent] = Field(default_factory=list)
    pipeline_status: PipelineStatus
    started_at: datetime = Field(default_factory=_utcnow)
    completed_at: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="before")
    @classmethod
    def _handle_legacy_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "recovery" in data and "recovery_result" not in data:
                data["recovery_result"] = data["recovery"]
            if "verification" in data and "verification_result" not in data:
                data["verification_result"] = data["verification"]
            if isinstance(data.get("policy_decision"), DecisionVerdict):
                inc_id = (
                    data.get("incident", {}).get("id", "")
                    if isinstance(data.get("incident"), dict)
                    else getattr(data.get("incident"), "id", "")
                )
                data["policy_decision"] = PolicyDecision(
                    incident_id=inc_id,
                    verdict=data["policy_decision"],
                    reason=data["policy_decision"].value,
                )
        return data

    @property
    def recovery(self) -> Optional[RecoveryResult]:
        return self.recovery_result

    @property
    def verification(self) -> Optional[VerificationResult]:
        return self.verification_result


# ═══════════════════════════════════════════════════════════════════════════
# Backwards-compatible aliases
# ═══════════════════════════════════════════════════════════════════════════

ServiceInfo = SystemState


class AuditRecord(IncidentResponse):
    """Backwards-compatible alias for earlier tests and routes expecting AuditRecord."""
    pass


class RecoveryRequest(BaseModel):
    """Request payload for POST /incidents/recover."""

    incident_id: str = Field(..., min_length=1, max_length=64, description="Incident ID")
    incident_type: str = Field(..., min_length=1, max_length=128, description="Incident type / classification")
    affected_service: str = Field(..., min_length=1, max_length=128, description="Affected service name")
    proposed_recovery_action: RecoveryAction = Field(..., description="Proposed recovery action")
    current_system_state: SystemState = Field(..., description="Current simulated system state")

    @model_validator(mode="before")
    @classmethod
    def _support_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "service_name" in data and "affected_service" not in data:
                data["affected_service"] = data["service_name"]
            if "recovery_action" in data and "proposed_recovery_action" not in data:
                data["proposed_recovery_action"] = data["recovery_action"]
            if "system_state" in data and "current_system_state" not in data:
                data["current_system_state"] = data["system_state"]
        return data


class RecoveryResponse(BaseModel):
    """Response payload returned by POST /incidents/recover."""

    incident_id: str = Field(..., description="Incident ID")
    policy_decision: Optional[PolicyDecision] = Field(default=None, description="Policy decision")
    recovery_result: Optional[RecoveryResult] = Field(default=None, description="Recovery result")
    verification_result: Optional[VerificationResult] = Field(default=None, description="Verification result")
    final_status: PipelineStatus = Field(..., description="Final pipeline status")
    audit_events: List[AuditEvent] = Field(default_factory=list, description="Audit events for this recovery")

    @model_validator(mode="before")
    @classmethod
    def _support_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "pipeline_status" in data and "final_status" not in data:
                data["final_status"] = data["pipeline_status"]
            if "status" in data and "final_status" not in data:
                data["final_status"] = data["status"]
        return data

    @property
    def status(self) -> PipelineStatus:
        return self.final_status

