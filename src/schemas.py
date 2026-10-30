"""
Shared data contracts for Autonomous IT Reliability & Incident Recovery System.

This module is the shared contract across:
- Nemotron AI diagnosis
- Monitoring and deterministic incident detection
- Recovery orchestration, policy enforcement, and verification
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict


class IncidentSeverity(str, Enum):
    """Agreed severity levels for detected incidents."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class MetricSnapshot(BaseModel):
    """Telemetry metric measurements at a point in time."""
    model_config = ConfigDict(frozen=True)

    latency_p50_ms: float = Field(..., ge=0.0, description="Median latency in milliseconds")
    latency_p99_ms: float = Field(..., ge=0.0, description="99th percentile latency in milliseconds")
    error_rate_pct: float = Field(..., ge=0.0, le=100.0, description="Error rate percentage (0.0 to 100.0)")
    request_rate_rps: float = Field(..., ge=0.0, description="Request rate in requests per second")
    cpu_utilization_pct: float = Field(..., ge=0.0, le=100.0, description="CPU utilization percentage (0.0 to 100.0)")
    memory_utilization_pct: float = Field(..., ge=0.0, le=100.0, description="Memory utilization percentage (0.0 to 100.0)")


class LogEntry(BaseModel):
    """Structured log record for incident context."""
    model_config = ConfigDict(frozen=True)

    timestamp: datetime = Field(..., description="Timestamp of the log entry")
    level: str = Field(..., description="Log level: DEBUG, INFO, WARN, ERROR, FATAL")
    message: str = Field(..., description="Log event description")
    component: Optional[str] = Field(default=None, description="Subsystem or logger component name")
    trace_id: Optional[str] = Field(default=None, description="Distributed tracing identifier")


class EvidenceItem(BaseModel):
    """Specific deterministic threshold or rule violation evidence."""
    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(..., description="Unique detection rule identifier")
    metric_name: str = Field(..., description="Name of the anomalous metric or state")
    threshold_value: float = Field(..., description="Configured threshold value that was breached")
    observed_value: float = Field(..., description="Actual observed metric value")
    explanation: str = Field(..., description="Deterministic explanation of the violation")


class DeploymentEvent(BaseModel):
    """Represents a recent software rollout or deployment event."""
    model_config = ConfigDict(frozen=True)

    deployment_id: str = Field(..., description="Unique deployment identifier")
    service: str = Field(..., description="Target service being deployed")
    version: str = Field(..., description="Deployed semantic release version")
    deployed_at: datetime = Field(..., description="Timestamp when deployment took place")
    status: str = Field(default="COMPLETED", description="Deployment status, e.g. COMPLETED, FAILED")


class IncidentPayload(BaseModel):
    """Complete structured incident payload emitted by the detection engine."""
    model_config = ConfigDict(frozen=True)

    incident_id: str = Field(..., description="Unique, stable incident identifier")
    service: str = Field(..., description="Name of the affected service")
    timestamp: datetime = Field(..., description="Detection timestamp")
    severity: IncidentSeverity = Field(..., description="Classified incident severity")
    summary: str = Field(..., description="Concise human-readable incident summary")
    metrics: MetricSnapshot = Field(..., description="Observed metric snapshot at detection")
    logs: List[LogEntry] = Field(default_factory=list, description="Relevant contextual log entries")
    evidence: List[EvidenceItem] = Field(default_factory=list, description="List of breached rules and evidence")
    recent_deployment: Optional[DeploymentEvent] = Field(
        default=None, description="Recent deployment event associated with this incident, if any"
    )


# Convenient alias for team members importing Incident directly
Incident = IncidentPayload
