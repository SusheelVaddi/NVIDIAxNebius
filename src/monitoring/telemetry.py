"""
Telemetry data models representing simulated infrastructure telemetry.

Reuses shared models from src.schemas for MetricSnapshot, LogEntry, and
DeploymentEvent to avoid duplicate schema definitions across modules.
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict

from src.schemas import MetricSnapshot, LogEntry, DeploymentEvent


class TelemetryWindow(BaseModel):
    """Encapsulates all metrics, logs, events, and health status for a monitoring window."""
    model_config = ConfigDict(frozen=True)

    service: str = Field(..., description="Monitored service identifier")
    timestamp: datetime = Field(..., description="Timestamp of telemetry collection window")
    metrics: MetricSnapshot = Field(..., description="Aggregated metric snapshot for this window")
    logs: List[LogEntry] = Field(default_factory=list, description="Structured logs collected during window")
    recent_deployment: Optional[DeploymentEvent] = Field(default=None, description="Recent deployment event, if any")
    service_status: str = Field(default="HEALTHY", description="Reported health status: HEALTHY, DEGRADED, UNHEALTHY")
