"""Orchestrator for the Autonomous IT Reliability & Incident Recovery System.

Coordinates the end-to-end recovery lifecycle:
1. Receive incident.
2. Load system state.
3. Ask RecoveryPlanner for a proposed action.
4. Record the recommendation in the audit log.
5. Send the action to DeterministicPolicyGate.
6. Execute only approved actions.
7. Independently verify the resulting state.
8. Record every result in the audit log.
9. Return IncidentResponse.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional

from app.audit import AuditLogger, audit_logger as default_audit_logger
from app.diagnosis import (
    DiagnosisError,
    DiagnosisResult,
    DeterministicIncidentDiagnoser,
    IncidentDiagnoser,
    NemotronAPIError,
    NemotronAuthError,
    NemotronClient,
    NemotronClientError,
    NemotronConnectionError,
    NemotronResponseError,
    NemotronTimeoutError,
)
from app.infrastructure import InfrastructureSimulator, infra as default_infra
from app.models import (
    AuditEventType,
    Incident,
    IncidentResponse,
    IncidentStatus,
    PipelineStatus,
    RecoveryAction,
    RecoveryResult,
    VerificationOutcome,
    VerificationResult,
)
from app.policy import DeterministicPolicyGate
from app.recovery import (
    DeterministicMockPlanner,
    NebiusPlanner,
    RecoveryPlanner,
    SimulatedRecoveryExecutor,
)
from app.verification import IndependentVerifier
from src.schemas import IncidentPayload as MonitoringIncidentPayload


class Orchestrator:
    """Coordinates incident reception, policy gating, recovery, verification, and audit trail."""

    def __init__(
        self,
        infra: Optional[InfrastructureSimulator] = None,
        policy_gate: Optional[DeterministicPolicyGate] = None,
        executor: Optional[SimulatedRecoveryExecutor] = None,
        verifier: Optional[IndependentVerifier] = None,
        audit_logger: Optional[AuditLogger] = None,
        planner: Optional[RecoveryPlanner] = None,
        diagnoser: Optional[IncidentDiagnoser] = None,
    ) -> None:
        self.infra = infra if infra is not None else default_infra
        self.policy_gate = policy_gate if policy_gate is not None else DeterministicPolicyGate()
        self.executor = executor if executor is not None else SimulatedRecoveryExecutor()
        self.verifier = verifier if verifier is not None else IndependentVerifier()
        self.audit_logger = audit_logger if audit_logger is not None else default_audit_logger
        api_key = os.getenv("NEBIUS_TOKEN_FACTORY_API_KEY", "").strip()
        if planner is not None:
            self.planner = planner
        elif api_key:
            self.planner = NebiusPlanner(api_key=api_key)
        else:
            self.planner = DeterministicMockPlanner()
        if diagnoser is not None:
            self.diagnoser = diagnoser
        elif os.getenv("ENABLE_AI_DIAGNOSIS", "").strip().lower() in {
            "1", "true", "yes", "t", "on"
        }:
            self.diagnoser = IncidentDiagnoser(client=NemotronClient())
        else:
            self.diagnoser = None

    @staticmethod
    def from_monitoring_payload(payload: MonitoringIncidentPayload, *, infra=None, audit_logger=None, **kwargs) -> "Orchestrator":
        """Create an orchestrator configured to consume a monitoring IncidentPayload."""
        incident = Incident.from_monitoring_payload(payload)
        return Orchestrator(infra=infra, audit_logger=audit_logger, **kwargs).with_incident(incident)

    def propose_action(
        self,
        incident: Incident,
        target_instances: Optional[int] = None,
    ) -> RecoveryAction:
        """Generate a proposed recovery action based on incident traits via the planner."""
        current_state = self.infra.get_service(incident.service_name)
        action = self.planner.plan(incident, current_state)
        if target_instances is not None:
            action.parameters["target_instances"] = target_instances
        return action

    def with_incident(self, incident: Incident) -> "Orchestrator":
        """Attach an incident to the orchestrator for a single pipeline run."""
        self._pending_incident = incident
        return self

    def handle_incident(
        self,
        incident: Incident,
        proposed_action: Optional[RecoveryAction] = None,
    ) -> IncidentResponse:
        """Execute the complete 9-step incident recovery pipeline."""
        started_at = datetime.now(timezone.utc)

        # -------------------------------------------------------------------
        # Step 1: Receive incident
        # -------------------------------------------------------------------
        incident.status = IncidentStatus.DETECTED
        self.audit_logger.record_event(
            incident_id=incident.id,
            component_name="Orchestrator",
            event_type=AuditEventType.INCIDENT_RECEIVED,
            success=True,
            explanation=(
                f"Incident received: '{incident.title}' on service '{incident.service_name}' "
                f"with severity '{incident.severity.value}'."
            ),
            details={"incident": incident.model_dump(mode="json")},
        )

        # -------------------------------------------------------------------
        # Step 2: Load system state
        # -------------------------------------------------------------------
        state_before = self.infra.get_service(incident.service_name)
        state_found = state_before is not None
        self.audit_logger.record_event(
            incident_id=incident.id,
            component_name="Orchestrator",
            event_type=AuditEventType.STATE_LOADED,
            success=state_found,
            explanation=(
                f"Loaded system state snapshot for '{incident.service_name}'."
                if state_found
                else f"Service '{incident.service_name}' not found in infrastructure catalog."
            ),
            details={"system_state_before": state_before.model_dump(mode="json") if state_before else None},
        )

        # -------------------------------------------------------------------
        # Step 3: Ask for a proposed action
        # -------------------------------------------------------------------
        diagnosis: Optional[DiagnosisResult] = None
        diagnosis_fallback: Optional[dict[str, str]] = None
        planner_name = getattr(self.planner, "__class__", type(self.planner)).__name__

        if proposed_action is not None:
            action = proposed_action
        elif self.diagnoser is None:
            action = self.planner.plan(incident, state_before)
        else:
            if state_before is not None:
                try:
                    diagnosis = self.diagnoser.diagnose(incident, state_before)
                except (DiagnosisError, NemotronClientError) as exc:
                    if isinstance(exc, DiagnosisError):
                        fallback_reason = "schema_validation_failed"
                    elif isinstance(exc, NemotronTimeoutError):
                        fallback_reason = "timeout"
                    elif isinstance(exc, NemotronConnectionError):
                        fallback_reason = "connection_failure"
                    elif isinstance(exc, NemotronAuthError):
                        fallback_reason = "authentication_failure"
                    elif isinstance(exc, NemotronAPIError):
                        fallback_reason = "api_error"
                    elif isinstance(exc, NemotronResponseError):
                        fallback_reason = "response_error"
                    else:
                        fallback_reason = "client_error"
                    diagnosis_fallback = {
                        "status": "failed",
                        "reason": fallback_reason,
                    }
                else:
                    self.audit_logger.record_event(
                        incident_id=incident.id,
                        component_name="IncidentDiagnoser",
                        event_type=AuditEventType.DIAGNOSIS_COMPLETED,
                        success=True,
                        explanation=(
                            "AI diagnosis completed and validated; it is advisory only."
                        ),
                        details={
                            "source": "ai",
                            "diagnosis": diagnosis.model_dump(mode="json"),
                        },
                    )
            else:
                diagnosis_fallback = {
                    "status": "unavailable",
                    "reason": "system_state_unavailable",
                }

            if diagnosis_fallback is not None:
                diagnosis = DeterministicIncidentDiagnoser().diagnose(
                    incident, state_before
                )
                self.audit_logger.record_event(
                    incident_id=incident.id,
                    component_name="DeterministicIncidentDiagnoser",
                    event_type=AuditEventType.DIAGNOSIS_FALLBACK,
                    success=True,
                    explanation=(
                        "AI diagnosis was unavailable; deterministic diagnosis was "
                        "derived from available incident and infrastructure evidence."
                    ),
                    details={
                        "source": "deterministic_fallback",
                        "diagnosis_fallback": diagnosis_fallback,
                        "diagnosis": diagnosis.model_dump(mode="json"),
                    },
                )

            if diagnosis is None:
                raise RuntimeError("Diagnoser completed without returning a diagnosis.")

            action = self.planner.plan_with_diagnosis(
                incident,
                state_before,
                diagnosis,
            )
            planner_name = getattr(self.planner, "__class__", type(self.planner)).__name__

        # -------------------------------------------------------------------
        # Step 4: Record the recommendation in the audit log
        # -------------------------------------------------------------------
        action_details = {
            "recovery_action": action.model_dump(mode="json"),
            "planner": planner_name,
        }
        if diagnosis is not None and diagnosis_fallback is None:
            action_details["diagnosis"] = diagnosis.model_dump(mode="json")
        if diagnosis_fallback is not None:
            action_details["diagnosis_fallback"] = diagnosis_fallback
        self.audit_logger.record_event(
            incident_id=incident.id,
            component_name="RecoveryPlanner",
            event_type=AuditEventType.ACTION_PROPOSED,
            success=True,
            explanation=(
                f"RecoveryPlanner ({planner_name}) recommended action '{action.action_type.value}' "
                f"targeting service '{action.target_service}' with parameters {action.parameters}."
            ),
            details=action_details,
        )

        # -------------------------------------------------------------------
        # Step 5: Send the action to DeterministicPolicyGate
        # -------------------------------------------------------------------
        action_target_state = self.infra.get_service(action.target_service)
        policy_decision = self.policy_gate.evaluate(action, action_target_state)
        is_approved = policy_decision.is_approved
        self.audit_logger.record_event(
            incident_id=incident.id,
            component_name="DeterministicPolicyGate",
            event_type=AuditEventType.POLICY_EVALUATED,
            success=is_approved,
            explanation=f"Policy decision: {policy_decision.verdict.value}. Rationale: {policy_decision.reason}",
            details={"policy_decision": policy_decision.model_dump(mode="json")},
        )

        # -------------------------------------------------------------------
        # Step 6: Execute only approved actions
        # -------------------------------------------------------------------
        recovery_result: Optional[RecoveryResult] = None
        verification_result: Optional[VerificationResult] = None
        pipeline_status: PipelineStatus

        if not is_approved:
            # Policy gate rejected the action: DO NOT EXECUTE
            incident.status = IncidentStatus.REJECTED
            pipeline_status = PipelineStatus.RECOVERY_DENIED

            self.audit_logger.record_event(
                incident_id=incident.id,
                component_name="Orchestrator",
                event_type=AuditEventType.RECOVERY_SKIPPED,
                success=False,
                explanation=(
                    f"Recovery action '{action.action_type.value}' was rejected by policy gate "
                    f"and was not executed: {policy_decision.reason}"
                ),
                details={"policy_verdict": policy_decision.verdict.value},
            )
        else:
            # Policy gate approved action: Proceed with execution
            incident.status = IncidentStatus.APPROVED
            recovery_result = self.executor.execute(action, self.infra)

            if recovery_result.success:
                incident.status = IncidentStatus.EXECUTED
            else:
                incident.status = IncidentStatus.FAILED

            self.audit_logger.record_event(
                incident_id=incident.id,
                component_name="SimulatedRecoveryExecutor",
                event_type=AuditEventType.RECOVERY_EXECUTED,
                success=recovery_result.success,
                explanation=recovery_result.message,
                details={"recovery_result": recovery_result.model_dump(mode="json")},
            )

            # ---------------------------------------------------------------
            # Step 7: Independently verify the resulting state
            # ---------------------------------------------------------------
            if recovery_result.success:
                verification_result = self.verifier.verify(
                    service_name=incident.service_name,
                    infra=self.infra,
                    action=action,
                    incident_id=incident.id,
                )

                verification_passed = verification_result.outcome == VerificationOutcome.PASS
                self.audit_logger.record_event(
                    incident_id=incident.id,
                    component_name="IndependentVerifier",
                    event_type=AuditEventType.VERIFICATION_COMPLETED,
                    success=verification_passed,
                    explanation=verification_result.details,
                    details={"verification_result": verification_result.model_dump(mode="json")},
                )

                if verification_passed:
                    incident.status = IncidentStatus.VERIFIED
                    incident.resolved_at = datetime.now(timezone.utc)
                    pipeline_status = PipelineStatus.SUCCESS
                else:
                    incident.status = IncidentStatus.FAILED
                    pipeline_status = PipelineStatus.VERIFICATION_FAILED
            else:
                pipeline_status = PipelineStatus.RECOVERY_FAILED

        # -------------------------------------------------------------------
        # Step 8: Record every result in the audit log
        # -------------------------------------------------------------------
        self.audit_logger.record_event(
            incident_id=incident.id,
            component_name="Orchestrator",
            event_type=AuditEventType.PIPELINE_COMPLETED,
            success=(pipeline_status == PipelineStatus.SUCCESS),
            explanation=f"Incident recovery pipeline completed with status '{pipeline_status.value}'.",
            details={
                "pipeline_status": pipeline_status.value,
                "incident_status": incident.status.value,
            },
        )

        # -------------------------------------------------------------------
        # Step 9: Return IncidentResponse
        # -------------------------------------------------------------------
        state_after = self.infra.get_service(incident.service_name)
        incident_events = self.audit_logger.get_events_for_incident(incident.id)

        response = IncidentResponse(
            incident=incident,
            system_state_before=state_before,
            policy_decision=policy_decision,
            recovery_action=action,
            recovery_result=recovery_result,
            verification_result=verification_result,
            system_state_after=state_after,
            audit_events=incident_events,
            pipeline_status=pipeline_status,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )
        self.audit_logger.log_pipeline_record(response)
        return response
