"""AI Recovery Planner interface and implementations.

Provides:
- RecoveryPlanner: abstract base class for proposing recovery actions without execution authority.
- AIPlanProposal: strict Pydantic model validating structured AI output.
- DeterministicMockPlanner: deterministic, rule-based planner for local tests and fallback.
- NebiusPlanner: production planner using OpenAI-compatible Nebius Token Factory API.
"""

from __future__ import annotations

import abc
import json
import logging
from typing import Any, Dict, Optional

import httpx
from pydantic import BaseModel, Field

from app.config import (
    DEFAULT_NEBIUS_API_BASE,
    DEFAULT_NEBIUS_MODEL_ID,
    get_nebius_api_base,
    get_nebius_api_key,
    get_nebius_model_id,
    get_nebius_timeout_seconds,
    is_nebius_mock_mode,
)
from app.diagnosis.models import DiagnosisResult
from app.models import (
    Incident,
    IncidentSeverity,
    RecoveryAction,
    RecoveryActionType,
    SystemState,
)

logger = logging.getLogger(__name__)

DEFAULT_NEBIUS_MODEL = DEFAULT_NEBIUS_MODEL_ID
DEFAULT_NEBIUS_BASE_URL = DEFAULT_NEBIUS_API_BASE


class AIPlanProposal(BaseModel):
    """Strict structured JSON schema required from the AI planner model.

    Must contain:
    - action_type: explicit recovery action
    - target_service: name of affected service
    - parameters: key-value dictionary of action parameters
    - reasoning: human-readable explanation of why this action is chosen
    - confidence: float score between 0.0 and 1.0
    """

    action_type: RecoveryActionType = Field(..., description="Action type to propose")
    target_service: str = Field(..., min_length=1, max_length=128, description="Target service")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Action parameters")
    reasoning: str = Field(..., min_length=1, max_length=2048, description="Model rationale")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score 0.0 - 1.0")


class RecoveryPlanner(abc.ABC):
    """Abstract interface for proposing recovery actions.

    The AI planner may ONLY suggest an action.
    It must never approve, execute, verify, or write audit events.
    """

    @abc.abstractmethod
    def plan(
        self,
        incident: Incident,
        state: Optional[SystemState],
    ) -> RecoveryAction:
        """Analyze incident and system state to propose a RecoveryAction."""
        pass

    def plan_with_diagnosis(
        self,
        incident: Incident,
        state: Optional[SystemState],
        diagnosis: DiagnosisResult,
    ) -> RecoveryAction:
        """Plan with diagnosis context while preserving existing planner implementations."""
        action = self.plan(incident, state)
        parameters = {
            **action.parameters,
            "diagnosis_likely_cause": diagnosis.likely_cause,
            "diagnosis_confidence": diagnosis.confidence,
            "diagnosis_evidence": diagnosis.evidence,
            "diagnosis_rationale": diagnosis.rationale,
            "diagnosis_uncertainty_or_notes": diagnosis.uncertainty_or_notes,
        }
        return action.model_copy(update={"parameters": parameters})


class DeterministicMockPlanner(RecoveryPlanner):
    """Deterministic, rule-based recovery planner used for local tests and fallback."""

    def plan(
        self,
        incident: Incident,
        state: Optional[SystemState],
    ) -> RecoveryAction:
        desc = f"{incident.title} {incident.description}".lower()
        params: Dict[str, Any] = {"severity": incident.severity.value}

        # 1. Queue backlog -> clear queue
        if "queue" in desc or (state and state.queue_size > 0):
            action_type = RecoveryActionType.CLEAR_QUEUE
        # 2. High load / scale request -> scale service
        elif "scale" in desc or (state and state.cpu_percent > 70.0):
            action_type = RecoveryActionType.SCALE_SERVICE
            target_instances = (state.instances + 1) if state else 2
            params["target_instances"] = target_instances
        # 3. Critical incident -> failover
        elif incident.severity == IncidentSeverity.CRITICAL:
            action_type = RecoveryActionType.FAILOVER
        # 4. High severity -> scale up
        elif incident.severity == IncidentSeverity.HIGH:
            action_type = RecoveryActionType.SCALE_UP
        # 5. Default -> restart service
        else:
            action_type = RecoveryActionType.RESTART_SERVICE

        return RecoveryAction(
            incident_id=incident.id,
            action_type=action_type,
            target_service=incident.service_name,
            parameters=params,
            safe_for_simulation=True,
            risk_level=1,
            retry_count=0,
        )

    def plan_with_diagnosis(
        self,
        incident: Incident,
        state: Optional[SystemState],
        diagnosis: DiagnosisResult,
    ) -> RecoveryAction:
        action_type = RecoveryActionType(diagnosis.recommended_action_id)
        parameters: Dict[str, Any] = {
            "severity": incident.severity.value,
            "diagnosis_likely_cause": diagnosis.likely_cause,
            "diagnosis_confidence": diagnosis.confidence,
            "diagnosis_evidence": diagnosis.evidence,
            "diagnosis_rationale": diagnosis.rationale,
            "diagnosis_uncertainty_or_notes": diagnosis.uncertainty_or_notes,
        }
        if action_type in {
            RecoveryActionType.SCALE_SERVICE,
            RecoveryActionType.SCALE_UP,
        }:
            parameters["target_instances"] = state.instances + 1 if state else 2
        return RecoveryAction(
            incident_id=incident.id,
            action_type=action_type,
            target_service=incident.service_name,
            parameters=parameters,
            safe_for_simulation=True,
            risk_level=1,
            retry_count=0,
        )


class NebiusPlanner(RecoveryPlanner):
    """Production planner calling OpenAI-compatible Nebius Token Factory API.

    Environment variables:
    - NEBIUS_API_KEY (aliases: NEMOTRON_API_KEY, NEBIUS_TOKEN_FACTORY_API_KEY)
    - NEBIUS_API_BASE (aliases: NEBIUS_BASE_URL, NEBIUS_TOKEN_FACTORY_BASE_URL)
    - NEBIUS_MODEL_ID (aliases: NEBIUS_MODEL, NEMOTRON_MODEL)
    - NEBIUS_TIMEOUT_SECONDS (alias: NEMOTRON_TIMEOUT_SECONDS)
    - NEBIUS_MOCK_MODE (alias: NEMOTRON_MOCK_MODE)

    If credentials are missing or the API call / validation fails, safely falls
    back to DeterministicMockPlanner.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[float] = None,
        fallback_planner: Optional[RecoveryPlanner] = None,
    ) -> None:
        self.api_key = api_key if api_key is not None else get_nebius_api_key() or ""
        self.base_url = (base_url or get_nebius_api_base()).rstrip("/")
        self.model = model or get_nebius_model_id()
        self.timeout = timeout if timeout is not None else get_nebius_timeout_seconds()
        self.mock_mode = is_nebius_mock_mode()
        self.fallback_planner = (
            fallback_planner if fallback_planner is not None else DeterministicMockPlanner()
        )

    def plan(
        self,
        incident: Incident,
        state: Optional[SystemState],
    ) -> RecoveryAction:
        return self._plan(incident, state, diagnosis=None)

    def plan_with_diagnosis(
        self,
        incident: Incident,
        state: Optional[SystemState],
        diagnosis: DiagnosisResult,
    ) -> RecoveryAction:
        return self._plan(incident, state, diagnosis=diagnosis)

    def _plan(
        self,
        incident: Incident,
        state: Optional[SystemState],
        diagnosis: Optional[DiagnosisResult],
    ) -> RecoveryAction:
        """Call Nebius Token Factory to generate a strictly validated RecoveryAction.

        Falls back to DeterministicMockPlanner if credentials are missing or any error occurs.
        """
        if self.mock_mode:
            logger.info("NEBIUS_MOCK_MODE is enabled. Using DeterministicMockPlanner fallback.")
            if diagnosis is not None:
                return self.fallback_planner.plan_with_diagnosis(
                    incident, state, diagnosis
                )
            return self.fallback_planner.plan(incident, state)

        # Fall back if no API key is configured
        if not self.api_key or not self.api_key.strip():
            logger.info("NEBIUS_API_KEY not set. Using DeterministicMockPlanner fallback.")
            if diagnosis is not None:
                return self.fallback_planner.plan_with_diagnosis(
                    incident, state, diagnosis
                )
            return self.fallback_planner.plan(incident, state)

        try:
            proposal = self._call_nebius_api(incident, state, diagnosis)
            parameters = {
                **proposal.parameters,
                "severity": incident.severity.value,
                "ai_reasoning": proposal.reasoning,
                "ai_confidence": proposal.confidence,
                "ai_model": self.model,
            }
            if diagnosis is not None:
                parameters.update({
                    "diagnosis_likely_cause": diagnosis.likely_cause,
                    "diagnosis_confidence": diagnosis.confidence,
                    "diagnosis_evidence": diagnosis.evidence,
                    "diagnosis_rationale": diagnosis.rationale,
                    "diagnosis_uncertainty_or_notes": diagnosis.uncertainty_or_notes,
                })
            return RecoveryAction(
                incident_id=incident.id,
                action_type=proposal.action_type,
                target_service=proposal.target_service,
                parameters=parameters,
                safe_for_simulation=True,
                risk_level=1,
                retry_count=0,
            )
        except Exception as exc:
            logger.warning("NebiusPlanner call or validation failed: %s. Using fallback planner.", exc)
            if diagnosis is not None:
                return self.fallback_planner.plan_with_diagnosis(
                    incident, state, diagnosis
                )
            return self.fallback_planner.plan(incident, state)

    def _call_nebius_api(
        self,
        incident: Incident,
        state: Optional[SystemState],
        diagnosis: Optional[DiagnosisResult] = None,
    ) -> AIPlanProposal:
        """Execute OpenAI-compatible HTTP request and validate strict JSON response."""
        system_prompt = (
            "You are an Autonomous IT Incident Recovery Planning AI for NVIDIA and Nebius infrastructure. "
            "Analyze the incident details and current system state, then propose a recovery action. "
            "If diagnosis context is supplied, use it as advisory input and do not treat it as policy approval.\n\n"
            "You MUST respond ONLY with a strict JSON object containing EXACTLY these keys:\n"
            "- \"action_type\": one of [\"restart_service\", \"clear_queue\", \"scale_service\", \"scale_up\", \"failover\"]\n"
            "- \"target_service\": string service name\n"
            "- \"parameters\": dictionary of parameters (for scale_service include \"target_instances\")\n"
            "- \"reasoning\": clear concise justification for this action\n"
            "- \"confidence\": float between 0.0 and 1.0\n\n"
            "Do not include markdown fences or extraneous text. Return raw JSON."
        )

        user_content = json.dumps(
            {
                "incident": {
                    "id": incident.id,
                    "service_name": incident.service_name,
                    "severity": incident.severity.value,
                    "title": incident.title,
                    "description": incident.description,
                },
                "system_state": state.model_dump(mode="json") if state else None,
                "diagnosis": diagnosis.model_dump(mode="json") if diagnosis else None,
            },
            indent=2,
        )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1,
        }

        url = f"{self.base_url}/chat/completions"

        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

        content = data["choices"][0]["message"]["content"]
        # Validate the strict structured JSON before returning
        return AIPlanProposal.model_validate_json(content)
