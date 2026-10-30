"""Diagnosis service for IT incident root-cause analysis.

Uses NemotronClient to invoke NVIDIA Nemotron via Nebius Token Factory,
parses the structured response, and enforces strict validation against
the DiagnosisResult schema and supported recovery actions.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Optional

from pydantic import ValidationError

from app.diagnosis.client import NemotronClient
from app.diagnosis.exceptions import DiagnosisError
from app.diagnosis.models import DiagnosisResult
from app.diagnosis.prompts import build_diagnosis_messages
from app.models import (
    Incident,
    IncidentSeverity,
    RecoveryActionType,
    SystemState,
)

logger = logging.getLogger(__name__)


def _clean_json_text(text: str) -> str:
    """Strip optional markdown code fences, preambles, and surrounding text."""
    if not text:
        return ""
    stripped = text.strip()

    # 1. Regex pattern for markdown-fenced JSON block: ```json ... ``` or ``` ... ```
    fence_pattern = re.compile(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", re.IGNORECASE)
    match = fence_pattern.search(stripped)
    if match:
        return match.group(1).strip()

    # 2. If text starts and ends with markdown fences without preamble
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        # Remove opening fence line (e.g. ```json or ```)
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        # Remove closing fence line
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()

    # 3. If there is a conversational preamble/postscript around raw JSON:
    # Find the outermost '{' and '}'
    first_brace = stripped.find("{")
    last_brace = stripped.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        candidate = stripped[first_brace : last_brace + 1].strip()
        try:
            json.loads(candidate)
            return candidate
        except (json.JSONDecodeError, ValueError):
            pass

    return stripped


class IncidentDiagnoser:
    """Service that coordinates incident diagnosis using NVIDIA Nemotron.

    Ensures that incident diagnosis is isolated from execution, strictly
    validated, and never silently fabricates or guesses missing actions.
    """

    def __init__(
        self,
        client: Optional[NemotronClient] = None,
        temperature: float = 0.2,
    ) -> None:
        """Initialize the diagnoser.

        Args:
            client: Configured NemotronClient instance. If None, creates a default client.
            temperature: Sampling temperature for deterministic reasoning.
        """
        self.client = client if client is not None else NemotronClient()
        self.temperature = temperature

    def diagnose(self, incident: Incident, state: SystemState) -> DiagnosisResult:
        """Diagnose an incident given current system snapshot metrics.

        Args:
            incident: The incident to analyze.
            state: The observed system state snapshot.

        Returns:
            A strictly validated DiagnosisResult.

        Raises:
            ValueError: If incident or state is invalid.
            NemotronClientError: If network, authentication, or API call fails.
            DiagnosisError: If the model response cannot be parsed as valid JSON
                or violates the DiagnosisResult schema (missing fields,
                unsupported action IDs, invalid confidence, etc.).
        """
        if not isinstance(incident, Incident):
            raise ValueError(f"Expected Incident instance, got {type(incident).__name__}")
        if not isinstance(state, SystemState):
            raise ValueError(f"Expected SystemState instance, got {type(state).__name__}")

        messages = build_diagnosis_messages(incident, state)

        # Call client (network, auth, timeout errors propagate clearly)
        raw_output = self.client.complete(
            messages=messages,
            temperature=self.temperature,
        )

        return self._parse_and_validate(raw_output)

    def _parse_and_validate(self, raw_output: str) -> DiagnosisResult:
        """Parse raw model output and validate against the schema."""
        if not raw_output or not raw_output.strip():
            raise DiagnosisError("Nemotron returned an empty response.")

        cleaned = _clean_json_text(raw_output)

        try:
            parsed = json.loads(cleaned)
        except (json.JSONDecodeError, TypeError, ValueError) as err:
            raise DiagnosisError(
                f"Failed to parse Nemotron response as JSON: {err}. Raw output: {raw_output[:200]}"
            ) from err

        if not isinstance(parsed, dict):
            raise DiagnosisError(
                f"Nemotron response must be a JSON object, got {type(parsed).__name__}"
            )

        try:
            return DiagnosisResult.model_validate(parsed)
        except ValidationError as err:
            raise DiagnosisError(
                f"Diagnosis schema validation failed: {err}"
            ) from err


class DeterministicIncidentDiagnoser:
    """Create a low-confidence diagnosis grounded only in incident and state data."""

    def diagnose(
        self,
        incident: Incident,
        state: Optional[SystemState],
    ) -> DiagnosisResult:
        evidence = [
            f"Incident severity is {incident.severity.value}.",
        ]
        if incident.title:
            evidence.append(f"Incident title: {incident.title}.")
        if incident.description:
            evidence.append(f"Incident description: {incident.description}.")

        action = RecoveryActionType.RESTART_SERVICE
        if state is None:
            cause = "Insufficient infrastructure telemetry to determine the likely cause."
            evidence.append("Infrastructure state is unavailable.")
        elif state.queue_size > 0:
            cause = "Observed queue backlog may be contributing to the incident."
            evidence.append(f"Queue size is {state.queue_size}.")
            action = RecoveryActionType.CLEAR_QUEUE
        elif state.cpu_percent > 70.0:
            cause = "Observed high CPU utilization may be contributing to the incident."
            evidence.append(f"CPU utilization is {state.cpu_percent:.1f}%.")
            action = RecoveryActionType.SCALE_SERVICE
        elif state.memory_percent > 85.0:
            cause = "Observed high memory utilization may be contributing to the incident."
            evidence.append(f"Memory utilization is {state.memory_percent:.1f}%.")
        elif state.error_rate > 0.1:
            cause = "Observed elevated error rate may be contributing to the incident."
            evidence.append(f"Error rate is {state.error_rate:.2f}.")
        elif state.status.value != "healthy":
            cause = f"Service state is {state.status.value}; the specific cause is undetermined."
            evidence.append(f"Service status is {state.status.value}.")
        else:
            cause = "Available telemetry does not identify a specific failure cause."
            evidence.append("No configured CPU, memory, queue, or error-rate threshold is exceeded.")

        if incident.severity == IncidentSeverity.CRITICAL and action == RecoveryActionType.RESTART_SERVICE:
            action = RecoveryActionType.FAILOVER
        elif incident.severity == IncidentSeverity.HIGH and action == RecoveryActionType.RESTART_SERVICE:
            action = RecoveryActionType.SCALE_UP

        return DiagnosisResult(
            likely_cause=cause,
            evidence=evidence,
            confidence=0.3,
            recommended_action_id=action.value,
            rationale="Use the deterministic recovery proposal derived from the available incident and telemetry.",
            uncertainty_or_notes=(
                "Deterministic fallback diagnosis; validate the cause with an operator."
            ),
        )


# Backwards compatibility alias
AIDiagnoser = IncidentDiagnoser
