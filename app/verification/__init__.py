"""Independent post-recovery verification module.

Exports:
- IndependentVerifier: class for inspecting infrastructure state independently post-recovery
- verify: legacy functional wrapper
"""

from __future__ import annotations

from typing import Optional

from app.infrastructure import InfrastructureSimulator
from app.models import RecoveryAction, VerificationResult
from app.verification.verifier import IndependentVerifier


def verify(
    service_name: str,
    infra: InfrastructureSimulator,
    action: Optional[RecoveryAction] = None,
) -> VerificationResult:
    """Legacy helper: Verify service health post-recovery."""
    verifier = IndependentVerifier()
    return verifier.verify(service_name=service_name, infra=infra, action=action)


__all__ = [
    "IndependentVerifier",
    "verify",
]
