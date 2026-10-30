"""Shared environment configuration for Nebius clients and administrative routes."""

from __future__ import annotations

import os
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

DEFAULT_NEBIUS_API_BASE = "https://api.studio.nebius.ai/v1"
DEFAULT_NEBIUS_MODEL_ID = "nvidia/llama-3.1-nemotron-70b-instruct"
DEFAULT_NEBIUS_TIMEOUT_SECONDS = 30.0
TRUTHY_VALUES = {"1", "true", "yes", "t", "on"}


def _first_configured(*names: str) -> Optional[str]:
    for name in names:
        value = os.getenv(name)
        if value and value.strip():
            return value.strip()
    return None


def get_nebius_api_key() -> Optional[str]:
    return _first_configured(
        "NEBIUS_API_KEY",
        "NEMOTRON_API_KEY",
        "NEBIUS_TOKEN_FACTORY_API_KEY",
    )


def get_nebius_api_base() -> str:
    return (
        _first_configured(
            "NEBIUS_API_BASE",
            "NEBIUS_BASE_URL",
            "NEBIUS_TOKEN_FACTORY_BASE_URL",
        )
        or DEFAULT_NEBIUS_API_BASE
    ).rstrip("/")


def get_nebius_model_id() -> str:
    return (
        _first_configured("NEBIUS_MODEL_ID", "NEBIUS_MODEL", "NEMOTRON_MODEL")
        or DEFAULT_NEBIUS_MODEL_ID
    )


def get_nebius_timeout_seconds() -> float:
    raw_timeout = _first_configured("NEBIUS_TIMEOUT_SECONDS", "NEMOTRON_TIMEOUT_SECONDS")
    if raw_timeout is None:
        return DEFAULT_NEBIUS_TIMEOUT_SECONDS
    try:
        return max(0.1, float(raw_timeout))
    except ValueError:
        return DEFAULT_NEBIUS_TIMEOUT_SECONDS


def is_nebius_mock_mode() -> bool:
    value = _first_configured("NEBIUS_MOCK_MODE", "NEMOTRON_MOCK_MODE")
    return value is not None and value.lower() in TRUTHY_VALUES


def is_ai_diagnosis_enabled() -> bool:
    value = _first_configured("ENABLE_AI_DIAGNOSIS")
    return value is not None and value.lower() in TRUTHY_VALUES
