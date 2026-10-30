"""Pytest configuration for test suite environment isolation."""

import pytest


@pytest.fixture(autouse=True)
def _default_test_env(monkeypatch):
    """Ensure unit tests run with clean default environment matching CI,

    isolating tests from developer-specific local .env overrides.
    Individual tests that test ENABLE_AI_DIAGNOSIS explicitly set it via monkeypatch.
    """
    monkeypatch.delenv("ENABLE_AI_DIAGNOSIS", raising=False)

