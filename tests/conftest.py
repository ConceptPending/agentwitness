"""Shared pytest fixtures and hypothesis profile configuration."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from hypothesis import HealthCheck, Verbosity, settings

FIXTURES_ROOT = Path(__file__).parent / "fixtures"


# Hypothesis profiles. Selected via the AGENTWITNESS_HYPOTHESIS_PROFILE env var.
settings.register_profile(
    "dev",
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile(
    "ci",
    max_examples=500,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile(
    "nightly",
    max_examples=5000,
    deadline=None,
    verbosity=Verbosity.normal,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile(os.environ.get("AGENTWITNESS_HYPOTHESIS_PROFILE", "dev"))


@pytest.fixture
def valid_bundle() -> Path:
    """Path to the hand-authored valid fixture bundle."""
    return FIXTURES_ROOT / "valid"


@pytest.fixture
def tampered_bundle() -> Path:
    """Path to the hand-authored tampered fixture bundle."""
    return FIXTURES_ROOT / "tampered"


@pytest.fixture
def out_of_scope_bundle() -> Path:
    """Path to the hand-authored out-of-scope fixture bundle."""
    return FIXTURES_ROOT / "out_of_scope"
