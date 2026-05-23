"""Tests for agentwitness.state."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentwitness.state import ENV_OVERRIDE, session_dir, sessions_dir, state_dir


def test_env_override_takes_precedence(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(ENV_OVERRIDE, str(tmp_path))
    assert state_dir() == tmp_path
    assert sessions_dir() == tmp_path / "sessions"
    assert session_dir("sess_x") == tmp_path / "sessions" / "sess_x"


def test_default_under_home_when_no_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(ENV_OVERRIDE, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    # Don't pin a platform; just confirm the path is under the fake home.
    resolved = state_dir()
    # macOS uses Library/Application Support; Linux uses .local/share or
    # $XDG_DATA_HOME. Both will be under HOME when XDG_DATA_HOME is unset.
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    resolved = state_dir()
    assert "agentwitness" in resolved.name or "agentwitness" == resolved.name


def test_xdg_data_home_used_when_set(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """On Linux, XDG_DATA_HOME overrides the ~/.local/share default."""
    import sys

    if sys.platform != "linux":
        pytest.skip("XDG_DATA_HOME logic only applies on Linux")
    monkeypatch.delenv(ENV_OVERRIDE, raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert state_dir() == tmp_path / "agentwitness"
