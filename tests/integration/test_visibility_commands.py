"""Tests for the ``export``, ``summary``, and ``blame`` CLI commands."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from agentwitness import keychain, verify
from agentwitness.cli import cli
from agentwitness.hook import main as hook_main
from agentwitness.install import CLAUDE_SETTINGS_ENV, install
from agentwitness.state import ENV_OVERRIDE


@pytest.fixture(autouse=True)
def in_memory_keyring() -> None:
    keychain._install_in_memory_backend()  # type: ignore[attr-defined]


@pytest.fixture
def recorded_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Install agentwitness in a sandbox and record three events through the hook."""
    state = tmp_path / "state"
    settings = tmp_path / "claude" / "settings.json"
    monkeypatch.setenv(ENV_OVERRIDE, str(state))
    monkeypatch.setenv(CLAUDE_SETTINGS_ENV, str(settings))

    install()

    payloads = [
        {
            "session_id": "claude-vis-test",
            "hook_event_name": "SessionStart",
            "source": "startup",
            "model": "claude-opus-4-7",
        },
        {
            "session_id": "claude-vis-test",
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/app.ts", "old_string": "a", "new_string": "b"},
            "tool_use_id": "tu-1",
        },
        {
            "session_id": "claude-vis-test",
            "hook_event_name": "PostToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/app.ts"},
            "tool_use_id": "tu-1",
            "tool_result": "ok",
        },
    ]
    for payload in payloads:
        rc = hook_main(stdin=io.StringIO(json.dumps(payload)))
        assert rc == 0

    return {"state": state, "settings": settings, "tmp": tmp_path}


# ---- export ----


def test_export_latest_session_writes_verifiable_bundle(
    recorded_environment: dict[str, Any],
) -> None:
    out = recorded_environment["tmp"] / "bundle"
    runner = CliRunner()
    result = runner.invoke(cli, ["export", "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert (out / "manifest.json").exists()
    assert (out / "events.jsonl").exists()
    assert (out / "signatures.jsonl").exists()
    assert (out / "chain.json").exists()

    # And the produced bundle verifies.
    verify_result = verify(out)
    assert verify_result.ok, [(e.code, e.message) for e in verify_result.errors]
    assert verify_result.events_verified == 3


def test_export_with_no_sessions_fails_helpfully(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_OVERRIDE, str(tmp_path / "state"))
    monkeypatch.setenv(CLAUDE_SETTINGS_ENV, str(tmp_path / "settings.json"))
    install()  # no sessions yet
    runner = CliRunner()
    result = runner.invoke(cli, ["export", "-o", str(tmp_path / "bundle")])
    assert result.exit_code != 0
    assert "No sessions" in result.output


def test_export_unknown_session_id_fails(recorded_environment: dict[str, Any]) -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "export",
            "--session",
            "sess_nonsuch",
            "-o",
            str(recorded_environment["tmp"] / "bundle"),
        ],
    )
    assert result.exit_code != 0
    assert "No session named" in result.output


# ---- summary ----


def test_summary_with_no_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_OVERRIDE, str(tmp_path / "state"))
    monkeypatch.setenv(CLAUDE_SETTINGS_ENV, str(tmp_path / "settings.json"))
    runner = CliRunner()
    result = runner.invoke(cli, ["summary"])
    assert result.exit_code == 0
    assert "not installed" in result.output


def test_summary_shows_installed_with_sessions(recorded_environment: dict[str, Any]) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["summary"])
    assert result.exit_code == 0, result.output
    assert "manifest:" in result.output
    assert "sessions" in result.output
    assert "3 events" in result.output
    assert "claude-vis-test" in result.output


def test_summary_shows_installed_with_no_sessions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_OVERRIDE, str(tmp_path / "state"))
    monkeypatch.setenv(CLAUDE_SETTINGS_ENV, str(tmp_path / "settings.json"))
    install()
    runner = CliRunner()
    result = runner.invoke(cli, ["summary"])
    assert result.exit_code == 0, result.output
    assert "No sessions recorded yet" in result.output


# ---- blame ----


def test_blame_finds_matching_events(recorded_environment: dict[str, Any]) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["blame", "src/app.ts"])
    assert result.exit_code == 0
    # Two events touched src/app.ts: the tool.requested and the tool.completed.
    assert "tool.requested" in result.output
    assert "tool.completed" in result.output
    assert "Edit" in result.output


def test_blame_matches_by_trailing_segment() -> None:
    """The fix that makes blame useful in practice — Claude Code records
    absolute paths and most users will type the file name."""
    from agentwitness.cli import _blame_matches

    # Exact equality
    assert _blame_matches("/Users/nick/lorem.md", "/Users/nick/lorem.md")
    # Trailing segment match — the case that bit during real dogfood
    assert _blame_matches("lorem.md", "/Users/nick/lorem.md")
    assert _blame_matches("src/auth.ts", "/Users/nick/proj/src/auth.ts")
    # Same suffix but different file — must NOT match
    assert not _blame_matches("lorem.md", "/Users/nick/other-lorem.md")
    # Absolute query requires exact match, no fuzziness
    assert not _blame_matches("/Users/nick/lorem.md", "/Users/nick/other/lorem.md")
    assert not _blame_matches("/lorem.md", "/Users/nick/lorem.md")
    # Empty resource path never matches
    assert not _blame_matches("lorem.md", "")


def test_blame_no_match(recorded_environment: dict[str, Any]) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["blame", "src/never_touched.ts"])
    assert result.exit_code == 0
    assert "No recorded events touched" in result.output


def test_blame_with_no_sessions_does_not_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_OVERRIDE, str(tmp_path / "state"))
    monkeypatch.setenv(CLAUDE_SETTINGS_ENV, str(tmp_path / "settings.json"))
    runner = CliRunner()
    result = runner.invoke(cli, ["blame", "anything.ts"])
    assert result.exit_code == 0
    assert "No events recorded yet" in result.output
