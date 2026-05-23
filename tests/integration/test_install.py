"""Install / uninstall tests, including the full Phase 5 closure test.

The closure test exercises the whole producer path end-to-end:

    install → simulate Claude Code hook firings → export → verify

If that test passes, the recorder, signer, manifest builder, writer,
hook entry point, settings patcher, and export module all agree.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import nacl.signing
import pytest
from click.testing import CliRunner

from agentwitness import keychain, verify
from agentwitness.cli import cli
from agentwitness.export import build_bundle
from agentwitness.hook import (
    derive_agentwitness_session_id,
)
from agentwitness.hook import (
    main as hook_main,
)
from agentwitness.install import (
    CLAUDE_SETTINGS_ENV,
    InstallError,
    _is_agentwitness_entry,
    _patch_settings,
    _strip_agentwitness_hooks,
    install,
    uninstall,
)
from agentwitness.state import ENV_OVERRIDE, state_dir
from agentwitness.writer import Session


@pytest.fixture(autouse=True)
def in_memory_keyring() -> None:
    keychain._install_in_memory_backend()  # type: ignore[attr-defined]


@pytest.fixture
def isolated_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    state = tmp_path / "state"
    settings = tmp_path / "claude" / "settings.json"
    monkeypatch.setenv(ENV_OVERRIDE, str(state))
    monkeypatch.setenv(CLAUDE_SETTINGS_ENV, str(settings))
    return {"state": state, "settings": settings}


# ---- Settings patcher unit tests ----


def test_patch_settings_creates_file_when_missing(tmp_path: Path) -> None:
    settings_path = tmp_path / "claude" / "settings.json"
    backup = _patch_settings(settings_path, "agentwitness hook", ("PreToolUse", "PostToolUse"))
    assert backup is None  # nothing to back up
    assert settings_path.exists()
    data = json.loads(settings_path.read_text())
    assert "hooks" in data
    assert "PreToolUse" in data["hooks"]
    assert "PostToolUse" in data["hooks"]


def test_patch_settings_writes_backup_when_existing(tmp_path: Path) -> None:
    settings_path = tmp_path / "claude" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(json.dumps({"unrelated": "preserved"}))
    backup = _patch_settings(settings_path, "agentwitness hook", ("PreToolUse",))
    assert backup is not None
    assert backup.exists()
    assert json.loads(backup.read_text()) == {"unrelated": "preserved"}
    data = json.loads(settings_path.read_text())
    assert data["unrelated"] == "preserved"  # preserved
    assert "hooks" in data
    assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "agentwitness hook"


def test_patch_settings_preserves_other_tools_hooks(tmp_path: Path) -> None:
    """Existing user hooks from other tools must survive the patch."""
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Edit",
                            "hooks": [{"type": "command", "command": "/other/tool"}],
                        }
                    ]
                }
            }
        )
    )
    _patch_settings(settings_path, "agentwitness hook", ("PreToolUse",))
    data = json.loads(settings_path.read_text())
    entries = data["hooks"]["PreToolUse"]
    assert len(entries) == 2
    commands = [h["command"] for entry in entries for h in entry["hooks"]]
    assert "/other/tool" in commands
    assert "agentwitness hook" in commands


def test_patch_settings_is_idempotent(tmp_path: Path) -> None:
    """Running install twice must produce identical file contents."""
    settings_path = tmp_path / "settings.json"
    _patch_settings(settings_path, "agentwitness hook", ("PreToolUse",))
    first = settings_path.read_text()
    _patch_settings(settings_path, "agentwitness hook", ("PreToolUse",))
    second = settings_path.read_text()
    assert first == second
    data = json.loads(second)
    assert len(data["hooks"]["PreToolUse"]) == 1  # no duplicate


def test_patch_settings_rejects_malformed_existing(tmp_path: Path) -> None:
    settings_path = tmp_path / "settings.json"
    settings_path.write_text("{not json")
    with pytest.raises(InstallError) as exc_info:
        _patch_settings(settings_path, "agentwitness hook", ("PreToolUse",))
    assert exc_info.value.code == "install.malformed_settings"


def test_is_agentwitness_entry_recognises_module_invocation() -> None:
    entry = {
        "matcher": "*",
        "hooks": [{"type": "command", "command": "/usr/bin/python3 -m agentwitness.cli hook"}],
    }
    assert _is_agentwitness_entry(entry)


def test_is_agentwitness_entry_does_not_match_unrelated_tool() -> None:
    entry = {
        "matcher": "*",
        "hooks": [{"type": "command", "command": "/usr/bin/other-tool hook"}],
    }
    assert not _is_agentwitness_entry(entry)


# ---- Install ----


def test_install_writes_key_manifest_and_settings(isolated_paths: dict[str, Path]) -> None:
    result = install()
    assert keychain.exists("default")
    assert result.manifest_path.exists()
    assert isolated_paths["settings"].exists()
    assert not result.key_existed  # fresh install

    data = json.loads(isolated_paths["settings"].read_text())
    assert "PreToolUse" in data["hooks"]
    assert "SessionStart" in data["hooks"]


def test_install_is_idempotent(isolated_paths: dict[str, Path]) -> None:
    first = install()
    second = install()
    assert second.key_existed
    assert second.key_id == first.key_id

    data = json.loads(isolated_paths["settings"].read_text())
    # No duplicates per event.
    for entries in data["hooks"].values():
        agentwitness_entries = [e for e in entries if _is_agentwitness_entry(e)]
        assert len(agentwitness_entries) == 1


# ---- Uninstall ----


def test_uninstall_removes_hooks_keeps_state_and_keys(
    isolated_paths: dict[str, Path],
) -> None:
    install()
    assert keychain.exists("default")
    result = uninstall()
    assert result.hooks_removed > 0
    assert keychain.exists("default")  # not purged
    assert isolated_paths["state"].exists()  # not purged
    data = json.loads(isolated_paths["settings"].read_text())
    # No agentwitness entries remain.
    for entries in data.get("hooks", {}).values():
        assert not any(_is_agentwitness_entry(e) for e in entries)


def test_uninstall_purge_keys_removes_seed(isolated_paths: dict[str, Path]) -> None:
    install()
    uninstall(purge_keys=True)
    assert not keychain.exists("default")


def test_uninstall_purge_state_removes_state_dir(
    isolated_paths: dict[str, Path],
) -> None:
    install()
    uninstall(purge_state=True)
    assert not isolated_paths["state"].exists()


def test_uninstall_restore_from_backup(isolated_paths: dict[str, Path]) -> None:
    """When backup exists, restore-from-backup recovers original settings exactly."""
    # Create a pre-existing settings file with unrelated content.
    isolated_paths["settings"].parent.mkdir(parents=True, exist_ok=True)
    original = {"unrelated": "abc", "hooks": {"PreToolUse": []}}
    isolated_paths["settings"].write_text(json.dumps(original))

    install()
    uninstall(restore_from_backup=True)
    assert json.loads(isolated_paths["settings"].read_text()) == original


def test_uninstall_on_clean_machine_is_safe(isolated_paths: dict[str, Path]) -> None:
    """Calling uninstall before install was ever run shouldn't blow up."""
    result = uninstall()
    assert result.hooks_removed == 0


def test_strip_handles_malformed_settings_gracefully(tmp_path: Path) -> None:
    """If settings.json is corrupt, uninstall leaves it alone rather than rewriting it."""
    settings_path = tmp_path / "settings.json"
    settings_path.write_text("{not json")
    removed = _strip_agentwitness_hooks(settings_path)
    assert removed == 0


# ---- Full closure test: install → hooks → export → verify ----


def test_full_install_hooks_export_verify_roundtrip(
    isolated_paths: dict[str, Path], tmp_path: Path
) -> None:
    """The whole Phase 5 promise on one path:

    1. ``install`` sets up keychain, manifest, settings.
    2. We simulate three Claude Code hook firings via the hook entry point.
    3. ``build_bundle`` produces a bundle from the resulting session.
    4. ``verify`` accepts that bundle, no errors, three events verified.
    """
    install_result = install()

    # Simulate hook firings for a single Claude Code session.
    claude_session = "claude-session-roundtrip"
    payloads = [
        {
            "session_id": claude_session,
            "hook_event_name": "SessionStart",
            "source": "startup",
            "model": "claude-opus-4-7",
        },
        {
            "session_id": claude_session,
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/app.ts", "old_string": "x", "new_string": "y"},
            "tool_use_id": "tu-1",
        },
        {
            "session_id": claude_session,
            "hook_event_name": "PostToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/app.ts"},
            "tool_use_id": "tu-1",
            "tool_result": "patched",
        },
    ]
    for payload in payloads:
        rc = hook_main(stdin=io.StringIO(json.dumps(payload)))
        assert rc == 0

    # The hook derives a deterministic agentwitness session id.
    aw_sid = derive_agentwitness_session_id(claude_session)
    session_path = state_dir() / "sessions" / aw_sid
    assert (session_path / "events.jsonl").exists()
    assert (session_path / "signatures.jsonl").exists()

    # Assemble a bundle. We have the signing key in the keychain.
    signing_key = nacl.signing.SigningKey(keychain.load_seed("default"))
    manifest = json.loads(install_result.manifest_path.read_text())
    session = Session.open_or_create(session_path, session_id=aw_sid)
    bundle_path = build_bundle(
        session=session,
        manifest=manifest,
        signing_key=signing_key,
        out_dir=tmp_path / "bundle",
    )

    result = verify(bundle_path)
    assert result.ok, [(e.code, e.message) for e in result.errors]
    assert result.events_verified == 3
    assert len(result.sessions_seen) == 1


def test_install_cli_command_runs(isolated_paths: dict[str, Path], tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["install"])
    assert result.exit_code == 0, result.output
    assert "public key" in result.output
    assert "key_id" in result.output


def test_uninstall_cli_command_runs(isolated_paths: dict[str, Path]) -> None:
    install()
    runner = CliRunner()
    result = runner.invoke(cli, ["uninstall"])
    assert result.exit_code == 0, result.output
    assert "Removed" in result.output or "Restored" in result.output
