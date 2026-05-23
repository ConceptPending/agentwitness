"""Tests for the Claude Code hook entry point.

Covers payload-to-event mapping for each hook event we care about,
plus an end-to-end test that drives the hook entry point against a
real Recorder writing into a tmpdir.
"""

from __future__ import annotations

import io
import json
import re
from pathlib import Path
from typing import Any

import nacl.signing
import pytest

from agentwitness import keychain
from agentwitness.hook import (
    build_event_body,
    derive_agentwitness_session_id,
)
from agentwitness.hook import (
    main as hook_main,
)
from agentwitness.keys import key_id_from_verify_key
from agentwitness.manifest import build_default_manifest
from agentwitness.state import ENV_OVERRIDE, state_dir


@pytest.fixture(autouse=True)
def in_memory_keyring() -> None:
    keychain._install_in_memory_backend()  # type: ignore[attr-defined]


@pytest.fixture
def installed_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Simulate what `agentwitness install` will set up: state dir, manifest, keychain seed.

    Returns a dict with the manifest, signing key, and key_id for use in
    the test body.
    """
    monkeypatch.setenv(ENV_OVERRIDE, str(tmp_path / "state"))
    state_dir().mkdir(parents=True, exist_ok=True)

    signing_key = nacl.signing.SigningKey.generate()
    kid = key_id_from_verify_key(signing_key.verify_key)
    keychain.store_seed("default", bytes(signing_key))

    manifest = build_default_manifest(
        signing_key=signing_key,
        key_id=kid,
        issued_at="2026-05-23T00:00:00.000Z",
        expires_at="2027-05-23T00:00:00.000Z",
    )
    (state_dir() / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )

    return {"manifest": manifest, "signing_key": signing_key, "key_id": kid}


# ---- derive_agentwitness_session_id ----


def test_derive_session_id_format() -> None:
    sid = derive_agentwitness_session_id("anything")
    assert sid.startswith("sess_")
    assert len(sid) == 5 + 22
    assert re.match(r"^sess_[0-9a-f]{22}$", sid)


def test_derive_session_id_is_deterministic() -> None:
    a = derive_agentwitness_session_id("abc123")
    b = derive_agentwitness_session_id("abc123")
    c = derive_agentwitness_session_id("different")
    assert a == b
    assert a != c


# ---- build_event_body unit tests ----


def test_pretooluse_payload_produces_tool_requested_event(
    installed_environment: dict[str, Any],
) -> None:
    payload = {
        "session_id": "abc123",
        "transcript_path": "/x",
        "cwd": "/y",
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "src/app.ts",
            "old_string": "a",
            "new_string": "b",
        },
        "tool_use_id": "tu-1",
    }
    body = build_event_body(
        payload, manifest=installed_environment["manifest"], key_id=installed_environment["key_id"]
    )
    assert body is not None
    assert body["kind"] == "tool.requested"
    assert body["tool"] == "Edit"
    assert body["request_id"] == "tu-1"
    assert body["resources"] == [
        {
            "type": "file",
            "op": "write",
            "path": "src/app.ts",
            "before_hash": None,
            "after_hash": None,
        }
    ]


def test_posttooluse_payload_produces_tool_completed_event(
    installed_environment: dict[str, Any],
) -> None:
    payload = {
        "session_id": "abc123",
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "src/app.ts"},
        "tool_use_id": "tu-1",
        "tool_result": "...",
    }
    body = build_event_body(
        payload, manifest=installed_environment["manifest"], key_id=installed_environment["key_id"]
    )
    assert body is not None
    assert body["kind"] == "tool.completed"
    assert body["resources"][0]["op"] == "read"


def test_posttooluse_failure_produces_tool_failed_event(
    installed_environment: dict[str, Any],
) -> None:
    payload = {
        "session_id": "abc123",
        "hook_event_name": "PostToolUseFailure",
        "tool_name": "Bash",
        "tool_input": {"command": "false"},
        "tool_use_id": "tu-2",
        "error": "command failed with exit 1",
    }
    body = build_event_body(
        payload, manifest=installed_environment["manifest"], key_id=installed_environment["key_id"]
    )
    assert body is not None
    assert body["kind"] == "tool.failed"
    assert body["outcome"]["status"] == "error"
    assert "exit 1" in body["outcome"]["message"]


def test_userpromptsubmit_payload_produces_user_prompt_event(
    installed_environment: dict[str, Any],
) -> None:
    payload = {
        "session_id": "abc123",
        "hook_event_name": "UserPromptSubmit",
        "prompt": "write a function",
    }
    body = build_event_body(
        payload, manifest=installed_environment["manifest"], key_id=installed_environment["key_id"]
    )
    assert body is not None
    assert body["kind"] == "user.prompt"
    # The prompt content itself is not stored — only metadata. Spec §5.3
    # privacy stance: hashed-only by default for content fields, and we
    # don't record the prompt verbatim at all.
    assert "prompt" not in body
    # Tool-only fields MUST be absent for non-tool kinds (spec §5).
    for forbidden in ("tool", "inputs", "outputs", "resources", "request_id"):
        assert forbidden not in body


def test_sessionstart_payload_produces_session_start_event(
    installed_environment: dict[str, Any],
) -> None:
    payload = {
        "session_id": "abc123",
        "hook_event_name": "SessionStart",
        "source": "startup",
        "model": "claude-opus-4-7",
    }
    body = build_event_body(
        payload, manifest=installed_environment["manifest"], key_id=installed_environment["key_id"]
    )
    assert body is not None
    assert body["kind"] == "session.start"
    assert body["agent"]["model"] == "claude-opus-4-7"
    assert "startup" in body["outcome"]["message"]


def test_unknown_hook_event_returns_none(
    installed_environment: dict[str, Any],
) -> None:
    """Unknown hook names are no-ops, not errors. v0.1 doesn't record everything."""
    payload = {"session_id": "abc123", "hook_event_name": "Notification", "message": "..."}
    body = build_event_body(
        payload, manifest=installed_environment["manifest"], key_id=installed_environment["key_id"]
    )
    assert body is None


def test_missing_session_id_returns_none(
    installed_environment: dict[str, Any],
) -> None:
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit", "tool_input": {}}
    body = build_event_body(
        payload, manifest=installed_environment["manifest"], key_id=installed_environment["key_id"]
    )
    assert body is None


# ---- main() end-to-end ----


def test_main_records_event_to_session_directory(
    installed_environment: dict[str, Any],
) -> None:
    payload = {
        "session_id": "claude-session-xyz",
        "hook_event_name": "SessionStart",
        "source": "startup",
        "model": "claude-opus-4-7",
    }
    stdin = io.StringIO(json.dumps(payload))
    rc = hook_main(stdin=stdin)
    assert rc == 0

    aw_sid = derive_agentwitness_session_id("claude-session-xyz")
    session_dir = state_dir() / "sessions" / aw_sid
    assert (session_dir / "events.jsonl").exists()
    assert (session_dir / "signatures.jsonl").exists()
    lines = (session_dir / "events.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1
    recorded = json.loads(lines[0])
    assert recorded["kind"] == "session.start"
    assert recorded["session"]["platform_id"] == "claude-session-xyz"


def test_main_returns_zero_on_malformed_json(
    installed_environment: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    stdin = io.StringIO("not json at all {{{")
    rc = hook_main(stdin=stdin)
    assert rc == 0  # never block
    err = capsys.readouterr().err
    assert "agentwitness" in err


def test_main_returns_zero_when_manifest_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Hook before install runs gracefully — logs to stderr, exits 0."""
    monkeypatch.setenv(ENV_OVERRIDE, str(tmp_path / "state"))
    stdin = io.StringIO(json.dumps({"session_id": "x", "hook_event_name": "SessionStart"}))
    rc = hook_main(stdin=stdin)
    assert rc == 0
    err = capsys.readouterr().err
    assert "manifest not found" in err


def test_main_handles_unknown_event_silently(
    installed_environment: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    payload = {"session_id": "x", "hook_event_name": "Notification", "message": "..."}
    stdin = io.StringIO(json.dumps(payload))
    rc = hook_main(stdin=stdin)
    assert rc == 0
    # No event was recorded; no error logged either.
    err = capsys.readouterr().err
    assert err == ""


# ---- path normalisation (spec §3.4) ----


def test_path_normalised_relative_to_cwd(installed_environment: dict[str, Any]) -> None:
    """An absolute file_path under cwd becomes repo-relative in the event."""
    payload = {
        "session_id": "abc",
        "cwd": "/Users/nick",
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "/Users/nick/lorem.md", "content": "x"},
        "tool_use_id": "tu-1",
    }
    body = build_event_body(
        payload,
        manifest=installed_environment["manifest"],
        key_id=installed_environment["key_id"],
    )
    assert body is not None
    assert body["resources"][0]["path"] == "lorem.md"


def test_path_outside_cwd_stays_absolute(installed_environment: dict[str, Any]) -> None:
    """A file outside the project root is recorded with its absolute path."""
    payload = {
        "session_id": "abc",
        "cwd": "/Users/nick/proj",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/etc/hosts"},
        "tool_use_id": "tu-1",
    }
    body = build_event_body(
        payload,
        manifest=installed_environment["manifest"],
        key_id=installed_environment["key_id"],
    )
    assert body is not None
    assert body["resources"][0]["path"] == "/etc/hosts"


def test_path_without_cwd_in_payload_stays_unchanged(
    installed_environment: dict[str, Any],
) -> None:
    """If the payload has no cwd we have no project root, so paths stay verbatim."""
    payload = {
        "session_id": "abc",
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "/Users/nick/lorem.md", "content": "x"},
        "tool_use_id": "tu-1",
    }
    body = build_event_body(
        payload,
        manifest=installed_environment["manifest"],
        key_id=installed_environment["key_id"],
    )
    assert body is not None
    assert body["resources"][0]["path"] == "/Users/nick/lorem.md"


def test_normalise_path_helper_edge_cases() -> None:
    from agentwitness.hook import _normalise_path

    # Inside cwd → relative
    assert _normalise_path("/proj/src/app.ts", "/proj") == "src/app.ts"
    # Cwd with trailing slash → still works
    assert _normalise_path("/proj/src/app.ts", "/proj/") == "src/app.ts"
    # Path equal to cwd → keep as-is (edge case)
    assert _normalise_path("/proj", "/proj") == "/proj"
    # Path is a sibling that shares a prefix → must NOT be treated as relative
    assert _normalise_path("/projXY/src/app.ts", "/proj") == "/projXY/src/app.ts"
    # Empty cwd → no-op
    assert _normalise_path("/Users/nick/lorem.md", "") == "/Users/nick/lorem.md"
    assert _normalise_path("/Users/nick/lorem.md", None) == "/Users/nick/lorem.md"
