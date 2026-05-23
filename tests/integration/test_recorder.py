"""End-to-end integration: recorder produces bundles the verifier accepts.

This is the closure test for Phase 5 commit 5. A separate (later) commit
will extract the bundle-assembly helper into a proper module; for now it
lives inline in this test.
"""

from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path
from typing import Any

import nacl.signing
import pytest

from agentwitness import keychain, verify
from agentwitness.errors import KeyResolutionError
from agentwitness.keys import key_id_from_verify_key
from agentwitness.manifest import build_default_manifest
from agentwitness.recorder import Recorder
from agentwitness.signing import sign_chain
from agentwitness.state import ENV_OVERRIDE
from agentwitness.writer import Session


@pytest.fixture(autouse=True)
def in_memory_keyring() -> None:
    keychain._install_in_memory_backend()  # type: ignore[attr-defined]


def _make_event_body(
    *,
    kind: str,
    manifest_id: str,
    key_id: str,
    ts: str,
    tool: str | None = None,
    path: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "v": "agentwitness/0.1",
        "session": {"agentwitness_id": "sess_e2e_test_v0", "platform_id": "plat-1"},
        "ts": ts,
        "kind": kind,
        "agent": {
            "platform": "claude-code",
            "model": "claude-opus-4-7",
            "model_version": "claude-opus-4-7-20260101",
        },
        "actor": {"signer_key_id": key_id, "principal_key_id": key_id, "delegation": []},
        "scope_token": f"{manifest_id}:0",
        "outcome": {"status": "ok", "code": f"{kind}.ok", "message": ""},
    }
    if tool is not None:
        body["tool"] = tool
        body["inputs"] = {}
        body["outputs"] = {}
        body["resources"] = (
            [
                {
                    "type": "file",
                    "op": "write",
                    "path": path,
                    "before_hash": None,
                    "after_hash": None,
                }
            ]
            if path
            else []
        )
    return body


def _assemble_bundle(
    *,
    session: Session,
    manifest: dict[str, Any],
    signing_key: nacl.signing.SigningKey,
    out_dir: Path,
) -> Path:
    """Build a verifiable bundle from a session's outputs.

    The export-proper logic lands in a later commit. This helper exists so
    the recorder's outputs can be verified end-to-end *now*.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(session.events_path, out_dir / "events.jsonl")
    shutil.copy(session.signatures_path, out_dir / "signatures.jsonl")
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    events = [
        json.loads(line) for line in (out_dir / "events.jsonl").read_text().splitlines() if line
    ]
    chain: dict[str, Any] = {
        "v": "agentwitness/0.1",
        "sessions": [
            {
                "session_agentwitness_id": events[0]["session"]["agentwitness_id"],
                "first_event_id": events[0]["id"],
                "head_event_id": events[-1]["id"],
                "head_seq": events[-1]["seq"],
                "first_ts": events[0]["ts"],
                "last_ts": events[-1]["ts"],
                "manifest_ids": [manifest["id"]],
            }
        ],
    }
    chain_sig = sign_chain(chain, signing_key)
    chain["sig"] = base64.b64encode(chain_sig).decode()
    (out_dir / "chain.json").write_text(json.dumps(chain, indent=2, sort_keys=True) + "\n")
    return out_dir


def test_bootstrap_then_record_then_verify(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The full Phase 5 loop: install-like setup, record events, verify."""
    # Install-like setup: store a seed in the (mocked) keychain.
    seed = nacl.signing.SigningKey.generate().encode()
    keychain.store_seed("default", seed)
    signing_key = nacl.signing.SigningKey(seed)
    kid = key_id_from_verify_key(signing_key.verify_key)

    # Point state at a tmpdir so the recorder writes there.
    state_root = tmp_path / "state"
    monkeypatch.setenv(ENV_OVERRIDE, str(state_root))

    # Build a self-signed default manifest.
    manifest = build_default_manifest(
        signing_key=signing_key,
        key_id=kid,
        issued_at="2026-05-23T00:00:00.000Z",
        expires_at="2027-05-23T00:00:00.000Z",
    )

    # Bootstrap the recorder via the production path (keychain + state dir).
    recorder = Recorder.bootstrap(session_id="sess_e2e_test_v0", platform_id="plat-1")
    assert recorder.key_id == kid

    # Record three events: session.start → tool.requested → tool.completed.
    recorder.record(
        _make_event_body(
            kind="session.start",
            manifest_id=manifest["id"],
            key_id=kid,
            ts="2026-05-23T14:00:00.000Z",
        )
    )
    recorder.record(
        _make_event_body(
            kind="tool.requested",
            manifest_id=manifest["id"],
            key_id=kid,
            ts="2026-05-23T14:00:01.000Z",
            tool="Edit",
            path="src/app.ts",
        )
    )
    recorder.record(
        _make_event_body(
            kind="tool.completed",
            manifest_id=manifest["id"],
            key_id=kid,
            ts="2026-05-23T14:00:02.000Z",
            tool="Edit",
            path="src/app.ts",
        )
    )

    # Assemble a bundle and verify it.
    bundle_path = _assemble_bundle(
        session=recorder.session,
        manifest=manifest,
        signing_key=signing_key,
        out_dir=tmp_path / "bundle",
    )
    result = verify(bundle_path)
    assert result.ok, [(e.code, e.message) for e in result.errors]
    assert result.events_verified == 3


def test_bootstrap_raises_when_no_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Bootstrap before `agentwitness install` should explain why it fails."""
    monkeypatch.setenv(ENV_OVERRIDE, str(tmp_path))
    with pytest.raises(KeyResolutionError) as exc_info:
        Recorder.bootstrap(session_id="sess_x")
    assert exc_info.value.code == "keychain.label_not_found"


def test_from_session_and_key_bypass(tmp_path: Path) -> None:
    """The escape-hatch construction path skips keychain entirely."""
    signing_key = nacl.signing.SigningKey.generate()
    kid = key_id_from_verify_key(signing_key.verify_key)
    session = Session.open_or_create(tmp_path / "s", session_id="sess_x")
    recorder = Recorder.from_session_and_key(session, signing_key)
    assert recorder.key_id == kid
