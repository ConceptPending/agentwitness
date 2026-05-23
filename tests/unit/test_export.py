"""Tests for agentwitness.export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import nacl.signing
import pytest

from agentwitness.errors import BundleError
from agentwitness.export import build_bundle
from agentwitness.keys import key_id_from_verify_key
from agentwitness.manifest import build_default_manifest
from agentwitness.recorder import Recorder
from agentwitness.writer import Session


def _record_a_session_start(recorder: Recorder, manifest: dict[str, Any]) -> None:
    body = {
        "v": "agentwitness/0.1",
        "session": {"agentwitness_id": "sess_unit_test_export", "platform_id": None},
        "ts": "2026-05-23T14:00:00.000Z",
        "kind": "session.start",
        "agent": {"platform": "test", "model": "x", "model_version": "y"},
        "actor": {
            "signer_key_id": recorder.key_id,
            "principal_key_id": recorder.key_id,
            "delegation": [],
        },
        "scope_token": f"{manifest['id']}:0",
        "outcome": {"status": "ok", "code": "session.started", "message": "x"},
    }
    recorder.record(body)


def test_build_bundle_writes_expected_files(tmp_path: Path) -> None:
    signing_key = nacl.signing.SigningKey.generate()
    kid = key_id_from_verify_key(signing_key.verify_key)
    manifest = build_default_manifest(
        signing_key=signing_key,
        key_id=kid,
        issued_at="2026-05-23T00:00:00.000Z",
        expires_at="2027-05-23T00:00:00.000Z",
    )

    session = Session.open_or_create(tmp_path / "s", session_id="sess_unit_test_export")
    recorder = Recorder.from_session_and_key(session, signing_key)
    _record_a_session_start(recorder, manifest)

    out = build_bundle(
        session=session,
        manifest=manifest,
        signing_key=signing_key,
        out_dir=tmp_path / "bundle",
    )
    assert (out / "manifest.json").exists()
    assert (out / "events.jsonl").exists()
    assert (out / "signatures.jsonl").exists()
    assert (out / "chain.json").exists()

    chain = json.loads((out / "chain.json").read_text())
    assert "sig" in chain
    assert chain["sessions"][0]["head_seq"] == 0


def test_build_bundle_rejects_empty_session(tmp_path: Path) -> None:
    signing_key = nacl.signing.SigningKey.generate()
    kid = key_id_from_verify_key(signing_key.verify_key)
    manifest = build_default_manifest(
        signing_key=signing_key,
        key_id=kid,
        issued_at="2026-05-23T00:00:00.000Z",
        expires_at="2027-05-23T00:00:00.000Z",
    )
    session = Session.open_or_create(tmp_path / "s", session_id="sess_empty")
    # No events written. build_bundle MUST refuse to produce a bundle.
    with pytest.raises(BundleError) as exc_info:
        build_bundle(
            session=session,
            manifest=manifest,
            signing_key=signing_key,
            out_dir=tmp_path / "bundle",
        )
    assert exc_info.value.code == "export.empty_session"
