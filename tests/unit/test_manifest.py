"""Tests for agentwitness.manifest.

Property tests for manifest signing/verification and scope-evaluation
determinism. Example tests cover specific scope rules.
"""

from __future__ import annotations

import base64
from typing import Any

import nacl.signing
import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentwitness.canonical import manifest_id, manifest_signing_bytes
from agentwitness.errors import ManifestError, ScopeError
from agentwitness.keys import key_id_from_verify_key
from agentwitness.manifest import (
    evaluate_event_scope,
    verify_manifest_id,
    verify_manifest_signature,
)

# ---- Builder helpers ----


def _build_signed_manifest(
    sk: nacl.signing.SigningKey,
    *,
    allow_tools: list[str] | None = None,
    deny_tools: list[str] | None = None,
    allow_paths: list[str] | None = None,
    deny_paths: list[str] | None = None,
    issued_at: str = "2026-05-23T00:00:00.000Z",
    expires_at: str = "2026-12-31T23:59:59.999Z",
) -> dict[str, Any]:
    pk = sk.verify_key
    kid = key_id_from_verify_key(pk)
    body: dict[str, Any] = {
        "v": "agentwitness/0.1",
        "issued_at": issued_at,
        "expires_at": expires_at,
        "issuer": kid,
        "project": {"name": "test", "root_hash": None},
        "principals": [
            {
                "key_id": kid,
                "label": "test-key",
                "public_key": base64.b64encode(bytes(pk)).decode(),
                "scopes": [
                    {
                        "allow_tools": allow_tools or ["Edit"],
                        "deny_tools": deny_tools or [],
                        "allow_paths": allow_paths or ["src/**"],
                        "deny_paths": deny_paths or [],
                        "allow_delegates": [],
                    }
                ],
            }
        ],
    }
    body["id"] = manifest_id(body)
    sig = sk.sign(manifest_signing_bytes(body)).signature
    body["sig"] = base64.b64encode(sig).decode()
    return body


def _tool_event(
    *,
    manifest: dict[str, Any],
    tool: str,
    path: str,
    kind: str = "tool.completed",
    ts: str = "2026-05-23T14:00:00.000Z",
) -> dict[str, Any]:
    kid = manifest["issuer"]
    return {
        "v": "agentwitness/0.1",
        "id": "deadbeef" * 8,
        "prev": None,
        "session": {"agentwitness_id": "sess_x", "platform_id": None},
        "seq": 0,
        "ts": ts,
        "kind": kind,
        "agent": {"platform": "claude-code", "model": "x", "model_version": "y"},
        "actor": {"signer_key_id": kid, "principal_key_id": kid, "delegation": []},
        "scope_token": f"{manifest['id']}:0",
        "tool": tool,
        "resources": [
            {"type": "file", "op": "write", "path": path, "before_hash": None, "after_hash": None}
        ],
        "outcome": {"status": "ok", "code": "x", "message": "y"},
    }


# ---- Manifest id / signature ----


def test_manifest_id_recompute_matches() -> None:
    sk = nacl.signing.SigningKey.generate()
    m = _build_signed_manifest(sk)
    assert verify_manifest_id(m) == m["id"]


def test_manifest_id_mismatch_rejected() -> None:
    sk = nacl.signing.SigningKey.generate()
    m = _build_signed_manifest(sk)
    m["id"] = "deadbeef" * 8
    with pytest.raises(ManifestError) as exc_info:
        verify_manifest_id(m)
    assert exc_info.value.code == "manifest.id_mismatch"


def test_manifest_signature_verifies() -> None:
    sk = nacl.signing.SigningKey.generate()
    m = _build_signed_manifest(sk)
    verify_manifest_signature(m)  # no error


def test_manifest_signature_mutation_detected() -> None:
    sk = nacl.signing.SigningKey.generate()
    m = _build_signed_manifest(sk)
    m["expires_at"] = "2099-12-31T23:59:59.999Z"  # tamper after signing
    # Note: this will also change the manifest_id if we recomputed it; but
    # the sig was over the original body so it must fail under the new body.
    with pytest.raises(ManifestError) as exc_info:
        verify_manifest_signature(m)
    assert exc_info.value.code == "manifest.signature_invalid"


def test_manifest_missing_sig_rejected() -> None:
    sk = nacl.signing.SigningKey.generate()
    m = _build_signed_manifest(sk)
    del m["sig"]
    with pytest.raises(ManifestError) as exc_info:
        verify_manifest_signature(m)
    assert exc_info.value.code == "manifest.missing_sig"


def test_manifest_issuer_not_in_principals_rejected() -> None:
    sk = nacl.signing.SigningKey.generate()
    m = _build_signed_manifest(sk)
    m["issuer"] = "0" * 64  # claim a different issuer
    with pytest.raises(ManifestError) as exc_info:
        verify_manifest_signature(m)
    assert exc_info.value.code == "manifest.issuer_not_in_principals"


# ---- Scope evaluation ----


def test_non_tool_event_always_passes_scope() -> None:
    sk = nacl.signing.SigningKey.generate()
    m = _build_signed_manifest(sk, allow_tools=[])  # nothing allowed
    event = {
        "kind": "session.start",
        "ts": "2026-05-23T14:00:00.000Z",
        "scope_token": f"{m['id']}:0",
    }
    assert evaluate_event_scope(event, m) is True


def test_allowed_tool_and_path_passes() -> None:
    sk = nacl.signing.SigningKey.generate()
    m = _build_signed_manifest(sk, allow_tools=["Edit"], allow_paths=["src/**"])
    event = _tool_event(manifest=m, tool="Edit", path="src/app.ts")
    assert evaluate_event_scope(event, m) is True


def test_disallowed_tool_fails() -> None:
    sk = nacl.signing.SigningKey.generate()
    m = _build_signed_manifest(sk, allow_tools=["Read"])
    event = _tool_event(manifest=m, tool="Edit", path="src/app.ts")
    assert evaluate_event_scope(event, m) is False


def test_disallowed_path_fails() -> None:
    sk = nacl.signing.SigningKey.generate()
    m = _build_signed_manifest(sk, allow_paths=["src/**"])
    event = _tool_event(manifest=m, tool="Edit", path="other/app.ts")
    assert evaluate_event_scope(event, m) is False


def test_deny_overrides_allow_for_tools() -> None:
    sk = nacl.signing.SigningKey.generate()
    m = _build_signed_manifest(sk, allow_tools=["Bash:*"], deny_tools=["Bash:terraform*"])
    permitted = _tool_event(manifest=m, tool="Bash:pytest", path="src/app.ts")
    denied = _tool_event(manifest=m, tool="Bash:terraform-apply", path="src/app.ts")
    assert evaluate_event_scope(permitted, m) is True
    assert evaluate_event_scope(denied, m) is False


def test_expired_manifest_denies() -> None:
    sk = nacl.signing.SigningKey.generate()
    m = _build_signed_manifest(
        sk,
        issued_at="2020-01-01T00:00:00.000Z",
        expires_at="2020-01-02T00:00:00.000Z",
    )
    event = _tool_event(manifest=m, tool="Edit", path="src/app.ts", ts="2026-05-23T14:00:00.000Z")
    assert evaluate_event_scope(event, m) is False


def test_scope_token_with_wrong_manifest_id_raises() -> None:
    sk = nacl.signing.SigningKey.generate()
    m = _build_signed_manifest(sk)
    event = _tool_event(manifest=m, tool="Edit", path="src/app.ts")
    event["scope_token"] = "deadbeef" * 8 + ":0"
    with pytest.raises(ScopeError) as exc_info:
        evaluate_event_scope(event, m)
    assert exc_info.value.code == "scope.manifest_mismatch"


def test_scope_token_principal_out_of_range_raises() -> None:
    sk = nacl.signing.SigningKey.generate()
    m = _build_signed_manifest(sk)
    event = _tool_event(manifest=m, tool="Edit", path="src/app.ts")
    event["scope_token"] = f"{m['id']}:42"
    with pytest.raises(ScopeError) as exc_info:
        evaluate_event_scope(event, m)
    assert exc_info.value.code == "scope.principal_out_of_range"


# ---- Hypothesis properties ----


@given(seed=st.binary(min_size=32, max_size=32))
def test_random_manifest_round_trips(seed: bytes) -> None:
    sk = nacl.signing.SigningKey(seed)
    m = _build_signed_manifest(sk)
    verify_manifest_id(m)
    verify_manifest_signature(m)


@given(
    seed=st.binary(min_size=32, max_size=32),
    extra_tool=st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu")), min_size=1, max_size=10
    ),
)
def test_scope_evaluation_deterministic(seed: bytes, extra_tool: str) -> None:
    """The same (manifest, event) always evaluates to the same answer."""
    sk = nacl.signing.SigningKey(seed)
    m = _build_signed_manifest(sk, allow_tools=[extra_tool])
    event = _tool_event(manifest=m, tool=extra_tool, path="src/app.ts")
    assert evaluate_event_scope(event, m) == evaluate_event_scope(event, m)


def test_event_with_disallowed_resource_denied_even_if_tool_allowed() -> None:
    """Catches a regression: if the tool matches but a path is disallowed,
    the action must be denied — not skipped via short-circuit."""
    sk = nacl.signing.SigningKey.generate()
    m = _build_signed_manifest(
        sk,
        allow_tools=["Edit"],
        allow_paths=["src/**"],
        deny_paths=["**/secrets/**"],
    )
    event = _tool_event(manifest=m, tool="Edit", path="src/secrets/key")
    assert evaluate_event_scope(event, m) is False
