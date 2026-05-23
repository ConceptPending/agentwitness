"""Integration tests: drive the verifier against the three Phase 2 fixtures.

This is the Phase 3 acceptance criterion. The verifier MUST:

- accept the valid bundle
- reject the tampered bundle with chain.event_id_mismatch
- reject the out-of-scope bundle with scope.unauthorised_completion

If any of these change, either the spec or the verifier is wrong; do not
patch the test silently.
"""

from __future__ import annotations

from pathlib import Path

from agentwitness import verify


def test_valid_bundle_accepted(valid_bundle: Path) -> None:
    result = verify(valid_bundle)
    assert result.ok, f"unexpected errors: {[(e.code, e.message) for e in result.errors]}"
    assert result.events_verified == 3
    assert len(result.sessions_seen) == 1


def test_tampered_bundle_rejected(tampered_bundle: Path) -> None:
    result = verify(tampered_bundle)
    assert not result.ok
    codes = [e.code for e in result.errors]
    assert "chain.event_id_mismatch" in codes


def test_out_of_scope_bundle_rejected(out_of_scope_bundle: Path) -> None:
    result = verify(out_of_scope_bundle)
    assert not result.ok
    codes = [e.code for e in result.errors]
    assert "scope.unauthorised_completion" in codes


def test_to_dict_is_json_serialisable(valid_bundle: Path) -> None:
    import json

    result = verify(valid_bundle)
    rendered = json.dumps(result.to_dict())
    parsed = json.loads(rendered)
    assert parsed["ok"] is True
    assert parsed["events_verified"] == 3
