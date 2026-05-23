"""Tests for agentwitness.chain.

Properties:

1. A freshly built valid chain walks cleanly.
2. Mutating any field of any event in a valid chain causes a chain error.
3. Swapping the prev pointer or seq field of any event causes a chain error.

Example tests cover the empty case and bad first-event prev.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentwitness.canonical import event_id
from agentwitness.chain import verify_event_id, walk_session
from agentwitness.errors import ChainError


def _minimal_event_body(seq: int, prev: str | None) -> dict[str, Any]:
    """A minimal valid-shape event body. id is added by the caller."""
    return {
        "v": "agentwitness/0.1",
        "prev": prev,
        "seq": seq,
        "ts": "2026-05-23T14:00:00.000Z",
        "kind": "session.start",
        "session": {"agentwitness_id": "sess_x", "platform_id": None},
        "agent": {"platform": "claude-code", "model": "x", "model_version": "y"},
        "actor": {"signer_key_id": "k", "principal_key_id": "k", "delegation": []},
        "scope_token": "m:0",
        "outcome": {"status": "ok", "code": "x", "message": "y"},
    }


def _build_chain(length: int, payloads: list[str] | None = None) -> list[dict[str, Any]]:
    """Build a length-N valid chain. Each event carries an optional payload
    field so we can vary content per event."""
    events: list[dict[str, Any]] = []
    prev: str | None = None
    for i in range(length):
        body = _minimal_event_body(i, prev)
        if payloads is not None:
            body["payload"] = payloads[i]
        body["id"] = event_id(body)
        events.append(body)
        prev = body["id"]
    return events


@given(st.integers(min_value=1, max_value=10))
def test_valid_chain_walks_cleanly(length: int) -> None:
    chain = _build_chain(length)
    verified = walk_session(chain)
    assert len(verified) == length
    assert verified == [event["id"] for event in chain]


@given(
    length=st.integers(min_value=2, max_value=6),
    target=st.integers(min_value=0, max_value=5),
)
def test_payload_mutation_anywhere_breaks(length: int, target: int) -> None:
    target_index = target % length
    payloads = [f"orig-{i}" for i in range(length)]
    chain = _build_chain(length, payloads=payloads)
    # Mutate the target event's payload without updating id.
    chain[target_index]["payload"] = "MUTATED"
    with pytest.raises(ChainError) as exc_info:
        walk_session(chain)
    # The first failure may be at the target (event_id_mismatch) or at a later
    # event (prev_mismatch) depending on which check runs first. Either way,
    # the chain is rejected.
    assert exc_info.value.code in {"chain.event_id_mismatch", "chain.prev_mismatch"}


@given(
    length=st.integers(min_value=2, max_value=6),
    target=st.integers(min_value=1, max_value=5),
)
def test_prev_pointer_corruption_breaks(length: int, target: int) -> None:
    target_index = target % length
    if target_index == 0:
        target_index = 1  # don't pick the genesis event
    chain = _build_chain(length)
    chain[target_index]["prev"] = "deadbeef" * 8  # 64 hex chars but wrong value
    with pytest.raises(ChainError) as exc_info:
        walk_session(chain)
    # The walker checks `prev` against the previous verified id before
    # re-deriving the current id, so the failure is `prev_mismatch`. If the
    # walker ever reorders these checks, `event_id_mismatch` would be the
    # alternative outcome (the stored id no longer matches the body with
    # the swapped prev). Either outcome is correct rejection.
    assert exc_info.value.code in {"chain.prev_mismatch", "chain.event_id_mismatch"}


def test_empty_session_rejected() -> None:
    with pytest.raises(ChainError) as exc_info:
        walk_session([])
    assert exc_info.value.code == "chain.empty_session"


def test_first_event_must_have_null_prev() -> None:
    body = _minimal_event_body(0, "some-fake-prev")
    body["id"] = event_id(body)
    with pytest.raises(ChainError) as exc_info:
        walk_session([body])
    assert exc_info.value.code == "chain.prev_mismatch"


def test_seq_must_start_at_zero() -> None:
    body = _minimal_event_body(7, None)
    body["id"] = event_id(body)
    with pytest.raises(ChainError) as exc_info:
        walk_session([body])
    assert exc_info.value.code == "chain.seq_mismatch"


def test_verify_event_id_rejects_missing_id() -> None:
    body = _minimal_event_body(0, None)
    # no id field set
    with pytest.raises(ChainError) as exc_info:
        verify_event_id(body)
    assert exc_info.value.code == "event.missing_id"
