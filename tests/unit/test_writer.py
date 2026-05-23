"""Tests for agentwitness.writer.

Property: any sequence of appends produces a chain that walk_session
accepts. Plus example tests for the explicit failure modes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentwitness.chain import walk_session
from agentwitness.errors import WriterError
from agentwitness.writer import Session


def _minimal_body(*, kind: str = "session.start") -> dict[str, Any]:
    """A minimum-shape event body with no chain fields."""
    return {
        "v": "agentwitness/0.1",
        "session": {"agentwitness_id": "sess_test", "platform_id": None},
        "ts": "2026-05-23T14:00:00.000Z",
        "kind": kind,
        "agent": {"platform": "claude-code", "model": "x", "model_version": "y"},
        "actor": {"signer_key_id": "k", "principal_key_id": "k", "delegation": []},
        "scope_token": "m:0",
        "outcome": {"status": "ok", "code": "x", "message": "y"},
    }


def test_fresh_session_first_event_has_null_prev_and_seq_zero(tmp_path: Path) -> None:
    session = Session.open_or_create(tmp_path / "s", session_id="sess_test")
    event = session.append(_minimal_body())
    assert event["prev"] is None
    assert event["seq"] == 0
    assert len(event["id"]) == 64


def test_append_chains_to_previous_head(tmp_path: Path) -> None:
    session = Session.open_or_create(tmp_path / "s", session_id="sess_test")
    e0 = session.append(_minimal_body())
    e1 = session.append(_minimal_body(kind="user.prompt"))
    assert e1["prev"] == e0["id"]
    assert e1["seq"] == 1


def test_writer_output_walks_cleanly(tmp_path: Path) -> None:
    session = Session.open_or_create(tmp_path / "s", session_id="sess_test")
    a = session.append(_minimal_body())
    b = session.append(_minimal_body(kind="user.prompt"))
    c = session.append(_minimal_body(kind="session.end"))
    verified = walk_session([a, b, c])
    assert verified == [a["id"], b["id"], c["id"]]


@given(length=st.integers(min_value=1, max_value=10))
def test_property_any_append_sequence_walks_cleanly(
    length: int, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """For any 1-10 appends, the resulting events.jsonl walks under walk_session."""
    session_path = tmp_path_factory.mktemp("s")
    session = Session.open_or_create(session_path, session_id="sess_test")
    events = [session.append(_minimal_body(kind="user.prompt")) for _ in range(length)]
    walk_session(events)


def test_body_with_id_rejected(tmp_path: Path) -> None:
    session = Session.open_or_create(tmp_path / "s", session_id="sess_test")
    body = _minimal_body()
    body["id"] = "deadbeef" * 8
    with pytest.raises(WriterError) as exc_info:
        session.append(body)
    assert exc_info.value.code == "writer.body_carries_chain_field"


def test_body_with_prev_rejected(tmp_path: Path) -> None:
    session = Session.open_or_create(tmp_path / "s", session_id="sess_test")
    body = _minimal_body()
    body["prev"] = None
    with pytest.raises(WriterError) as exc_info:
        session.append(body)
    assert exc_info.value.code == "writer.body_carries_chain_field"


def test_body_with_seq_rejected(tmp_path: Path) -> None:
    session = Session.open_or_create(tmp_path / "s", session_id="sess_test")
    body = _minimal_body()
    body["seq"] = 0
    with pytest.raises(WriterError) as exc_info:
        session.append(body)
    assert exc_info.value.code == "writer.body_carries_chain_field"


def test_corrupt_head_rejected(tmp_path: Path) -> None:
    session_path = tmp_path / "s"
    session_path.mkdir()
    (session_path / "head.json").write_text("{not json")
    session = Session.open_or_create(session_path, session_id="sess_test")
    with pytest.raises(WriterError) as exc_info:
        session.append(_minimal_body())
    assert exc_info.value.code == "writer.corrupt_head"


def test_head_file_updated_after_append(tmp_path: Path) -> None:
    session = Session.open_or_create(tmp_path / "s", session_id="sess_test")
    event = session.append(_minimal_body())
    head_data = json.loads((session.head_path).read_text())
    assert head_data["event_id"] == event["id"]
    assert head_data["seq"] == 0


def test_events_appended_to_jsonl(tmp_path: Path) -> None:
    session = Session.open_or_create(tmp_path / "s", session_id="sess_test")
    a = session.append(_minimal_body())
    b = session.append(_minimal_body(kind="user.prompt"))
    lines = (session.events_path).read_text().strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["id"] == a["id"]
    assert json.loads(lines[1])["id"] == b["id"]


def test_concurrent_write_rejected(tmp_path: Path) -> None:
    """Two processes can't both hold the writer lock at once."""
    import fcntl

    session_path = tmp_path / "s"
    session = Session.open_or_create(session_path, session_id="sess_test")
    # Pre-write one event so the lock file exists.
    session.append(_minimal_body())

    # Now hold the lock from outside the writer and try to append again.
    lock_path = session.lock_path
    with open(lock_path, "r+") as outside_holder:
        fcntl.flock(outside_holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(WriterError) as exc_info:
            session.append(_minimal_body(kind="user.prompt"))
        assert exc_info.value.code == "writer.concurrent_write"
