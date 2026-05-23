"""Hash-chain integrity walker.

Spec references:
- §6   hash chain
- §6.1 chain checkpoint
- §7.1 event_id derivation

The walker raises ``ChainError`` on the first inconsistency it finds within a
session. The verifier orchestrator (agentwitness.verify) decides whether to
continue verifying other sessions after a failure.
"""

from __future__ import annotations

from agentwitness.canonical import event_id as _event_id
from agentwitness.errors import ChainError
from agentwitness.types import RawEvent


def verify_event_id(event: RawEvent) -> str:
    """Recompute ``event_id`` per spec §7.1 and compare against the stored value.

    Returns the verified event_id on success. Raises ``ChainError`` with code
    ``event.missing_id`` if there's no id field, or
    ``chain.event_id_mismatch`` if the recomputed value disagrees with the
    stored one.
    """
    if "id" not in event:
        raise ChainError(
            code="event.missing_id",
            message="event has no id field",
            context={"seq": event.get("seq"), "kind": event.get("kind")},
        )
    stored: str = event["id"]
    recomputed = _event_id(event)
    if stored != recomputed:
        raise ChainError(
            code="chain.event_id_mismatch",
            message="event_id does not match recomputed canonical hash",
            context={
                "stored": stored,
                "recomputed": recomputed,
                "seq": event.get("seq"),
                "kind": event.get("kind"),
            },
        )
    return stored


def walk_session(events: list[RawEvent]) -> list[str]:
    """Walk a session's events in order, verifying chain integrity.

    Returns the list of verified event_ids in order.

    Raises ``ChainError`` on:
    - ``chain.empty_session``: events is empty
    - ``chain.seq_mismatch``: seq is not strictly increasing from 0
    - ``chain.prev_mismatch``: event.prev doesn't match the previous event's id
    - ``chain.event_id_mismatch``: stored id doesn't match recomputed value
    """
    if not events:
        raise ChainError(
            code="chain.empty_session",
            message="cannot walk an empty event list",
            context={},
        )

    verified_ids: list[str] = []
    expected_prev: str | None = None

    for i, event in enumerate(events):
        actual_seq = event.get("seq")
        if actual_seq != i:
            raise ChainError(
                code="chain.seq_mismatch",
                message=f"expected seq {i}, got {actual_seq!r}",
                context={"expected": i, "actual": actual_seq},
            )

        actual_prev = event.get("prev")
        if actual_prev != expected_prev:
            raise ChainError(
                code="chain.prev_mismatch",
                message=(f"event at seq {i} has prev={actual_prev!r}, expected {expected_prev!r}"),
                context={
                    "seq": i,
                    "expected_prev": expected_prev,
                    "actual_prev": actual_prev,
                },
            )

        verified_id = verify_event_id(event)
        verified_ids.append(verified_id)
        expected_prev = verified_id

    return verified_ids
