"""Append-only event writer with chain head tracking.

Spec references:
- §5   event format
- §6   hash chain
- §7.1 event_id derivation

The writer composes each event from a body provided by the caller plus
chain-derived fields (``prev``, ``seq``) and an ``id`` computed from the
canonical bytes. It appends to ``events.jsonl`` and updates a sidecar
``head.json`` pointer atomically per event, using ``fcntl`` advisory
locking to prevent concurrent writers within the same session from
corrupting the chain.

This module is signing-agnostic. The Phase 5 recorder wraps this writer
and also produces ``signatures.jsonl`` alongside.

POSIX only in v0.1; Windows support pending a cross-platform lock.
"""

from __future__ import annotations

import fcntl
import json
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentwitness.canonical import event_id, event_signing_bytes
from agentwitness.errors import WriterError
from agentwitness.types import RawEvent, RawSignature

# Fields the writer assigns. A caller-supplied body must not include any of
# these; the writer will reject the body if it does.
_CHAIN_FIELDS = frozenset({"prev", "seq", "id"})

# A signer callback takes the new event's id and canonical signing-input bytes,
# and returns a complete signature object dict (event_id, key_id, alg, sig).
# The writer does not interpret the signature internals; it just appends the
# returned dict to signatures.jsonl alongside the event.
SignerCallback = Callable[[str, bytes], RawSignature]


@dataclass(frozen=True)
class ChainHead:
    """Snapshot of the current chain head for a session."""

    event_id: str | None  # None when no events have been written
    seq: int  # -1 when empty; the first event's seq is 0
    ts: str | None  # the last event's timestamp, or None when empty


def _read_head(head_path: Path) -> ChainHead:
    if not head_path.exists():
        return ChainHead(event_id=None, seq=-1, ts=None)
    try:
        data = json.loads(head_path.read_text())
    except json.JSONDecodeError as exc:
        raise WriterError(
            code="writer.corrupt_head",
            message=f"head file {head_path.name} is not valid JSON",
            context={"path": str(head_path)},
        ) from exc
    return ChainHead(
        event_id=data.get("event_id"),
        seq=data.get("seq", -1),
        ts=data.get("ts"),
    )


def _write_head(head_path: Path, head: ChainHead) -> None:
    """Atomically replace head.json via tmp-file rename."""
    tmp = head_path.with_suffix(".json.tmp")
    payload = json.dumps(
        {"event_id": head.event_id, "seq": head.seq, "ts": head.ts},
        sort_keys=True,
        indent=2,
    )
    tmp.write_text(payload + "\n")
    tmp.replace(head_path)


@contextmanager
def _session_lock(lock_path: Path) -> Iterator[None]:
    """Acquire an exclusive advisory lock on ``lock_path``.

    Released automatically when the file handle closes (including on
    process exit), so a crashed writer does not leave a stale lock.
    """
    if sys.platform == "win32":
        raise WriterError(
            code="writer.unsupported_platform",
            message="agentwitness writer requires POSIX fcntl locking; Windows support is pending",
            context={"platform": sys.platform},
        )
    lock_path.touch(exist_ok=True)
    with open(lock_path, "r+") as fh:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise WriterError(
                code="writer.concurrent_write",
                message=f"another process holds the writer lock on {lock_path.parent}",
                context={"lock_path": str(lock_path)},
            ) from exc
        try:
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


@dataclass
class Session:
    """A session directory holding events.jsonl and head.json.

    Phase 5 adds ``signatures.jsonl`` alongside.
    """

    path: Path
    session_id: str
    platform_id: str | None = None

    @classmethod
    def open_or_create(
        cls,
        path: Path,
        *,
        session_id: str,
        platform_id: str | None = None,
    ) -> Session:
        """Open an existing session directory or create one at ``path``."""
        path.mkdir(parents=True, exist_ok=True)
        return cls(path=path, session_id=session_id, platform_id=platform_id)

    @property
    def events_path(self) -> Path:
        return self.path / "events.jsonl"

    @property
    def head_path(self) -> Path:
        return self.path / "head.json"

    @property
    def signatures_path(self) -> Path:
        return self.path / "signatures.jsonl"

    @property
    def lock_path(self) -> Path:
        return self.path / ".lock"

    def head(self) -> ChainHead:
        return _read_head(self.head_path)

    def append(self, body: dict[str, Any]) -> RawEvent:
        """Append an unsigned event. Returns the full event with chain fields assigned.

        Equivalent to ``record(body, signer=None)[0]`` but with a simpler
        return type. Use this in contexts where signing is genuinely not
        wanted (test fixtures, dry-run tooling). Production recording goes
        through ``record``.

        Body MUST NOT carry ``prev``, ``seq``, or ``id``; the writer assigns
        those.
        """
        event, _ = self._append_locked(body, signer=None)
        return event

    def record(
        self,
        body: dict[str, Any],
        *,
        signer: SignerCallback,
    ) -> tuple[RawEvent, RawSignature]:
        """Append an event AND its signature atomically.

        The ``signer`` callback receives the event id and the canonical
        signing-input bytes (spec §7.2) and returns a complete signature
        object dict (``event_id``, ``key_id``, ``alg``, ``sig``). The writer
        appends both the event line and the signature line inside a single
        lock-held window so the two files cannot drift apart under
        concurrent access.

        Body MUST NOT carry ``prev``, ``seq``, or ``id``.
        """
        event, sig_obj = self._append_locked(body, signer=signer)
        assert sig_obj is not None  # signer was provided, so writer produced one
        return event, sig_obj

    def _append_locked(
        self,
        body: dict[str, Any],
        *,
        signer: SignerCallback | None,
    ) -> tuple[RawEvent, RawSignature | None]:
        for forbidden in _CHAIN_FIELDS:
            if forbidden in body:
                raise WriterError(
                    code="writer.body_carries_chain_field",
                    message=(f"event body must not contain {forbidden!r}; the writer assigns it"),
                    context={"field": forbidden},
                )

        with _session_lock(self.lock_path):
            head = self.head()
            new_event: dict[str, Any] = dict(body)
            new_event["prev"] = head.event_id
            new_event["seq"] = head.seq + 1
            new_event["id"] = event_id(new_event)

            # Compute the signature before any file writes so signing
            # failures do not leave a partially-written log.
            sig_obj: RawSignature | None = None
            if signer is not None:
                signing_input = event_signing_bytes(new_event)
                sig_obj = signer(new_event["id"], signing_input)

            with open(self.events_path, "a") as fh:
                fh.write(json.dumps(new_event, sort_keys=True) + "\n")

            if sig_obj is not None:
                with open(self.signatures_path, "a") as fh:
                    fh.write(json.dumps(sig_obj, sort_keys=True) + "\n")

            _write_head(
                self.head_path,
                ChainHead(
                    event_id=new_event["id"],
                    seq=new_event["seq"],
                    ts=new_event.get("ts"),
                ),
            )

        return new_event, sig_obj
