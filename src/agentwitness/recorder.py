"""Top-level recorder: writes signed events for a session.

The Phase 5 public API. Wraps a ``writer.Session`` with a keychain-loaded
signing key so every event written under this recorder is also signed and
the signature lands in ``signatures.jsonl`` alongside.

Two construction paths:

- ``Recorder.bootstrap(session_id=...)`` — production path. Resolves the
  user-level state directory, loads the seed from the OS keychain, opens
  the session.
- ``Recorder.from_session_and_key(session, signing_key)`` — escape hatch
  for tests and for callers (CLI tooling, Cowork plugins) that have
  already resolved a key by some other means.

The Recorder does not know about manifests, scopes, or the platform's
session identifier shape. Those are the caller's responsibility — see
``hook.py`` for the Claude Code mapping.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import nacl.signing

from agentwitness import keychain
from agentwitness.keys import key_id_from_verify_key
from agentwitness.signing import make_event_signer
from agentwitness.state import session_dir as resolve_session_dir
from agentwitness.types import RawEvent, RawSignature
from agentwitness.writer import Session, SignerCallback

DEFAULT_LABEL = "default"


@dataclass
class Recorder:
    """Signed-event recorder for a single session.

    Not safe to share across sessions — each Recorder is bound to one
    Session and one key.
    """

    session: Session
    key_id: str
    _signer: SignerCallback

    @classmethod
    def bootstrap(
        cls,
        *,
        session_id: str,
        platform_id: str | None = None,
        label: str = DEFAULT_LABEL,
    ) -> Recorder:
        """Resolve the state dir, load the signing key, open the session.

        Raises ``KeyResolutionError`` (code ``keychain.label_not_found``) if
        ``agentwitness install`` hasn't been run on this machine, or if the
        given label doesn't exist in the keychain.
        """
        seed = keychain.load_seed(label)
        signing_key = nacl.signing.SigningKey(seed)
        session_path = resolve_session_dir(session_id)
        session = Session.open_or_create(
            session_path,
            session_id=session_id,
            platform_id=platform_id,
        )
        kid = key_id_from_verify_key(signing_key.verify_key)
        return cls(
            session=session,
            key_id=kid,
            _signer=make_event_signer(signing_key, kid),
        )

    @classmethod
    def from_session_and_key(
        cls,
        session: Session,
        signing_key: nacl.signing.SigningKey,
    ) -> Recorder:
        """Construct directly from an open session and an in-memory signing key.

        Bypasses the keychain. Used by tests and by callers that have a
        signing key from somewhere other than the OS keychain (HSM-backed,
        pre-provisioned, in-process generated for a one-off bundle).
        """
        kid = key_id_from_verify_key(signing_key.verify_key)
        return cls(
            session=session,
            key_id=kid,
            _signer=make_event_signer(signing_key, kid),
        )

    def record(self, body: dict[str, Any]) -> tuple[RawEvent, RawSignature]:
        """Sign and append an event. Returns the full event and its signature object.

        Body MUST NOT carry ``prev``, ``seq``, or ``id``. The recorder
        assumes the caller has populated everything else (including
        ``actor.signer_key_id`` matching this recorder's key, and a
        ``scope_token`` referencing the active manifest). Verification will
        catch any mismatch later.
        """
        return self.session.record(body, signer=self._signer)
