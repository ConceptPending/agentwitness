"""Structured error hierarchy for verification.

Every verification failure raises a ``VerifyError`` (or a subclass) carrying:

- a stable ``code`` string (e.g. ``"chain.event_id_mismatch"``) suitable for
  programmatic matching in tests and CI scripts;
- a human-readable ``message``;
- a ``context`` dict with the specific values that produced the failure
  (event_id, manifest_id, expected vs actual digests, etc.).

The verifier accumulates errors into a structured report rather than raising
on the first failure, so the CLI exit path is one place rather than scattered.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class VerifyError(Exception):
    """Base verification error. Carries a stable code, message, and context."""

    code: str
    message: str
    context: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class BundleError(VerifyError):
    """Bundle layout, missing files, parse errors."""


class CanonicalError(VerifyError):
    """Failure to canonicalise or recompute an id."""


class EventError(VerifyError):
    """Per-event structural problems: missing required fields, unexpected fields, bad types."""


class ChainError(VerifyError):
    """Hash-chain integrity failures: event_id mismatch, prev mismatch, seq mismatch."""


class SignatureError(VerifyError):
    """Signature verification failures: invalid sig, key mismatch, unknown alg."""


class ManifestError(VerifyError):
    """Manifest signature, expiry, or structural problems."""


class ScopeError(VerifyError):
    """Authority scope evaluation failures: unauthorised completion, missing scope_token."""


class KeyResolutionError(VerifyError):
    """A referenced key_id could not be resolved against the active manifests."""
