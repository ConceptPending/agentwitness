"""RFC 8785 JSON canonicalisation and id derivation.

Spec references:
- §7   Canonical serialisation
- §7.1 event_id derivation
- §7.2 event signing input
- §7.3 manifest_id derivation and signing input
- §6.1 chain checkpoint signing input
"""

from __future__ import annotations

import hashlib
from typing import Any, TypeAlias

import jcs  # type: ignore[import-untyped]

JsonObject: TypeAlias = dict[str, Any]


def canonical_bytes(obj: JsonObject) -> bytes:
    """Return the RFC 8785 (JCS) canonical UTF-8 bytes of ``obj``.

    Used wherever the spec calls for canonical serialisation: id derivation,
    signature input, and any byte-level comparison of structured data.
    """
    result = jcs.canonicalize(obj)
    # jcs.canonicalize returns bytes already; type narrowing for the caller.
    if not isinstance(result, bytes):  # pragma: no cover - defensive, jcs always returns bytes
        raise TypeError(f"jcs.canonicalize returned {type(result).__name__}, expected bytes")
    return result


def event_id(event: JsonObject) -> str:
    """Compute ``event_id`` per spec §7.1.

    SHA-256 of the canonical bytes of the event with the ``id`` field absent.
    Returns the full 64-character lowercase hex digest.
    """
    body = {k: v for k, v in event.items() if k != "id"}
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def event_signing_bytes(event_with_id: JsonObject) -> bytes:
    """Return the canonical bytes that an event signature covers (spec §7.2).

    The event MUST have its ``id`` field present. The signature itself is
    detached and never appears inside the event body.
    """
    if "id" not in event_with_id:
        raise ValueError("event must have id present before signing")
    return canonical_bytes(event_with_id)


def manifest_id(manifest: JsonObject) -> str:
    """Compute ``manifest_id`` per spec §7.3.

    SHA-256 of the canonical bytes of the manifest with both ``id`` and
    ``sig`` fields absent. Returns the full 64-character lowercase hex
    digest.
    """
    body = {k: v for k, v in manifest.items() if k not in {"id", "sig"}}
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def manifest_signing_bytes(manifest_with_id: JsonObject) -> bytes:
    """Return the canonical bytes that a manifest signature covers (spec §7.3 step 6).

    The manifest MUST have its ``id`` field present and its ``sig`` field
    absent at the time of signing.
    """
    if "id" not in manifest_with_id:
        raise ValueError("manifest must have id present before signing")
    body = {k: v for k, v in manifest_with_id.items() if k != "sig"}
    return canonical_bytes(body)


def chain_signing_bytes(chain: JsonObject) -> bytes:
    """Return the canonical bytes that a chain checkpoint signature covers (spec §6.1).

    The chain MUST have its ``sig`` field absent at the time of signing.
    """
    body = {k: v for k, v in chain.items() if k != "sig"}
    return canonical_bytes(body)
