"""Detached Ed25519 signature verification.

Spec reference: §8 (signing envelope) and §7.2 (signing input).

Signing-side helpers (private-key handling, signature production) live in a
separate module added in Phase 5. This module is verification-only.
"""

from __future__ import annotations

import base64
import binascii

import nacl.exceptions
import nacl.signing

from agentwitness.errors import SignatureError

SUPPORTED_ALGS: frozenset[str] = frozenset({"ed25519"})
SIGNATURE_BYTES = 64


def verify_signature(
    *,
    signing_input: bytes,
    signature_b64: str,
    alg: str,
    verify_key: nacl.signing.VerifyKey,
    event_id: str,
    key_id: str,
) -> None:
    """Verify a detached signature against ``signing_input``.

    ``event_id`` and ``key_id`` are accepted for inclusion in any raised
    error's context. They are not used to compute the signature; the caller
    is responsible for producing ``signing_input`` per spec §7.2.

    Raises ``SignatureError`` on:
    - unknown ``alg``
    - malformed base64
    - wrong signature length
    - cryptographic verification failure
    """
    if alg not in SUPPORTED_ALGS:
        raise SignatureError(
            code="signature.unknown_alg",
            message=f"signature alg {alg!r} is not supported in v0.1",
            context={"alg": alg, "supported": sorted(SUPPORTED_ALGS), "event_id": event_id},
        )

    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SignatureError(
            code="signature.base64_invalid",
            message=f"signature is not valid base64: {exc}",
            context={"event_id": event_id, "key_id": key_id},
        ) from exc

    if len(signature) != SIGNATURE_BYTES:
        raise SignatureError(
            code="signature.invalid_length",
            message=(f"Ed25519 signature must be {SIGNATURE_BYTES} bytes, got {len(signature)}"),
            context={"length": len(signature), "event_id": event_id, "key_id": key_id},
        )

    try:
        verify_key.verify(signing_input, signature)
    except nacl.exceptions.BadSignatureError as exc:
        raise SignatureError(
            code="signature.verification_failed",
            message="signature does not verify under the declared key",
            context={"event_id": event_id, "key_id": key_id},
        ) from exc
