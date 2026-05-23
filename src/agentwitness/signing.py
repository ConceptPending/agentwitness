"""Detached Ed25519 signature verification and production.

Spec reference: §8 (signing envelope) and §7.2 (signing input).

The verification side (``verify_signature``) is what the Phase 3 verifier
uses. The production side (``sign_event`` / ``sign_manifest`` /
``sign_chain`` / ``make_event_signer``) is what the Phase 5 recorder uses.

Both sides live in the same module so the canonicalisation choices made
on one side are visible to the other.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

import nacl.exceptions
import nacl.signing

from agentwitness.canonical import (
    chain_signing_bytes,
    event_signing_bytes,
    manifest_signing_bytes,
)
from agentwitness.errors import SignatureError
from agentwitness.types import RawChain, RawEvent, RawManifest, RawSignature

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


# ---- Producer side ----


def sign_event(event: RawEvent, signing_key: nacl.signing.SigningKey) -> bytes:
    """Sign an event's canonical signing-input bytes (spec §7.2).

    The event MUST have its ``id`` field present. Returns the raw 64-byte
    Ed25519 signature.
    """
    if "id" not in event:
        raise SignatureError(
            code="signing.event_missing_id",
            message="event must have id present before signing",
            context={},
        )
    return signing_key.sign(event_signing_bytes(event)).signature


def sign_manifest(manifest: RawManifest, signing_key: nacl.signing.SigningKey) -> bytes:
    """Sign a manifest's canonical signing-input bytes (spec §7.3 step 6).

    The manifest MUST have its ``id`` field present and its ``sig`` field
    absent at the time of signing. Returns the raw 64-byte signature.
    """
    if "id" not in manifest:
        raise SignatureError(
            code="signing.manifest_missing_id",
            message="manifest must have id present before signing",
            context={},
        )
    return signing_key.sign(manifest_signing_bytes(manifest)).signature


def sign_chain(chain: RawChain, signing_key: nacl.signing.SigningKey) -> bytes:
    """Sign a chain checkpoint's canonical bytes (spec §6.1).

    The chain MUST have its ``sig`` field absent at the time of signing.
    Returns the raw 64-byte signature.
    """
    return signing_key.sign(chain_signing_bytes(chain)).signature


def make_event_signer(
    signing_key: nacl.signing.SigningKey,
    key_id: str,
) -> Any:
    """Build a SignerCallback for use with ``writer.Session.record``.

    The returned callable signs the canonical signing bytes with
    ``signing_key`` and assembles a complete signature object dict
    (``event_id``, ``key_id``, ``alg``, ``sig``) ready to write to
    ``signatures.jsonl``.

    The return type is ``writer.SignerCallback`` but is annotated as
    ``Any`` here to avoid a cyclic import. ``writer`` already imports
    ``signing`` indirectly via ``canonical``.
    """

    def signer(event_id: str, signing_input: bytes) -> RawSignature:
        sig_bytes = signing_key.sign(signing_input).signature
        return {
            "event_id": event_id,
            "key_id": key_id,
            "alg": "ed25519",
            "sig": base64.b64encode(sig_bytes).decode(),
        }

    return signer
