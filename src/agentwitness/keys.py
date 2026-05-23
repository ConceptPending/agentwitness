"""Ed25519 key loading and identifier helpers.

agentwitness v0.1 uses Ed25519 only (spec §8). This module deals with the
verification side: loading public keys from the base64 form stored in
manifests, and computing the ``key_id`` (lowercase hex SHA-256 of the raw
32-byte public key) per spec §3.2.

Signing-side helpers (key generation, OS keyring storage) live in a separate
module added in Phase 5.
"""

from __future__ import annotations

import base64
import binascii
import hashlib

import nacl.signing

from agentwitness.errors import KeyResolutionError

PUBLIC_KEY_BYTES = 32


def key_id_from_bytes(public_key_bytes: bytes) -> str:
    """Compute ``key_id`` per spec §3.2 from raw public-key bytes.

    Returns the full 64-character lowercase hex SHA-256 digest.
    """
    if len(public_key_bytes) != PUBLIC_KEY_BYTES:
        raise KeyResolutionError(
            code="key.invalid_length",
            message=(
                f"Ed25519 public key must be {PUBLIC_KEY_BYTES} bytes, got {len(public_key_bytes)}"
            ),
            context={"length": len(public_key_bytes)},
        )
    return hashlib.sha256(public_key_bytes).hexdigest()


def key_id_from_verify_key(verify_key: nacl.signing.VerifyKey) -> str:
    """Compute ``key_id`` from a PyNaCl VerifyKey instance."""
    return key_id_from_bytes(bytes(verify_key))


def load_public_key_b64(public_key_b64: str) -> nacl.signing.VerifyKey:
    """Load a public key from the base64 form used in manifests.

    Raises ``KeyResolutionError`` if the base64 is malformed or the decoded
    bytes are the wrong length.
    """
    try:
        raw = base64.b64decode(public_key_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise KeyResolutionError(
            code="key.base64_invalid",
            message=f"public_key is not valid base64: {exc}",
            context={},
        ) from exc

    if len(raw) != PUBLIC_KEY_BYTES:
        raise KeyResolutionError(
            code="key.invalid_length",
            message=(f"Ed25519 public key must decode to {PUBLIC_KEY_BYTES} bytes, got {len(raw)}"),
            context={"length": len(raw)},
        )
    return nacl.signing.VerifyKey(raw)
