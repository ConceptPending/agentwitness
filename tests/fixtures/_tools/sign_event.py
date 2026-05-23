"""Fixture authoring scaffolding — NOT runtime code.

Used to compute event_id, manifest_id, and Ed25519 signatures during the
hand-authoring of fixtures under tests/fixtures/. The runtime canonicalisation
and signing live in agentwitness/canonical.py and agentwitness/signing.py
(Phase 3).

Reproducing a fixture:

    from sign_event import (
        canonical_bytes, event_id, manifest_id,
        sign_event_body, sign_manifest_body, sk_from_hex, pk_from_hex,
    )

    sk = sk_from_hex(open("../_keys/nick-laptop.ed25519.sk").read().strip())

    event = {"v": "agentwitness/0.1", "prev": None, "session": {...}, ...}
    event["id"] = event_id(event)

    sig_bytes = sign_event_body(event, sk)
"""

from __future__ import annotations

import hashlib
from typing import Any

import jcs
import nacl.signing


def canonical_bytes(obj: dict[str, Any]) -> bytes:
    """RFC 8785 JSON canonicalisation."""
    return jcs.canonicalize(obj)


def event_id(event: dict[str, Any]) -> str:
    """Compute event_id per spec §7.1: SHA-256 of canonical body with `id` absent."""
    body = {k: v for k, v in event.items() if k != "id"}
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def manifest_id(manifest: dict[str, Any]) -> str:
    """Compute manifest_id per spec §7.3: SHA-256 of canonical body with `id` and `sig` absent."""
    body = {k: v for k, v in manifest.items() if k not in {"id", "sig"}}
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def sign_event_body(event_with_id: dict[str, Any], sk: nacl.signing.SigningKey) -> bytes:
    """Sign the canonical event body with `id` present (spec §7.2).

    Returns the raw 64-byte Ed25519 signature.
    """
    if "id" not in event_with_id:
        raise ValueError("event must have id field present before signing")
    body = canonical_bytes(event_with_id)
    return sk.sign(body).signature


def sign_manifest_body(manifest_with_id: dict[str, Any], sk: nacl.signing.SigningKey) -> bytes:
    """Sign the canonical manifest body with `id` present, `sig` absent (spec §7.3 step 6)."""
    if "id" not in manifest_with_id:
        raise ValueError("manifest must have id field present before signing")
    body = {k: v for k, v in manifest_with_id.items() if k != "sig"}
    return sk.sign(canonical_bytes(body)).signature


def sk_from_hex(hex_str: str) -> nacl.signing.SigningKey:
    """Load an Ed25519 signing key from a hex-encoded raw seed (32 bytes / 64 hex chars)."""
    return nacl.signing.SigningKey(bytes.fromhex(hex_str.strip()))


def pk_from_hex(hex_str: str) -> nacl.signing.VerifyKey:
    """Load an Ed25519 verify key from hex-encoded raw bytes."""
    return nacl.signing.VerifyKey(bytes.fromhex(hex_str.strip()))


def key_id(pk: nacl.signing.VerifyKey) -> str:
    """Compute key_id per spec §3.2: lowercase hex SHA-256 of raw public key bytes."""
    return hashlib.sha256(bytes(pk)).hexdigest()
