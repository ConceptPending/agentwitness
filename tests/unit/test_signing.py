"""Tests for agentwitness.signing.

Sign-then-verify properties driven by hypothesis: any (keypair, message)
roundtrips cleanly, and any mutation of either the message or the
signature is detected.
"""

from __future__ import annotations

import base64
import secrets

import nacl.signing
import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentwitness.errors import SignatureError
from agentwitness.signing import verify_signature

# A small helper to sign with a fresh key. Hypothesis generates the seed
# so each example uses a distinct key.
_keypair_seed = st.binary(min_size=32, max_size=32)
_messages = st.binary(min_size=0, max_size=4096)


@given(seed=_keypair_seed, message=_messages)
def test_sign_then_verify_roundtrip(seed: bytes, message: bytes) -> None:
    sk = nacl.signing.SigningKey(seed)
    vk = sk.verify_key
    sig = sk.sign(message).signature
    verify_signature(
        signing_input=message,
        signature_b64=base64.b64encode(sig).decode(),
        alg="ed25519",
        verify_key=vk,
        event_id="x",
        key_id="x",
    )


@given(seed=_keypair_seed, message=_messages, flip_index=st.integers(min_value=0, max_value=63))
def test_signature_mutation_detected(seed: bytes, message: bytes, flip_index: int) -> None:
    sk = nacl.signing.SigningKey(seed)
    vk = sk.verify_key
    sig = bytearray(sk.sign(message).signature)
    sig[flip_index] ^= 0x01  # flip a bit
    with pytest.raises(SignatureError) as exc_info:
        verify_signature(
            signing_input=message,
            signature_b64=base64.b64encode(bytes(sig)).decode(),
            alg="ed25519",
            verify_key=vk,
            event_id="x",
            key_id="x",
        )
    assert exc_info.value.code == "signature.verification_failed"


@given(seed=_keypair_seed, message=_messages)
def test_message_mutation_detected(seed: bytes, message: bytes) -> None:
    sk = nacl.signing.SigningKey(seed)
    vk = sk.verify_key
    sig = sk.sign(message).signature
    mutated = message + b"\x00"  # extend by one byte
    with pytest.raises(SignatureError) as exc_info:
        verify_signature(
            signing_input=mutated,
            signature_b64=base64.b64encode(sig).decode(),
            alg="ed25519",
            verify_key=vk,
            event_id="x",
            key_id="x",
        )
    assert exc_info.value.code == "signature.verification_failed"


def test_unknown_alg_rejected() -> None:
    vk = nacl.signing.SigningKey.generate().verify_key
    with pytest.raises(SignatureError) as exc_info:
        verify_signature(
            signing_input=b"x",
            signature_b64=base64.b64encode(b"\x00" * 64).decode(),
            alg="ecdsa-p256",  # not supported in v0.1
            verify_key=vk,
            event_id="e",
            key_id="k",
        )
    assert exc_info.value.code == "signature.unknown_alg"


def test_bad_base64_rejected() -> None:
    vk = nacl.signing.SigningKey.generate().verify_key
    with pytest.raises(SignatureError) as exc_info:
        verify_signature(
            signing_input=b"x",
            signature_b64="not-base64!!!@@@",
            alg="ed25519",
            verify_key=vk,
            event_id="e",
            key_id="k",
        )
    assert exc_info.value.code == "signature.base64_invalid"


def test_wrong_length_signature_rejected() -> None:
    vk = nacl.signing.SigningKey.generate().verify_key
    with pytest.raises(SignatureError) as exc_info:
        verify_signature(
            signing_input=b"x",
            signature_b64=base64.b64encode(b"\x00" * 32).decode(),  # half length
            alg="ed25519",
            verify_key=vk,
            event_id="e",
            key_id="k",
        )
    assert exc_info.value.code == "signature.invalid_length"


def test_wrong_key_rejected() -> None:
    """A signature produced by one key MUST NOT verify under a different key."""
    sk_a = nacl.signing.SigningKey(secrets.token_bytes(32))
    sk_b = nacl.signing.SigningKey(secrets.token_bytes(32))
    message = b"some message"
    sig = sk_a.sign(message).signature
    with pytest.raises(SignatureError) as exc_info:
        verify_signature(
            signing_input=message,
            signature_b64=base64.b64encode(sig).decode(),
            alg="ed25519",
            verify_key=sk_b.verify_key,  # wrong key
            event_id="e",
            key_id="k",
        )
    assert exc_info.value.code == "signature.verification_failed"


# ---- Producer side ----


def test_sign_event_then_verify_roundtrip() -> None:
    """sign_event followed by verify_signature on the same canonical bytes
    succeeds. Direct roundtrip closes the loop between producer and verifier."""
    from agentwitness.canonical import event_id as compute_event_id
    from agentwitness.canonical import event_signing_bytes
    from agentwitness.signing import sign_event

    sk = nacl.signing.SigningKey.generate()
    body = {"v": "agentwitness/0.1", "foo": "bar"}
    body["id"] = compute_event_id(body)
    sig = sign_event(body, sk)
    verify_signature(
        signing_input=event_signing_bytes(body),
        signature_b64=base64.b64encode(sig).decode(),
        alg="ed25519",
        verify_key=sk.verify_key,
        event_id=body["id"],
        key_id="x",
    )


def test_sign_event_rejects_missing_id() -> None:
    from agentwitness.signing import sign_event

    sk = nacl.signing.SigningKey.generate()
    with pytest.raises(SignatureError) as exc_info:
        sign_event({"v": "agentwitness/0.1"}, sk)
    assert exc_info.value.code == "signing.event_missing_id"


def test_sign_manifest_then_verify_roundtrip() -> None:
    from agentwitness.canonical import manifest_id as compute_manifest_id
    from agentwitness.canonical import manifest_signing_bytes
    from agentwitness.signing import sign_manifest

    sk = nacl.signing.SigningKey.generate()
    body: dict = {"v": "agentwitness/0.1", "issuer": "x"}
    body["id"] = compute_manifest_id(body)
    sig = sign_manifest(body, sk)
    verify_signature(
        signing_input=manifest_signing_bytes(body),
        signature_b64=base64.b64encode(sig).decode(),
        alg="ed25519",
        verify_key=sk.verify_key,
        event_id=body["id"],
        key_id="x",
    )


def test_sign_chain_then_verify_roundtrip() -> None:
    from agentwitness.canonical import chain_signing_bytes
    from agentwitness.signing import sign_chain

    sk = nacl.signing.SigningKey.generate()
    body = {"v": "agentwitness/0.1", "sessions": []}
    sig = sign_chain(body, sk)
    verify_signature(
        signing_input=chain_signing_bytes(body),
        signature_b64=base64.b64encode(sig).decode(),
        alg="ed25519",
        verify_key=sk.verify_key,
        event_id="<chain>",
        key_id="x",
    )


def test_make_event_signer_callback_produces_writer_compatible_object() -> None:
    """make_event_signer returns a callable that the writer can call directly."""
    from agentwitness.signing import make_event_signer

    sk = nacl.signing.SigningKey.generate()
    signer = make_event_signer(sk, key_id="abc")
    sig_obj = signer("event-id-here", b"some canonical bytes")
    assert sig_obj["event_id"] == "event-id-here"
    assert sig_obj["key_id"] == "abc"
    assert sig_obj["alg"] == "ed25519"
    # Verify the produced signature is correct.
    verify_signature(
        signing_input=b"some canonical bytes",
        signature_b64=sig_obj["sig"],
        alg="ed25519",
        verify_key=sk.verify_key,
        event_id="event-id-here",
        key_id="abc",
    )


@given(seed=st.binary(min_size=32, max_size=32), message=st.binary(max_size=128))
def test_sign_event_property_roundtrip(seed: bytes, message: bytes) -> None:
    """Property: for any signing key and any event-like body, sign-then-verify
    succeeds."""
    from agentwitness.canonical import event_id as compute_event_id
    from agentwitness.canonical import event_signing_bytes
    from agentwitness.signing import sign_event

    sk = nacl.signing.SigningKey(seed)
    body: dict = {"v": "agentwitness/0.1", "payload_b64": base64.b64encode(message).decode()}
    body["id"] = compute_event_id(body)
    sig = sign_event(body, sk)
    verify_signature(
        signing_input=event_signing_bytes(body),
        signature_b64=base64.b64encode(sig).decode(),
        alg="ed25519",
        verify_key=sk.verify_key,
        event_id=body["id"],
        key_id="x",
    )
