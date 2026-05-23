"""Tests for agentwitness.keys."""

from __future__ import annotations

import base64

import nacl.signing
import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentwitness.errors import KeyResolutionError
from agentwitness.keys import (
    PUBLIC_KEY_BYTES,
    key_id_from_bytes,
    key_id_from_verify_key,
    load_public_key_b64,
)


@given(st.binary(min_size=PUBLIC_KEY_BYTES, max_size=PUBLIC_KEY_BYTES))
def test_key_id_is_64_char_hex(public_key: bytes) -> None:
    kid = key_id_from_bytes(public_key)
    assert len(kid) == 64
    int(kid, 16)  # parseable as hex


@given(
    st.binary(min_size=0, max_size=PUBLIC_KEY_BYTES - 1)
    | st.binary(min_size=PUBLIC_KEY_BYTES + 1, max_size=PUBLIC_KEY_BYTES + 16)
)
def test_key_id_rejects_wrong_length(public_key: bytes) -> None:
    with pytest.raises(KeyResolutionError) as exc_info:
        key_id_from_bytes(public_key)
    assert exc_info.value.code == "key.invalid_length"


@given(st.binary(min_size=PUBLIC_KEY_BYTES, max_size=PUBLIC_KEY_BYTES))
def test_key_id_consistent_between_bytes_and_verify_key(public_key: bytes) -> None:
    vk = nacl.signing.VerifyKey(public_key)
    assert key_id_from_bytes(public_key) == key_id_from_verify_key(vk)


def test_load_public_key_b64_roundtrip() -> None:
    sk = nacl.signing.SigningKey.generate()
    pk = sk.verify_key
    b64 = base64.b64encode(bytes(pk)).decode()
    loaded = load_public_key_b64(b64)
    assert bytes(loaded) == bytes(pk)


def test_load_public_key_b64_rejects_bad_base64() -> None:
    with pytest.raises(KeyResolutionError) as exc_info:
        load_public_key_b64("not-valid-base64!!!@@@")
    assert exc_info.value.code == "key.base64_invalid"


def test_load_public_key_b64_rejects_wrong_length() -> None:
    short = base64.b64encode(b"too-short").decode()
    with pytest.raises(KeyResolutionError) as exc_info:
        load_public_key_b64(short)
    assert exc_info.value.code == "key.invalid_length"
