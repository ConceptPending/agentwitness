"""Tests for agentwitness.keychain.

Uses an in-memory keyring backend installed before each test so the real
OS keychain is never touched.
"""

from __future__ import annotations

import secrets

import pytest

from agentwitness.errors import KeyResolutionError
from agentwitness.keychain import (
    SEED_BYTES,
    _install_in_memory_backend,
    delete_seed,
    exists,
    load_seed,
    store_seed,
)


@pytest.fixture(autouse=True)
def in_memory_keyring() -> None:
    """Install a fresh in-memory backend before every test in this file."""
    _install_in_memory_backend()


def test_store_then_load_roundtrips() -> None:
    seed = secrets.token_bytes(SEED_BYTES)
    store_seed("default", seed)
    assert load_seed("default") == seed


def test_store_overwrites_existing() -> None:
    first = secrets.token_bytes(SEED_BYTES)
    second = secrets.token_bytes(SEED_BYTES)
    store_seed("default", first)
    store_seed("default", second)
    assert load_seed("default") == second


def test_load_missing_label_raises() -> None:
    with pytest.raises(KeyResolutionError) as exc_info:
        load_seed("never-stored")
    assert exc_info.value.code == "keychain.label_not_found"


def test_store_wrong_length_seed_rejected() -> None:
    with pytest.raises(KeyResolutionError) as exc_info:
        store_seed("default", b"short")
    assert exc_info.value.code == "keychain.invalid_seed_length"


def test_delete_removes_entry() -> None:
    seed = secrets.token_bytes(SEED_BYTES)
    store_seed("default", seed)
    assert exists("default")
    delete_seed("default")
    assert not exists("default")


def test_delete_missing_label_is_noop() -> None:
    delete_seed("never-stored")  # should not raise


def test_multiple_labels_isolated() -> None:
    a = secrets.token_bytes(SEED_BYTES)
    b = secrets.token_bytes(SEED_BYTES)
    store_seed("laptop", a)
    store_seed("ci-runner", b)
    assert load_seed("laptop") == a
    assert load_seed("ci-runner") == b


def test_exists_returns_false_for_missing() -> None:
    assert not exists("never-stored")
