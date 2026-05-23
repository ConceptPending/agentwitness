"""OS-keychain integration for Ed25519 seed storage.

Wraps the ``keyring`` library so the rest of agentwitness sees a tight
domain interface rather than the generic password store. Seeds are stored
hex-encoded under the service name ``agentwitness`` with the keypair's
label as the username.

On macOS this lands in Keychain Access. On Linux it goes through the
Secret Service API (GNOME Keyring / KWallet). On Windows it uses Windows
Credential Manager. The user gets the OS's normal at-rest encryption and
access prompts; agentwitness never touches the seed bytes outside this
module.
"""

from __future__ import annotations

import binascii
from typing import Any

import keyring
import keyring.errors

from agentwitness.errors import KeyResolutionError

SERVICE_NAME = "agentwitness"
SEED_BYTES = 32


def store_seed(label: str, seed: bytes) -> None:
    """Store a 32-byte Ed25519 seed under ``label``.

    Overwrites any existing value at that label. Raises ``KeyResolutionError``
    if the seed is the wrong length; lets keyring-level failures (locked
    keychain, no backend) propagate as their native exceptions.
    """
    if len(seed) != SEED_BYTES:
        raise KeyResolutionError(
            code="keychain.invalid_seed_length",
            message=f"Ed25519 seed must be {SEED_BYTES} bytes, got {len(seed)}",
            context={"label": label, "length": len(seed)},
        )
    keyring.set_password(SERVICE_NAME, label, binascii.hexlify(seed).decode())


def load_seed(label: str) -> bytes:
    """Load the seed stored under ``label``.

    Raises ``KeyResolutionError`` with code ``keychain.label_not_found`` if
    nothing is stored at that label, or ``keychain.corrupt_seed`` if what is
    stored doesn't decode as hex of the right length.
    """
    value = keyring.get_password(SERVICE_NAME, label)
    if value is None:
        raise KeyResolutionError(
            code="keychain.label_not_found",
            message=f"no agentwitness key stored under label {label!r}",
            context={"label": label},
        )
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise KeyResolutionError(
            code="keychain.corrupt_seed",
            message=f"stored seed for label {label!r} is not valid hex",
            context={"label": label},
        ) from exc
    if len(raw) != SEED_BYTES:
        raise KeyResolutionError(
            code="keychain.corrupt_seed",
            message=(f"stored seed for label {label!r} is {len(raw)} bytes, expected {SEED_BYTES}"),
            context={"label": label, "length": len(raw)},
        )
    return raw


def delete_seed(label: str) -> None:
    """Delete the stored seed at ``label``. No-op if nothing is stored there."""
    try:
        keyring.delete_password(SERVICE_NAME, label)
    except keyring.errors.PasswordDeleteError:
        # Nothing was there; that's fine.
        pass


def exists(label: str) -> bool:
    """Return True iff a seed is stored under ``label``."""
    return keyring.get_password(SERVICE_NAME, label) is not None


def _install_in_memory_backend() -> Any:
    """Test helper: replace the active keyring with an in-memory backend.

    Returns the backend object so tests can introspect or reset it. Not
    part of the public API; lives here so the test files don't have to
    duplicate the backend class.
    """
    backend = _InMemoryBackend()
    keyring.set_keyring(backend)
    return backend


class _InMemoryBackend(keyring.backend.KeyringBackend):
    """A keyring backend that stores everything in a process-local dict.

    For tests only. Each call to ``_install_in_memory_backend`` creates a
    fresh instance, so test isolation is automatic when tests use that
    helper.
    """

    priority = 1  # required by keyring's backend protocol

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], str] = {}

    def set_password(self, service: str, username: str, password: str) -> None:
        self._store[(service, username)] = password

    def get_password(self, service: str, username: str) -> str | None:
        return self._store.get((service, username))

    def delete_password(self, service: str, username: str) -> None:
        if (service, username) not in self._store:
            raise keyring.errors.PasswordDeleteError("no such entry")
        del self._store[(service, username)]
