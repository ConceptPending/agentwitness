"""Tests for agentwitness.canonical.

Properties driven by hypothesis where applicable; specific edge cases
covered by example.
"""

from __future__ import annotations

import json
import re

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentwitness.canonical import (
    canonical_bytes,
    chain_signing_bytes,
    event_id,
    event_signing_bytes,
    manifest_id,
    manifest_signing_bytes,
)

# A recursive strategy for JSON-compatible values that jcs can canonicalise.
# Numbers stay within the JS safe-integer range; floats exclude NaN/Inf.
_json_values = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(min_value=-((2**53) - 1), max_value=(2**53) - 1),
        st.floats(allow_nan=False, allow_infinity=False, allow_subnormal=False),
        st.text(),
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=8),
        st.dictionaries(st.text(min_size=1, max_size=20), children, max_size=8),
    ),
    max_leaves=24,
)

# A strategy producing JSON object roots, which is what canonical_bytes accepts.
_json_objects = st.dictionaries(
    st.text(min_size=1, max_size=20),
    _json_values,
    max_size=10,
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@given(_json_objects)
def test_canonical_bytes_returns_bytes(obj: dict) -> None:
    assert isinstance(canonical_bytes(obj), bytes)


@given(_json_objects)
def test_canonical_bytes_is_deterministic(obj: dict) -> None:
    assert canonical_bytes(obj) == canonical_bytes(obj)


@given(_json_objects)
def test_canonical_round_trip_is_stable(obj: dict) -> None:
    """canonical(json.loads(canonical(x).decode())) == canonical(x)."""
    first = canonical_bytes(obj)
    re_parsed = json.loads(first.decode("utf-8"))
    second = canonical_bytes(re_parsed)
    assert first == second


@given(_json_objects)
def test_canonical_insensitive_to_key_order_in_input(obj: dict) -> None:
    """The same logical mapping in any iteration order produces identical bytes."""
    reversed_obj = dict(reversed(list(obj.items())))
    assert canonical_bytes(obj) == canonical_bytes(reversed_obj)


def test_canonical_known_vector_simple_object() -> None:
    """A hand-checked vector to anchor the implementation."""
    obj = {"b": 1, "a": 2}
    # JCS sorts keys lexicographically.
    assert canonical_bytes(obj) == b'{"a":2,"b":1}'


def test_canonical_known_vector_nested() -> None:
    obj = {"z": {"b": 1, "a": 2}, "y": [1, 2, 3]}
    assert canonical_bytes(obj) == b'{"y":[1,2,3],"z":{"a":2,"b":1}}'


@given(_json_objects)
def test_event_id_is_64_char_lowercase_hex(obj: dict) -> None:
    assert _HEX64.match(event_id(obj))


@given(_json_objects)
def test_event_id_ignores_id_field(obj: dict) -> None:
    """Adding or changing the ``id`` field MUST NOT change the derived event_id."""
    a = event_id(obj)
    with_id_x = dict(obj, id="x")
    with_id_y = dict(obj, id="y")
    assert a == event_id(with_id_x) == event_id(with_id_y)


def test_event_signing_bytes_rejects_missing_id() -> None:
    with pytest.raises(ValueError, match="id"):
        event_signing_bytes({"foo": 1})


def test_event_signing_bytes_includes_id() -> None:
    event = {"foo": 1, "id": "abc"}
    out = event_signing_bytes(event)
    # The id is present in the canonical bytes.
    assert b'"id":"abc"' in out


@given(_json_objects)
def test_manifest_id_is_64_char_lowercase_hex(obj: dict) -> None:
    assert _HEX64.match(manifest_id(obj))


@given(_json_objects)
def test_manifest_id_ignores_id_and_sig_fields(obj: dict) -> None:
    base = manifest_id(obj)
    with_id = dict(obj, id="something")
    with_sig = dict(obj, sig="something")
    with_both = dict(obj, id="x", sig="y")
    assert base == manifest_id(with_id) == manifest_id(with_sig) == manifest_id(with_both)


def test_manifest_signing_bytes_rejects_missing_id() -> None:
    with pytest.raises(ValueError, match="id"):
        manifest_signing_bytes({"foo": 1})


def test_manifest_signing_bytes_excludes_sig_but_keeps_id() -> None:
    manifest = {"foo": 1, "id": "abc", "sig": "should-be-excluded"}
    out = manifest_signing_bytes(manifest)
    assert b'"id":"abc"' in out
    assert b"should-be-excluded" not in out


@given(_json_objects)
def test_chain_signing_bytes_excludes_sig(obj: dict) -> None:
    with_sig = dict(obj, sig="excluded")
    out = chain_signing_bytes(with_sig)
    assert b"excluded" not in out
