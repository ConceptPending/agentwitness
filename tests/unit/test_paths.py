"""Tests for agentwitness.paths."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentwitness.paths import path_matches, tool_matches

# ---- Path glob ----


@pytest.mark.parametrize(
    "pattern,path,expected",
    [
        # Any-depth (unanchored)
        ("src/**", "src/app.ts", True),
        ("src/**", "src/sub/app.ts", True),
        ("src/**", "foo/src/app.ts", True),  # any-depth
        ("src/**", "tests/app.ts", False),
        (".env", ".env", True),
        (".env", "config/.env", True),
        (".env", ".envrc", False),  # exact name match
        ("**/secrets/**", "secrets/key", True),
        ("**/secrets/**", "foo/secrets/key", True),
        ("**/secrets/**", "config/secrets/api/key", True),
        # Anchored to root
        ("/.env", ".env", True),
        ("/.env", "config/.env", False),
        ("/src/**", "src/app.ts", True),
        ("/src/**", "foo/src/app.ts", False),
        # Single char
        ("?.py", "a.py", True),
        ("?.py", "ab.py", False),
        ("?.py", "py", False),
    ],
)
def test_path_matches_known_cases(pattern: str, path: str, expected: bool) -> None:
    assert path_matches(pattern, path) is expected


@given(st.text(min_size=1, max_size=20), st.text(min_size=1, max_size=40))
def test_path_matches_is_deterministic(pattern: str, path: str) -> None:
    """Same inputs always give the same answer (no hidden state, no cache issues)."""
    a = path_matches(pattern, path)
    b = path_matches(pattern, path)
    assert a == b


# ---- Tool matching ----


@pytest.mark.parametrize(
    "pattern,tool,expected",
    [
        ("Edit", "Edit", True),
        ("Edit", "Read", False),
        ("Bash:*", "Bash:pytest", True),
        ("Bash:*", "Bash:terraform-apply", True),
        ("Bash:*", "Edit", False),
        ("Bash:terraform*", "Bash:terraform", True),
        ("Bash:terraform*", "Bash:terraform-apply", True),
        ("Bash:terraform*", "Bash:pytest", False),
        ("*", "anything", True),
    ],
)
def test_tool_matches_known_cases(pattern: str, tool: str, expected: bool) -> None:
    assert tool_matches(pattern, tool) is expected


@given(st.text(min_size=1, max_size=30))
def test_tool_matches_self(tool: str) -> None:
    """A tool always matches itself when used as the pattern, modulo fnmatch special chars."""
    # Strip the chars fnmatch treats specially; otherwise the literal name
    # may be interpreted as a pattern.
    plain = "".join(c for c in tool if c not in "*?[]")
    if not plain:
        return
    assert tool_matches(plain, plain)
