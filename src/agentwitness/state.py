"""User-level state directory resolution.

agentwitness keeps recorded sessions under a single user-level state
directory. Per the Phase 5 design (DIRECTION.md / NEXT_STEPS.md):

- macOS:   ~/Library/Application Support/agentwitness
- Linux:   $XDG_DATA_HOME/agentwitness, or ~/.local/share/agentwitness
- Windows: %APPDATA%/agentwitness

The ``AGENTWITNESS_STATE_DIR`` environment variable overrides all of the
above. Tests use this to point at a temporary directory.

Sessions live at ``<state_dir>/sessions/<session_id>/``. Each session
directory holds ``events.jsonl``, a ``head.json`` pointer, and
(post-Phase-5) ``signatures.jsonl``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ENV_OVERRIDE = "AGENTWITNESS_STATE_DIR"


def state_dir() -> Path:
    """Return the agentwitness user-level state directory.

    Does not create the directory; callers are responsible for ensuring
    the path exists before writing into it.
    """
    override = os.environ.get(ENV_OVERRIDE)
    if override:
        return Path(override)

    home = Path.home()
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "agentwitness"
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "agentwitness"
        return home / "AppData" / "Roaming" / "agentwitness"

    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "agentwitness"
    return home / ".local" / "share" / "agentwitness"


def sessions_dir() -> Path:
    """Return the sessions subdirectory under the state root."""
    return state_dir() / "sessions"


def session_dir(session_id: str) -> Path:
    """Return the directory for a specific session id."""
    return sessions_dir() / session_id
