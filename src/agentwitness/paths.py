"""Path glob matching and tool pattern matching for manifest scope rules.

Spec reference: §3.4 (path normalisation and glob semantics) and §9.3
(scope evaluation).

Two matchers live here because they have different semantics:

- ``path_matches``: file-path matching with the spec §3.4 glob rules,
  including the any-depth rule when a pattern is not anchored with a
  leading ``/``.
- ``tool_matches``: tool-name matching using simple ``fnmatch`` semantics
  (``*``, ``?``, ``[...]``). Tool names have no directory structure so the
  any-depth rule doesn't apply.

Path normalisation (lexical ``..`` collapse, symlink avoidance, project-root
relativisation) is a recorder concern and lands in Phase 5. The verifier
trusts that the recorder already wrote normalised paths into events.
"""

from __future__ import annotations

import fnmatch
import re
from functools import lru_cache


@lru_cache(maxsize=512)
def _compile_path_glob(pattern: str) -> re.Pattern[str]:
    """Translate a spec §3.4 glob to a regex.

    Rules:
    - leading ``/`` anchors the pattern to the root (no implicit prefix)
    - otherwise the pattern can match at any depth (implicit ``**/`` prefix)
    - ``**`` matches any sequence including ``/``
    - ``**/`` matches zero or more directory components
    - ``*`` matches any sequence not containing ``/``
    - ``?`` matches any single character not containing ``/``
    """
    if pattern.startswith("/"):
        effective = pattern[1:]
    else:
        effective = pattern if pattern.startswith("**/") else "**/" + pattern

    out: list[str] = []
    i = 0
    while i < len(effective):
        if effective[i : i + 3] == "**/":
            out.append(r"(?:[^/]+/)*")
            i += 3
        elif effective[i : i + 2] == "**":
            out.append(r".*")
            i += 2
        elif effective[i] == "*":
            out.append(r"[^/]*")
            i += 1
        elif effective[i] == "?":
            out.append(r"[^/]")
            i += 1
        else:
            out.append(re.escape(effective[i]))
            i += 1

    return re.compile(r"\A" + "".join(out) + r"\Z")


def path_matches(pattern: str, path: str) -> bool:
    """True if ``path`` matches ``pattern`` per spec §3.4 glob rules."""
    return bool(_compile_path_glob(pattern).match(path))


def tool_matches(pattern: str, tool: str) -> bool:
    """True if ``tool`` matches ``pattern`` under fnmatch semantics.

    Tool names look like ``Edit``, ``Bash:pytest``, ``WebFetch``. Patterns
    use ``*``, ``?``, ``[...]`` with no special treatment of ``:`` or any
    other character.
    """
    return fnmatch.fnmatchcase(tool, pattern)
