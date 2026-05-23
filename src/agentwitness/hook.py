"""Claude Code hook entry point.

Claude Code invokes hook commands with a single JSON payload on stdin
(see code.claude.com/docs/en/hooks). This module reads that payload,
maps it to an agentwitness event body, and writes a signed event via
the bootstrapped Recorder.

The wiring (inserted into ``~/.claude/settings.json`` by
``agentwitness install``) looks roughly like::

    "hooks": {
      "PreToolUse": [
        {
          "matcher": "*",
          "hooks": [{"type": "command", "command": "agentwitness hook"}]
        }
      ],
      "PostToolUse":      [/* same shape */],
      "UserPromptSubmit": [/* same shape */],
      "SessionStart":     [/* same shape */],
      "SessionEnd":       [/* same shape */]
    }

The hook always exits 0. agentwitness records; it never blocks a tool
call. If recording fails, an explanatory line goes to stderr (which
Claude Code surfaces to the user) and the hook still exits 0.

The agentwitness session id is derived deterministically from Claude
Code's ``session_id`` so the same Claude session maps to the same
agentwitness session across multiple hook firings — per spec §3.2 rev e.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentwitness.recorder import Recorder
from agentwitness.state import state_dir

# Map Claude Code hook event names to agentwitness event kinds.
_HOOK_TO_KIND: dict[str, str] = {
    "PreToolUse": "tool.requested",
    "PostToolUse": "tool.completed",
    "PostToolUseFailure": "tool.failed",
    "UserPromptSubmit": "user.prompt",
    "SessionStart": "session.start",
    "SessionEnd": "session.end",
}


def derive_agentwitness_session_id(platform_session_id: str) -> str:
    """Derive a stable agentwitness session id from a platform session id.

    Per spec §3.2 (rev e), recorders MAY derive deterministically. We use
    SHA-256 truncated to 22 hex characters — 88 bits of derived entropy
    from whatever entropy the platform put into its session id.
    """
    digest = hashlib.sha256(platform_session_id.encode("utf-8")).hexdigest()
    return f"sess_{digest[:22]}"


def _now_iso_ms() -> str:
    """Current UTC time as the spec §3.1 RFC 3339 millisecond string."""
    now = datetime.now(timezone.utc)
    return now.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _manifest_path() -> Path:
    """User-level manifest location. Sits next to the sessions/ directory."""
    return state_dir() / "manifest.json"


def _load_manifest() -> dict[str, Any]:
    """Load the manifest the install command wrote.

    Raises FileNotFoundError if install hasn't been run; the caller
    converts that into a stderr message and exits 0.
    """
    text = _manifest_path().read_text()
    result: dict[str, Any] = json.loads(text)
    return result


def _normalise_path(path: str, cwd: str | None) -> str:
    """Per spec §3.4: if a project root is known and ``path`` is under it,
    return the project-relative form. Otherwise leave the path absolute.

    The hook treats Claude Code's payload ``cwd`` as the project root.
    Symlinks are not followed (spec §3.4 rule 1). Paths outside cwd stay
    absolute.
    """
    if not cwd:
        return path
    cwd = cwd.rstrip("/")
    if not cwd:
        return path
    if path == cwd:
        return path  # the path IS the project root; leave it alone
    prefix = cwd + "/"
    if path.startswith(prefix):
        return path[len(prefix) :]
    return path


def _resources_for_tool(
    tool_name: str,
    tool_input: dict[str, Any],
    *,
    cwd: str | None = None,
) -> list[dict[str, Any]]:
    """Best-effort mapping of Claude Code tool inputs to spec §4 resources.

    Many tools (Bash, WebFetch, WebSearch, AskUserQuestion) have no path
    semantics we can infer from the input alone; those record with an
    empty resources list and the verifier can still scope-check based on
    the tool name. Tools with obvious file paths (Edit, Write, Read) get
    a single resource entry with the path normalised relative to ``cwd``
    when that path is inside the project root.
    """
    if tool_name in {"Edit", "Write"}:
        path = tool_input.get("file_path")
        if isinstance(path, str):
            return [
                {
                    "type": "file",
                    "op": "write",
                    "path": _normalise_path(path, cwd),
                    "before_hash": None,
                    "after_hash": None,
                }
            ]
    elif tool_name == "Read":
        path = tool_input.get("file_path")
        if isinstance(path, str):
            return [
                {
                    "type": "file",
                    "op": "read",
                    "path": _normalise_path(path, cwd),
                    "before_hash": None,
                    "after_hash": None,
                }
            ]
    return []


def build_event_body(
    payload: dict[str, Any],
    *,
    manifest: dict[str, Any],
    key_id: str,
) -> dict[str, Any] | None:
    """Map a Claude Code hook payload to an agentwitness event body.

    Returns ``None`` if the payload's ``hook_event_name`` isn't one we
    record. The caller treats that as a no-op.

    The body is signing-input-ready: it has everything except the
    chain-derived fields (``prev``, ``seq``, ``id``), which the writer
    will add when the recorder calls ``Session.record``.
    """
    event_name = payload.get("hook_event_name")
    kind = _HOOK_TO_KIND.get(event_name) if isinstance(event_name, str) else None
    if kind is None:
        return None

    platform_session = payload.get("session_id", "")
    if not isinstance(platform_session, str) or not platform_session:
        return None

    body: dict[str, Any] = {
        "v": "agentwitness/0.1",
        "session": {
            "agentwitness_id": derive_agentwitness_session_id(platform_session),
            "platform_id": platform_session,
        },
        "ts": _now_iso_ms(),
        "kind": kind,
        "agent": {
            "platform": "claude-code",
            "model": payload.get("model", "unknown"),
            "model_version": payload.get("model", "unknown"),
        },
        "actor": {
            "signer_key_id": key_id,
            "principal_key_id": key_id,
            "delegation": [],
        },
        "scope_token": f"{manifest['id']}:0",
        "outcome": {"status": "ok", "code": kind, "message": ""},
    }

    if kind in {"tool.requested", "tool.completed", "tool.failed"}:
        tool_name = payload.get("tool_name", "unknown")
        tool_input = payload.get("tool_input", {}) or {}
        cwd = payload.get("cwd")
        cwd_str = cwd if isinstance(cwd, str) else None
        body["tool"] = tool_name
        body["inputs"] = {}
        body["outputs"] = {}
        body["resources"] = _resources_for_tool(tool_name, tool_input, cwd=cwd_str)
        tool_use_id = payload.get("tool_use_id")
        if isinstance(tool_use_id, str):
            body["request_id"] = tool_use_id

        if kind == "tool.failed":
            body["outcome"] = {
                "status": "error",
                "code": "tool.failed",
                "message": str(payload.get("error", "tool failed")),
            }
        else:
            body["outcome"] = {
                "status": "ok",
                "code": kind,
                "message": f"{tool_name} {kind.split('.', 1)[1]}",
            }

    elif kind == "session.start":
        body["outcome"] = {
            "status": "ok",
            "code": "session.started",
            "message": f"session started (source={payload.get('source', 'unknown')})",
        }

    elif kind == "session.end":
        body["outcome"] = {
            "status": "ok",
            "code": "session.ended",
            "message": f"session ended (reason={payload.get('reason', 'unknown')})",
        }

    elif kind == "user.prompt":
        # The prompt content itself is not stored in the event — only metadata.
        # Content can be added in a future revision via inputs hashes if needed.
        body["outcome"] = {
            "status": "ok",
            "code": "prompt.received",
            "message": "user prompt received",
        }

    return body


def _log_stderr(msg: str) -> None:
    """Write a single agentwitness-prefixed line to stderr."""
    print(f"agentwitness: {msg}", file=sys.stderr)


def main(stdin: Any = None) -> int:
    """Hook entry point. Always returns 0.

    Reads the JSON payload from stdin (or the optional ``stdin`` arg used
    in tests), looks up the active manifest, bootstraps a recorder, and
    writes one event. Any failure logs to stderr and returns 0 anyway —
    agentwitness records, it never blocks a tool call.
    """
    source = stdin if stdin is not None else sys.stdin

    try:
        payload = json.loads(source.read())
    except json.JSONDecodeError as exc:
        _log_stderr(f"hook payload was not valid JSON: {exc}")
        return 0

    if not isinstance(payload, dict):
        _log_stderr("hook payload was not a JSON object")
        return 0

    try:
        manifest = _load_manifest()
    except FileNotFoundError:
        _log_stderr(f"manifest not found at {_manifest_path()}; run `agentwitness install`")
        return 0
    except json.JSONDecodeError as exc:
        _log_stderr(f"manifest is not valid JSON: {exc}")
        return 0

    platform_session = payload.get("session_id", "")
    if not isinstance(platform_session, str) or not platform_session:
        _log_stderr("payload had no session_id; skipping")
        return 0

    try:
        recorder = Recorder.bootstrap(
            session_id=derive_agentwitness_session_id(platform_session),
            platform_id=platform_session,
        )
    except Exception as exc:
        _log_stderr(f"failed to bootstrap recorder: {exc}")
        return 0

    body = build_event_body(payload, manifest=manifest, key_id=recorder.key_id)
    if body is None:
        # Unknown hook_event_name or missing session_id — silent no-op.
        return 0

    try:
        recorder.record(body)
    except Exception as exc:
        _log_stderr(f"failed to record event: {exc}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
