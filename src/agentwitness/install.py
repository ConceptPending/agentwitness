"""Non-interactive install and uninstall for agentwitness.

The install command does, in order:

1. Generate (or reuse) an Ed25519 keypair and stash the seed in the OS
   keychain under the chosen label.
2. Write a self-signed default manifest at ``<state>/manifest.json``.
3. Patch ``~/.claude/settings.json`` idempotently to add agentwitness
   hooks for the events we record. A ``.bak`` of any existing file is
   written first.

The uninstall command:

1. Removes agentwitness hook entries from ``~/.claude/settings.json``
   (or restores from ``.bak`` if requested).
2. Optionally removes the keychain entry (``--purge-keys``).
3. Optionally removes the state directory (``--purge-state``).

Both operations expose every path as an explicit argument so tests can
point them at temporary locations rather than the user's real home.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import nacl.signing

from agentwitness import keychain
from agentwitness.errors import VerifyError
from agentwitness.keys import key_id_from_verify_key
from agentwitness.manifest import build_default_manifest
from agentwitness.state import state_dir as default_state_dir

CLAUDE_SETTINGS_ENV = "AGENTWITNESS_CLAUDE_SETTINGS"
DEFAULT_LABEL = "default"
DEFAULT_HOOK_EVENTS: tuple[str, ...] = (
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "UserPromptSubmit",
    "SessionStart",
    "SessionEnd",
)


class InstallError(VerifyError):
    """Errors from install/uninstall flows."""


@dataclass
class InstallResult:
    key_id: str
    public_key_b64: str
    key_existed: bool
    manifest_path: Path
    settings_path: Path
    settings_backup_path: Path | None
    hook_events: list[str]


@dataclass
class UninstallResult:
    settings_path: Path
    hooks_removed: int
    settings_restored_from_backup: bool
    key_purged: bool
    state_purged: bool


# ---- Path resolution ----


def claude_settings_path() -> Path:
    """Resolve the path Claude Code reads its settings from.

    ``AGENTWITNESS_CLAUDE_SETTINGS`` overrides for tests.
    """
    override = os.environ.get(CLAUDE_SETTINGS_ENV)
    if override:
        return Path(override)
    return Path.home() / ".claude" / "settings.json"


def agentwitness_command() -> str:
    """Return the absolute command string used in hook entries.

    Resolution order, from cleanest to most robust:

    1. ``sys.argv[0]`` if it looks like an ``agentwitness`` script. When
       the user runs ``agentwitness install``, ``sys.argv[0]`` is the
       script they invoked, so by definition that path works.
    2. The interpreter's bin directory. Catches pyenv and virtualenv
       installs where the script lives next to ``python`` but PATH
       doesn't include that bin directory.
    3. ``shutil.which("agentwitness")``. Catches pipx and pip-user
       installs where the script is on PATH.
    4. ``{sys.executable} -m agentwitness.cli hook``. Always works.
       Used as a last resort because it hard-codes a Python path that
       can move (venv recreation, Python version change).
    """
    argv0 = Path(sys.argv[0]) if sys.argv and sys.argv[0] else None
    if argv0 is not None and argv0.name.startswith("agentwitness") and argv0.is_file():
        return f"{argv0.resolve()} hook"

    bin_dir = Path(sys.executable).resolve().parent
    candidate = bin_dir / "agentwitness"
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return f"{candidate} hook"

    path = shutil.which("agentwitness")
    if path:
        return f"{path} hook"

    return f"{sys.executable} -m agentwitness.cli hook"


# ---- Install ----


def install(
    *,
    state: Path | None = None,
    settings_path: Path | None = None,
    label: str = DEFAULT_LABEL,
    allow_everything: bool = True,
    hook_events: tuple[str, ...] = DEFAULT_HOOK_EVENTS,
    now: datetime | None = None,
    expiry_days: int = 365,
) -> InstallResult:
    """Perform the full install. All inputs explicit so tests can override."""
    state_root = state if state is not None else default_state_dir()
    settings_target = settings_path if settings_path is not None else claude_settings_path()
    issued = now if now is not None else datetime.now(timezone.utc)
    expires = issued + timedelta(days=expiry_days)

    signing_key, key_existed = _ensure_key(label)
    kid = key_id_from_verify_key(signing_key.verify_key)

    state_root.mkdir(parents=True, exist_ok=True)
    manifest = build_default_manifest(
        signing_key=signing_key,
        key_id=kid,
        issued_at=_format_iso_ms(issued),
        expires_at=_format_iso_ms(expires),
        allow_everything=allow_everything,
    )
    manifest_path = state_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    backup_path = _patch_settings(settings_target, agentwitness_command(), hook_events)

    return InstallResult(
        key_id=kid,
        public_key_b64=manifest["principals"][0]["public_key"],
        key_existed=key_existed,
        manifest_path=manifest_path,
        settings_path=settings_target,
        settings_backup_path=backup_path,
        hook_events=list(hook_events),
    )


def _ensure_key(label: str) -> tuple[nacl.signing.SigningKey, bool]:
    """Load the existing key or generate a fresh one.

    Returns ``(signing_key, key_existed)`` — ``key_existed`` is True if a
    seed was already in the keychain under this label.
    """
    if keychain.exists(label):
        seed = keychain.load_seed(label)
        return nacl.signing.SigningKey(seed), True
    signing_key = nacl.signing.SigningKey.generate()
    keychain.store_seed(label, bytes(signing_key))
    return signing_key, False


def _format_iso_ms(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ---- Settings.json patcher ----


def _is_agentwitness_entry(entry: Any) -> bool:
    """True if a settings.json hook entry is one we put there.

    An entry counts as ours when any of its inner hook commands ends with
    ``hook`` and mentions ``agentwitness``. That covers the absolute-path
    form (``/usr/local/bin/agentwitness hook``) and the module-invocation
    form (``/path/to/python -m agentwitness.cli hook``).
    """
    if not isinstance(entry, dict):
        return False
    inner = entry.get("hooks")
    if not isinstance(inner, list):
        return False
    for h in inner:
        if not isinstance(h, dict):
            continue
        cmd = h.get("command")
        if not isinstance(cmd, str):
            continue
        if cmd.endswith(" hook") and "agentwitness" in cmd:
            return True
    return False


def _patch_settings(
    settings_path: Path,
    aw_command: str,
    hook_events: tuple[str, ...],
) -> Path | None:
    """Idempotently merge agentwitness hooks into the settings file.

    Returns the path to the ``.bak`` backup when one is written (i.e.
    when there was an existing settings file), or ``None`` when no
    backup was needed because the file didn't exist yet.
    """
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    backup_path: Path | None = None
    if settings_path.exists():
        backup_path = settings_path.with_suffix(".json.bak")
        shutil.copy(settings_path, backup_path)
        try:
            settings = json.loads(settings_path.read_text())
        except json.JSONDecodeError as exc:
            raise InstallError(
                code="install.malformed_settings",
                message=f"existing {settings_path} is not valid JSON",
                context={"path": str(settings_path)},
            ) from exc
        if not isinstance(settings, dict):
            raise InstallError(
                code="install.malformed_settings",
                message=f"{settings_path} is JSON but not an object",
                context={"path": str(settings_path)},
            )
    else:
        settings = {}

    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise InstallError(
            code="install.malformed_settings",
            message=f"{settings_path}: 'hooks' is not an object",
            context={"path": str(settings_path)},
        )

    canonical_entry = {
        "matcher": "*",
        "hooks": [{"type": "command", "command": aw_command}],
    }
    for event in hook_events:
        existing = hooks.get(event)
        if not isinstance(existing, list):
            existing = []
        # Drop any prior entry of ours so we don't duplicate on re-install.
        kept = [e for e in existing if not _is_agentwitness_entry(e)]
        kept.append(canonical_entry)
        hooks[event] = kept

    _atomic_write_json(settings_path, settings)
    return backup_path


def _atomic_write_json(path: Path, obj: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2) + "\n")
    tmp.replace(path)


# ---- Uninstall ----


def uninstall(
    *,
    state: Path | None = None,
    settings_path: Path | None = None,
    label: str = DEFAULT_LABEL,
    purge_keys: bool = False,
    purge_state: bool = False,
    restore_from_backup: bool = False,
) -> UninstallResult:
    """Reverse the install. Conservative by default — keeps keys, state, manifest."""
    state_root = state if state is not None else default_state_dir()
    settings_target = settings_path if settings_path is not None else claude_settings_path()

    removed = 0
    restored = False
    if restore_from_backup:
        backup = settings_target.with_suffix(".json.bak")
        if backup.exists():
            shutil.copy(backup, settings_target)
            restored = True
        else:
            removed = _strip_agentwitness_hooks(settings_target)
    else:
        removed = _strip_agentwitness_hooks(settings_target)

    if purge_keys:
        keychain.delete_seed(label)
    if purge_state and state_root.exists():
        shutil.rmtree(state_root)

    return UninstallResult(
        settings_path=settings_target,
        hooks_removed=removed,
        settings_restored_from_backup=restored,
        key_purged=purge_keys,
        state_purged=purge_state,
    )


def _strip_agentwitness_hooks(settings_path: Path) -> int:
    """Remove agentwitness entries from settings.json. Returns count removed."""
    if not settings_path.exists():
        return 0
    try:
        settings = json.loads(settings_path.read_text())
    except json.JSONDecodeError:
        # Malformed settings — leave it alone rather than make it worse.
        return 0
    if not isinstance(settings, dict):
        return 0
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return 0

    removed = 0
    for event, entries in list(hooks.items()):
        if not isinstance(entries, list):
            continue
        kept = []
        for entry in entries:
            if _is_agentwitness_entry(entry):
                removed += 1
            else:
                kept.append(entry)
        if kept:
            hooks[event] = kept
        else:
            del hooks[event]

    if not hooks:
        settings.pop("hooks", None)

    _atomic_write_json(settings_path, settings)
    return removed
