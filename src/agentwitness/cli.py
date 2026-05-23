"""Command-line interface for agentwitness."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import click
import nacl.signing

from agentwitness import __version__, keychain
from agentwitness.export import build_bundle
from agentwitness.hook import main as hook_main
from agentwitness.install import install as install_impl
from agentwitness.install import uninstall as uninstall_impl
from agentwitness.state import sessions_dir, state_dir
from agentwitness.verify import verify as verify_bundle
from agentwitness.writer import Session


@click.group()
@click.version_option(version=__version__, prog_name="agentwitness")
def cli() -> None:
    """agentwitness — verifiable evidence for AI-assisted engineering."""


@cli.command("verify")
@click.argument(
    "path",
    type=click.Path(exists=True, path_type=Path),
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["human", "json"]),
    default="human",
    show_default=True,
    help="Output format.",
)
def verify_cmd(path: Path, output_format: str) -> None:
    """Verify an evidence bundle at PATH.

    Exits 0 if the bundle is internally consistent, non-zero otherwise.
    """
    result = verify_bundle(path)

    if output_format == "json":
        click.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        click.echo(_human_report(result, path))

    sys.exit(0 if result.ok else 1)


def _human_report(result: object, path: Path) -> str:
    # Local import to avoid circular type-checking concerns; result is VerifyResult.
    from agentwitness.verify import VerifyResult

    assert isinstance(result, VerifyResult)
    lines: list[str] = []
    status = "OK" if result.ok else "FAILED"
    lines.append(f"agentwitness verify: {status}  ({path})")
    lines.append(f"  events verified:   {result.events_verified}")
    lines.append(f"  sessions seen:     {len(result.sessions_seen)}")
    if result.errors:
        lines.append(f"  errors:            {len(result.errors)}")
        for err in result.errors:
            lines.append(f"    - {err.code}: {err.message}")
    return "\n".join(lines)


@cli.command("hook")
def hook_cmd() -> None:
    """Hook entry point. Reads a Claude Code hook payload from stdin and records it.

    Wired into ``~/.claude/settings.json`` by ``agentwitness install``.
    Always exits 0 — recording never blocks tool calls.
    """
    sys.exit(hook_main())


@cli.command("install")
@click.option(
    "--label",
    default="default",
    show_default=True,
    help="Keychain label to store the signing key under.",
)
@click.option(
    "--strict/--allow-everything",
    default=False,
    show_default=True,
    help=(
        "Manifest scope: --strict starts with no permissions (every action denied);"
        " --allow-everything (the default) creates a permissive scope so the recorder"
        " logs everything without blocking."
    ),
)
def install_cmd(label: str, strict: bool) -> None:
    """Non-interactive install. Idempotent.

    Generates an Ed25519 keypair (or reuses the existing one), stores the
    seed in the OS keychain, writes the user-level manifest, and patches
    ``~/.claude/settings.json`` to invoke ``agentwitness hook``.
    """
    result = install_impl(label=label, allow_everything=not strict)
    if result.key_existed:
        click.echo(f"Using existing key in keychain (label: {label})")
    else:
        click.echo(f"Generated new Ed25519 keypair (label: {label})")
    click.echo(f"  public key: {result.public_key_b64}")
    click.echo(f"  key_id:     {result.key_id}")
    click.echo(f"  manifest:   {result.manifest_path}")
    click.echo(f"  settings:   {result.settings_path}")
    if result.settings_backup_path:
        click.echo(f"  backup:     {result.settings_backup_path}")
    click.echo(f"  hook events: {', '.join(result.hook_events)}")
    click.echo("")
    click.echo("agentwitness will now record signed events for every Claude Code session.")


@cli.command("uninstall")
@click.option("--label", default="default", show_default=True)
@click.option(
    "--purge-keys",
    is_flag=True,
    help="Also delete the keychain entry. Default keeps the key so old bundles remain verifiable.",
)
@click.option(
    "--purge-state",
    is_flag=True,
    help="Also delete the state directory (manifest, sessions). Default keeps recorded history.",
)
@click.option("--purge-all", is_flag=True, help="Shorthand for --purge-keys --purge-state.")
@click.option(
    "--restore-from-backup",
    is_flag=True,
    help="Restore settings.json from the .bak written at install rather than filtering entries.",
)
def uninstall_cmd(
    label: str,
    purge_keys: bool,
    purge_state: bool,
    purge_all: bool,
    restore_from_backup: bool,
) -> None:
    """Remove agentwitness hooks from Claude Code's settings.

    By default, only hook entries are removed — the keychain entry and
    state directory are preserved so old bundles remain verifiable.
    Use ``--purge-keys`` and/or ``--purge-state`` (or ``--purge-all``)
    for a clean removal.
    """
    if purge_all:
        purge_keys = True
        purge_state = True
    result = uninstall_impl(
        label=label,
        purge_keys=purge_keys,
        purge_state=purge_state,
        restore_from_backup=restore_from_backup,
    )
    if result.settings_restored_from_backup:
        click.echo(f"Restored {result.settings_path} from backup.")
    else:
        click.echo(
            f"Removed {result.hooks_removed} agentwitness hook entries from {result.settings_path}."
        )
    if result.key_purged:
        click.echo(f"Deleted keychain entry (label: {label}).")
    if result.state_purged:
        click.echo("Removed state directory.")
    if not (result.key_purged or result.state_purged):
        click.echo(
            "Kept keychain and state directory (use --purge-keys / --purge-state to remove)."
        )


# ---- export / summary / blame ----


def _list_session_dirs() -> list[Path]:
    """All recorded session directories, oldest first."""
    root = sessions_dir()
    if not root.exists():
        return []
    return sorted((p for p in root.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime)


def _read_session_events(session_path: Path) -> list[dict[str, Any]]:
    """Parse the events.jsonl for a session. Returns [] if the file is missing or empty."""
    events_path = session_path / "events.jsonl"
    if not events_path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in events_path.read_text().splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def _format_ts(ts: str) -> str:
    """Trim millisecond ISO to a friendlier form for tabular output."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ts


def _resolve_session(session_id: str | None, latest: bool) -> Path:
    """Pick a session directory based on flags. Defaults to latest."""
    if session_id:
        candidate = sessions_dir() / session_id
        if not candidate.is_dir():
            raise click.ClickException(f"No session named {session_id!r} found.")
        return candidate

    sessions = _list_session_dirs()
    if not sessions:
        raise click.ClickException(
            "No sessions recorded yet. Run `agentwitness install` and use Claude Code first."
        )
    if not latest and session_id is None:
        # Default behaviour — pick the most recent.
        pass
    return sessions[-1]


def _load_active_manifest() -> dict[str, Any]:
    manifest_path = state_dir() / "manifest.json"
    if not manifest_path.exists():
        raise click.ClickException(
            f"No manifest at {manifest_path}. Run `agentwitness install` first."
        )
    try:
        result: dict[str, Any] = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"Manifest is not valid JSON: {exc}") from exc
    return result


def _load_signing_key(label: str) -> nacl.signing.SigningKey:
    if not keychain.exists(label):
        raise click.ClickException(
            f"No signing key in keychain under label {label!r}. Run `agentwitness install` first."
        )
    return nacl.signing.SigningKey(keychain.load_seed(label))


@cli.command("export")
@click.option("--session", "session_id", default=None, help="Export a specific session id.")
@click.option(
    "--latest",
    is_flag=True,
    default=False,
    help="Export the most recent session (this is the default when no flags are given).",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    required=True,
    help="Directory to write the bundle into. Will be created if missing.",
)
@click.option("--label", default="default", show_default=True)
def export_cmd(session_id: str | None, latest: bool, output: Path, label: str) -> None:
    """Build an evidence bundle from a recorded session.

    With no flags, exports the most recent session. Use ``--session <id>``
    to pick a specific one (``agentwitness summary`` lists them).
    """
    session_path = _resolve_session(session_id, latest)
    manifest = _load_active_manifest()
    signing_key = _load_signing_key(label)
    session = Session.open_or_create(session_path, session_id=session_path.name)
    bundle_path = build_bundle(
        session=session,
        manifest=manifest,
        signing_key=signing_key,
        out_dir=output,
    )
    click.echo(f"Bundle written to {bundle_path}")
    click.echo("Verify with: agentwitness verify " + str(bundle_path))


@cli.command("summary")
@click.option("--label", default="default", show_default=True)
def summary_cmd(label: str) -> None:
    """Show recorded sessions, the active manifest, and the active key."""
    if not (state_dir() / "manifest.json").exists():
        click.echo("agentwitness is not installed on this machine.")
        click.echo("Run `agentwitness install` to start recording.")
        return

    manifest = _load_active_manifest()
    click.echo(f"manifest: {manifest['id']}")
    click.echo(f"  issued:  {_format_ts(manifest['issued_at'])}")
    click.echo(f"  expires: {_format_ts(manifest['expires_at'])}")
    click.echo(f"  issuer:  {manifest['issuer']}")
    click.echo("")

    sessions = _list_session_dirs()
    if not sessions:
        click.echo("No sessions recorded yet.")
        return

    click.echo(f"sessions ({len(sessions)}):")
    for path in sessions:
        events = _read_session_events(path)
        if not events:
            click.echo(f"  {path.name}  (no events yet)")
            continue
        platform = events[0].get("session", {}).get("platform_id") or "?"
        first = _format_ts(events[0]["ts"])
        last = _format_ts(events[-1]["ts"])
        click.echo(f"  {path.name}  {len(events):>4} events  {first} → {last}  ({platform})")


@cli.command("blame")
@click.argument("file_path", type=str)
def blame_cmd(file_path: str) -> None:
    """Show recorded events that touched FILE_PATH.

    Match is exact-string against the ``path`` field of each event's
    resources. In v0.1 the recorder writes file paths verbatim from the
    agent's tool input; glob support is post-v0.
    """
    sessions = _list_session_dirs()
    if not sessions:
        click.echo(f"No events recorded yet (looked for {file_path}).")
        return

    matches: list[tuple[str, str, str, str, str]] = []  # (ts, kind, tool, session, status)
    for sess_path in sessions:
        for event in _read_session_events(sess_path):
            resources = event.get("resources") or []
            if any(r.get("path") == file_path for r in resources):
                matches.append(
                    (
                        event.get("ts", ""),
                        event.get("kind", "?"),
                        event.get("tool", "?"),
                        sess_path.name,
                        event.get("outcome", {}).get("status", "?"),
                    )
                )

    if not matches:
        click.echo(f"No recorded events touched {file_path}.")
        return

    matches.sort(key=lambda row: row[0])
    click.echo(f"events touching {file_path}:")
    for ts, kind, tool, sess, status in matches:
        click.echo(f"  {_format_ts(ts)}  {kind:<16} {tool:<14} {sess[:20]}  ({status})")


def main() -> None:
    """Console-script entry point."""
    cli()


if __name__ == "__main__":
    main()
