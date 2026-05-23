"""Command-line interface for agentwitness.

v0.1 ships one subcommand, ``verify``. Future phases will add ``init``,
``install``, ``blame``, ``export``, and ``keys``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from agentwitness import __version__
from agentwitness.hook import main as hook_main
from agentwitness.install import install as install_impl
from agentwitness.install import uninstall as uninstall_impl
from agentwitness.verify import verify as verify_bundle


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


def main() -> None:
    """Console-script entry point."""
    cli()


if __name__ == "__main__":
    main()
