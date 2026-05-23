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


def main() -> None:
    """Console-script entry point."""
    cli()


if __name__ == "__main__":
    main()
