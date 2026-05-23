"""End-to-end CLI tests against the three fixtures."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agentwitness.cli import cli


def test_verify_valid_exits_zero(valid_bundle: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["verify", str(valid_bundle)])
    assert result.exit_code == 0, result.output
    assert "OK" in result.output


def test_verify_tampered_exits_nonzero(tampered_bundle: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["verify", str(tampered_bundle)])
    assert result.exit_code != 0
    assert "FAILED" in result.output
    assert "chain.event_id_mismatch" in result.output


def test_verify_out_of_scope_exits_nonzero(out_of_scope_bundle: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["verify", str(out_of_scope_bundle)])
    assert result.exit_code != 0
    assert "scope.unauthorised_completion" in result.output


def test_verify_json_output_is_valid_json(valid_bundle: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["verify", "--format", "json", str(valid_bundle)])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["ok"] is True
    assert parsed["events_verified"] == 3


def test_verify_nonexistent_path_errors() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["verify", "/does/not/exist/anywhere"])
    assert result.exit_code != 0
