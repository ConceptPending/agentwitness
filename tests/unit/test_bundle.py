"""Tests for agentwitness.bundle."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentwitness.bundle import read_bundle
from agentwitness.errors import BundleError


def test_reads_valid_fixture(valid_bundle: Path) -> None:
    b = read_bundle(valid_bundle)
    assert len(b.events) == 3
    assert len(b.signatures) == 3
    assert len(b.manifests) == 1
    assert "sessions" in b.chain


def test_signature_count_mismatch_raises(tmp_path: Path, valid_bundle: Path) -> None:
    """Copy the valid fixture but truncate signatures.jsonl by one line."""
    import shutil

    dst = tmp_path / "broken"
    shutil.copytree(valid_bundle, dst)
    sig_path = dst / "signatures.jsonl"
    lines = sig_path.read_text().splitlines()
    sig_path.write_text("\n".join(lines[:-1]) + "\n")  # drop last signature
    with pytest.raises(BundleError) as exc_info:
        read_bundle(dst)
    assert exc_info.value.code == "bundle.signature_count_mismatch"


def test_missing_manifest_raises(tmp_path: Path, valid_bundle: Path) -> None:
    import shutil

    dst = tmp_path / "broken"
    shutil.copytree(valid_bundle, dst)
    (dst / "manifest.json").unlink()
    with pytest.raises(BundleError) as exc_info:
        read_bundle(dst)
    assert exc_info.value.code == "bundle.no_manifest"


def test_malformed_json_raises(tmp_path: Path, valid_bundle: Path) -> None:
    import shutil

    dst = tmp_path / "broken"
    shutil.copytree(valid_bundle, dst)
    (dst / "manifest.json").write_text("not json at all")
    with pytest.raises(BundleError) as exc_info:
        read_bundle(dst)
    assert exc_info.value.code == "bundle.malformed_json"


def test_not_a_directory_raises(tmp_path: Path) -> None:
    file_path = tmp_path / "not-a-dir"
    file_path.write_text("")
    with pytest.raises(BundleError) as exc_info:
        read_bundle(file_path)
    assert exc_info.value.code == "bundle.not_a_directory"
