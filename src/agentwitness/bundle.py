"""Read an evidence bundle from a directory on disk.

Spec reference: §10 (evidence bundle layout).

v0.1 supports the directory layout only. Tarball (.tar.gz) reading is
trivial to add later; deferred to keep this module small.

This module performs *layout* validation (the right files exist, JSON
parses, signature count matches event count) but does not perform any
cryptographic or semantic verification. The verifier orchestrator
consumes the parsed dataclass and runs the checks.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from agentwitness.errors import BundleError
from agentwitness.types import RawChain, RawEvent, RawManifest, RawSignature


@dataclass(frozen=True)
class Bundle:
    """A parsed bundle. Layout has been validated; cryptography has not."""

    path: Path
    manifests: dict[str, RawManifest]  # keyed by stored manifest id
    events: list[RawEvent]
    signatures: list[RawSignature]
    chain: RawChain


def _read_json(path: Path) -> RawEvent:
    try:
        return json.loads(path.read_text())  # type: ignore[no-any-return]
    except FileNotFoundError as exc:
        raise BundleError(
            code="bundle.missing_file",
            message=f"expected file not present: {path.name}",
            context={"file": str(path)},
        ) from exc
    except json.JSONDecodeError as exc:
        raise BundleError(
            code="bundle.malformed_json",
            message=f"{path.name} is not valid JSON: {exc.msg}",
            context={"file": str(path), "line": exc.lineno, "column": exc.colno},
        ) from exc


def _read_jsonl(path: Path) -> list[RawEvent]:
    if not path.exists():
        raise BundleError(
            code="bundle.missing_file",
            message=f"expected file not present: {path.name}",
            context={"file": str(path)},
        )
    out: list[RawEvent] = []
    for lineno, raw_line in enumerate(path.read_text().splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise BundleError(
                code="bundle.malformed_jsonl",
                message=f"{path.name} line {lineno} is not valid JSON: {exc.msg}",
                context={"file": str(path), "line": lineno},
            ) from exc
    return out


def read_bundle(path: Path) -> Bundle:
    """Read a directory-layout bundle.

    Raises BundleError on missing files, malformed JSON, or layout
    inconsistencies (signature count != event count).
    """
    if not path.is_dir():
        raise BundleError(
            code="bundle.not_a_directory",
            message=f"{path} is not a directory; tarball bundles are not supported in v0.1",
            context={"path": str(path)},
        )

    # Manifests: either single manifest.json or a manifests/ directory.
    manifests: dict[str, RawManifest] = {}
    single = path / "manifest.json"
    multi_dir = path / "manifests"

    if single.exists():
        m = _read_json(single)
        mid = m.get("id")
        if not isinstance(mid, str):
            raise BundleError(
                code="bundle.manifest_missing_id",
                message="manifest.json has no id field",
                context={"file": str(single)},
            )
        manifests[mid] = m
    elif multi_dir.is_dir():
        for manifest_path in sorted(multi_dir.glob("*.json")):
            m = _read_json(manifest_path)
            mid = m.get("id")
            if not isinstance(mid, str):
                raise BundleError(
                    code="bundle.manifest_missing_id",
                    message=f"{manifest_path.name} has no id field",
                    context={"file": str(manifest_path)},
                )
            manifests[mid] = m
    else:
        raise BundleError(
            code="bundle.no_manifest",
            message="bundle has neither manifest.json nor manifests/ directory",
            context={"path": str(path)},
        )

    events = _read_jsonl(path / "events.jsonl")
    signatures = _read_jsonl(path / "signatures.jsonl")

    if len(signatures) != len(events):
        raise BundleError(
            code="bundle.signature_count_mismatch",
            message=(
                f"signatures.jsonl has {len(signatures)} entries, events.jsonl has {len(events)}"
            ),
            context={"events": len(events), "signatures": len(signatures)},
        )

    chain = _read_json(path / "chain.json")

    return Bundle(
        path=path,
        manifests=manifests,
        events=events,
        signatures=signatures,
        chain=chain,
    )
