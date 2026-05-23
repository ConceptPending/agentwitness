"""Build a verifiable evidence bundle from a session and a manifest.

Spec reference: §10 (evidence bundle layout).

Takes the on-disk session (events.jsonl, signatures.jsonl produced by
``writer.Session.record``) plus an active manifest, produces a bundle
directory with the layout the verifier expects. The chain.json
checkpoint is signed under the issuer key.

v0.1 ships single-session, single-issuer bundles. Multi-session
aggregation, partial-range exports, and tarball packaging are post-v0.
"""

from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path
from typing import Any

import nacl.signing

from agentwitness.errors import BundleError
from agentwitness.signing import sign_chain
from agentwitness.writer import Session


def build_bundle(
    *,
    session: Session,
    manifest: dict[str, Any],
    signing_key: nacl.signing.SigningKey,
    out_dir: Path,
) -> Path:
    """Assemble a verifier-ready bundle from ``session`` into ``out_dir``.

    Caller is responsible for ensuring ``signing_key`` matches the
    manifest's issuer — the chain checkpoint signature uses it. The
    function raises ``BundleError`` if the session has no events.
    """
    if not session.events_path.exists() or not session.events_path.stat().st_size:
        raise BundleError(
            code="export.empty_session",
            message=f"session at {session.path} has no events to export",
            context={"path": str(session.path)},
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(session.events_path, out_dir / "events.jsonl")
    if session.signatures_path.exists():
        shutil.copy(session.signatures_path, out_dir / "signatures.jsonl")

    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    events = [
        json.loads(line) for line in (out_dir / "events.jsonl").read_text().splitlines() if line
    ]
    if not events:
        raise BundleError(
            code="export.empty_session",
            message=f"session at {session.path} has an empty events.jsonl",
            context={"path": str(session.path)},
        )

    chain: dict[str, Any] = {
        "v": "agentwitness/0.1",
        "sessions": [
            {
                "session_agentwitness_id": events[0]["session"]["agentwitness_id"],
                "first_event_id": events[0]["id"],
                "head_event_id": events[-1]["id"],
                "head_seq": events[-1]["seq"],
                "first_ts": events[0]["ts"],
                "last_ts": events[-1]["ts"],
                "manifest_ids": [manifest["id"]],
            }
        ],
    }
    chain_sig = sign_chain(chain, signing_key)
    chain["sig"] = base64.b64encode(chain_sig).decode()
    (out_dir / "chain.json").write_text(json.dumps(chain, indent=2, sort_keys=True) + "\n")

    return out_dir
