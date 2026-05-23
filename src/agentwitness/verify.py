"""Top-level bundle verifier.

Orchestrates the per-module checks against a parsed Bundle:

1. Each manifest's id and signature.
2. Each session's chain integrity (event_id, prev, seq).
3. Each event's signature under the key declared in actor.signer_key_id.
4. Each tool event's scope, plus recorder-honesty checks: tool.completed
   actions MUST pass scope, tool.denied actions MUST NOT pass scope.
5. The chain.json checkpoint matches the events and verifies under the
   issuer key.

Errors are accumulated rather than raised so a single verification run
returns the full set of problems. Chain integrity is the one exception:
within a session, once a chain link breaks, subsequent events in that
session are not checked because their position is meaningless.

Spec references: §6, §7, §8, §9, §10.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentwitness.bundle import Bundle, read_bundle
from agentwitness.canonical import chain_signing_bytes, event_signing_bytes
from agentwitness.chain import walk_session
from agentwitness.errors import (
    BundleError,
    ChainError,
    ManifestError,
    ScopeError,
    SignatureError,
    VerifyError,
)
from agentwitness.keys import load_public_key_b64
from agentwitness.manifest import (
    evaluate_event_scope,
    verify_manifest_id,
    verify_manifest_signature,
)
from agentwitness.signing import verify_signature
from agentwitness.types import RawEvent, RawManifest, RawSignature, is_tool_kind


@dataclass
class VerifyResult:
    ok: bool
    errors: list[VerifyError] = field(default_factory=list)
    events_verified: int = 0
    sessions_seen: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "events_verified": self.events_verified,
            "sessions_seen": self.sessions_seen,
            "errors": [
                {"code": e.code, "message": e.message, "context": e.context} for e in self.errors
            ],
        }


def _resolve_signer_key(event: RawEvent, manifests: dict[str, RawManifest]) -> tuple[str, str]:
    """Return ``(signer_key_id, public_key_b64)`` from the event's active manifest.

    Looks up the manifest referenced by scope_token, then locates the
    principal whose key_id matches the event's actor.signer_key_id.
    """
    scope_token = event.get("scope_token", "")
    mid, _, _ = scope_token.partition(":")
    manifest = manifests.get(mid)
    if manifest is None:
        raise ScopeError(
            code="scope.manifest_not_in_bundle",
            message=f"event references manifest {mid!r} which is not in the bundle",
            context={"event_id": event.get("id"), "scope_token": scope_token},
        )

    actor = event.get("actor", {})
    signer_kid = actor.get("signer_key_id")
    if not isinstance(signer_kid, str):
        raise SignatureError(
            code="signature.missing_signer_key_id",
            message="event has no actor.signer_key_id",
            context={"event_id": event.get("id")},
        )

    for principal in manifest.get("principals", []):
        if principal.get("key_id") == signer_kid:
            pk = principal.get("public_key")
            if isinstance(pk, str):
                return signer_kid, pk

    raise SignatureError(
        code="signature.key_not_in_manifest",
        message=(f"signer_key_id {signer_kid!r} not present in the principals of manifest {mid!r}"),
        context={"event_id": event.get("id"), "signer_key_id": signer_kid},
    )


def _verify_event_signature(
    event: RawEvent,
    sig_obj: RawSignature,
    manifests: dict[str, RawManifest],
) -> None:
    """Verify one event's detached signature."""
    stored_event_id = event.get("id", "")

    if sig_obj.get("event_id") != stored_event_id:
        raise SignatureError(
            code="signature.event_id_mismatch",
            message=(
                f"signature.event_id={sig_obj.get('event_id')!r} does not match "
                f"event.id={stored_event_id!r}"
            ),
            context={
                "expected_event_id": stored_event_id,
                "actual": sig_obj.get("event_id"),
            },
        )

    actor = event.get("actor", {})
    signer_kid = actor.get("signer_key_id")
    if sig_obj.get("key_id") != signer_kid:
        raise SignatureError(
            code="signature.key_mismatch",
            message=(
                f"signature.key_id={sig_obj.get('key_id')!r} does not match "
                f"actor.signer_key_id={signer_kid!r}"
            ),
            context={"event_id": stored_event_id},
        )

    _, public_key_b64 = _resolve_signer_key(event, manifests)
    verify_key = load_public_key_b64(public_key_b64)
    verify_signature(
        signing_input=event_signing_bytes(event),
        signature_b64=sig_obj.get("sig", ""),
        alg=sig_obj.get("alg", ""),
        verify_key=verify_key,
        event_id=stored_event_id,
        key_id=signer_kid or "",
    )


def _verify_scope_consistency(
    event: RawEvent,
    manifests: dict[str, RawManifest],
    result: VerifyResult,
) -> None:
    """Apply spec §9.3 recorder-honesty rules.

    - tool.completed MUST have passed scope (otherwise should have been tool.denied)
    - tool.denied MUST NOT have passed scope (recorder claimed denial of a permitted action)
    - tool.requested has no scope obligation (just a record of the attempt)
    - tool.failed: action was permitted but failed for other reasons; treated like completed
    """
    kind = event.get("kind", "")
    if not is_tool_kind(kind):
        return

    scope_token = event.get("scope_token", "")
    mid, _, _ = scope_token.partition(":")
    manifest = manifests.get(mid)
    if manifest is None:
        result.errors.append(
            ScopeError(
                code="scope.manifest_not_in_bundle",
                message=f"event references manifest {mid!r} which is not in the bundle",
                context={"event_id": event.get("id"), "scope_token": scope_token},
            )
        )
        return

    try:
        permitted = evaluate_event_scope(event, manifest)
    except ScopeError as exc:
        result.errors.append(exc)
        return

    if kind in {"tool.completed", "tool.failed"} and not permitted:
        result.errors.append(
            ScopeError(
                code="scope.unauthorised_completion",
                message=(
                    f"event {kind} was emitted for an action that does not pass scope; "
                    "the recorder should have emitted tool.denied instead"
                ),
                context={
                    "event_id": event.get("id"),
                    "seq": event.get("seq"),
                    "tool": event.get("tool"),
                },
            )
        )
    elif kind == "tool.denied" and permitted:
        result.errors.append(
            ScopeError(
                code="scope.spurious_denial",
                message=(
                    "event tool.denied was emitted for an action that *does* pass scope; "
                    "the recorder denied a permitted action"
                ),
                context={
                    "event_id": event.get("id"),
                    "seq": event.get("seq"),
                    "tool": event.get("tool"),
                },
            )
        )


def _verify_chain_checkpoint(
    bundle: Bundle,
    result: VerifyResult,
    sessions_to_heads: dict[str, str],
    sessions_with_chain_errors: set[str],
) -> None:
    """Verify chain.json head pointers match the events and the checkpoint signature."""
    chain = bundle.chain
    sig_b64 = chain.get("sig")
    if not isinstance(sig_b64, str):
        result.errors.append(
            BundleError(
                code="chain.checkpoint_missing_sig",
                message="chain.json has no sig field",
                context={},
            )
        )
        return

    # The checkpoint's signer is implicit: it is the issuer of the (first)
    # manifest in the bundle. v0.1 single-issuer model.
    if len(bundle.manifests) != 1:
        # Multi-manifest checkpoint signing is deferred; skip the sig check
        # and just verify the head pointers.
        pass
    else:
        manifest = next(iter(bundle.manifests.values()))
        issuer_kid = manifest.get("issuer", "")
        public_key_b64 = ""
        for principal in manifest.get("principals", []):
            if principal.get("key_id") == issuer_kid:
                pk = principal.get("public_key")
                if isinstance(pk, str):
                    public_key_b64 = pk
                    break
        if public_key_b64:
            verify_key = load_public_key_b64(public_key_b64)
            try:
                verify_signature(
                    signing_input=chain_signing_bytes(chain),
                    signature_b64=sig_b64,
                    alg="ed25519",
                    verify_key=verify_key,
                    event_id="<chain.json>",
                    key_id=issuer_kid,
                )
            except SignatureError as exc:
                result.errors.append(
                    BundleError(
                        code="chain.checkpoint_signature_invalid",
                        message="chain.json signature does not verify under the issuer key",
                        context={"underlying": exc.code},
                    )
                )

    # Head pointer checks
    for session in chain.get("sessions", []):
        sid = session.get("session_agentwitness_id")
        head_id = session.get("head_event_id")
        head_seq = session.get("head_seq")
        if sid in sessions_with_chain_errors:
            # The chain walk for this session already failed; reporting a
            # downstream checkpoint mismatch would be noise on top of the
            # primary failure.
            continue
        if sid not in sessions_to_heads:
            result.errors.append(
                BundleError(
                    code="chain.checkpoint_unknown_session",
                    message=f"chain.json names session {sid!r} not present in events",
                    context={"session_id": sid},
                )
            )
            continue
        events_head_id = sessions_to_heads[sid]
        if head_id != events_head_id:
            result.errors.append(
                BundleError(
                    code="chain.checkpoint_head_mismatch",
                    message=(
                        f"chain.json head_event_id={head_id!r} for session {sid!r} "
                        f"does not match the last event id {events_head_id!r}"
                    ),
                    context={
                        "session_id": sid,
                        "expected": events_head_id,
                        "actual": head_id,
                        "head_seq": head_seq,
                    },
                )
            )


def verify(path: Path) -> VerifyResult:
    """Verify a bundle at ``path``. Returns a VerifyResult with accumulated errors.

    The result's ``ok`` flag is True iff no errors were collected.
    """
    result = VerifyResult(ok=True)

    try:
        bundle = read_bundle(path)
    except BundleError as exc:
        result.ok = False
        result.errors.append(exc)
        return result

    # 1. Manifests
    for _mid, manifest in bundle.manifests.items():
        try:
            verify_manifest_id(manifest)
            verify_manifest_signature(manifest)
        except ManifestError as exc:
            result.errors.append(exc)

    # 2. Group events by session and walk each chain
    sessions: dict[str, list[tuple[int, RawEvent, RawSignature]]] = {}
    for idx, ev in enumerate(bundle.events):
        sid = ev.get("session", {}).get("agentwitness_id", "<no-session>")
        sessions.setdefault(sid, []).append((idx, ev, bundle.signatures[idx]))

    sessions_to_heads: dict[str, str] = {}
    sessions_with_chain_errors: set[str] = set()
    for sid, items in sessions.items():
        result.sessions_seen.append(sid)
        events_for_session = [ev for _, ev, _ in items]
        try:
            verified_ids = walk_session(events_for_session)
            sessions_to_heads[sid] = verified_ids[-1]
        except ChainError as exc:
            result.errors.append(exc)
            sessions_with_chain_errors.add(sid)
            # Skip per-event signature and scope for this session — the chain
            # is broken so positions are meaningless.
            continue

        # 3. Per-event signature verification
        # 4. Scope consistency
        for _, ev, sig_obj in items:
            try:
                _verify_event_signature(ev, sig_obj, bundle.manifests)
                result.events_verified += 1
            except (SignatureError, ScopeError) as exc:
                result.errors.append(exc)
                continue
            _verify_scope_consistency(ev, bundle.manifests, result)

    # 5. Chain checkpoint
    _verify_chain_checkpoint(bundle, result, sessions_to_heads, sessions_with_chain_errors)

    result.ok = not result.errors
    return result
