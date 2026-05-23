"""Authority manifest verification and scope evaluation.

Spec references:
- §7.3 manifest_id derivation
- §9   authority manifest (signature, principals, scopes)
- §9.3 scope evaluation rules

The verifier accepts manifests that declare their own issuer key. Binding
the issuer key to a real-world identity is a trust-anchor question (spec
§11) layered on top of the cryptographic checks in this module.
"""

from __future__ import annotations

from typing import Any

from agentwitness.canonical import (
    manifest_id as compute_manifest_id,
)
from agentwitness.canonical import (
    manifest_signing_bytes,
)
from agentwitness.errors import ManifestError, ScopeError, SignatureError
from agentwitness.keys import load_public_key_b64
from agentwitness.paths import path_matches, tool_matches
from agentwitness.signing import verify_signature
from agentwitness.types import RawEvent, RawManifest, is_tool_kind


def verify_manifest_id(manifest: RawManifest) -> str:
    """Recompute ``manifest_id`` and check it matches the stored value.

    Returns the verified manifest_id. Raises ``ManifestError`` with one of
    ``manifest.missing_id`` or ``manifest.id_mismatch``.
    """
    stored = manifest.get("id")
    if not isinstance(stored, str):
        raise ManifestError(
            code="manifest.missing_id",
            message="manifest has no id field",
            context={},
        )
    recomputed = compute_manifest_id(manifest)
    if stored != recomputed:
        raise ManifestError(
            code="manifest.id_mismatch",
            message="manifest id does not match recomputed canonical hash",
            context={"stored": stored, "recomputed": recomputed},
        )
    return stored


def _resolve_issuer_public_key(manifest: RawManifest) -> tuple[str, str]:
    """Return ``(issuer_key_id, issuer_public_key_b64)`` from the manifest.

    The issuer's public key must be present in the manifest's own ``principals``
    list — agentwitness manifests are self-contained in v0.1.
    """
    issuer_kid = manifest.get("issuer")
    if not isinstance(issuer_kid, str):
        raise ManifestError(
            code="manifest.missing_issuer",
            message="manifest has no issuer field",
            context={},
        )

    for principal in manifest.get("principals", []):
        if principal.get("key_id") == issuer_kid:
            pk = principal.get("public_key")
            if not isinstance(pk, str):
                raise ManifestError(
                    code="manifest.principal_missing_public_key",
                    message=f"principal {issuer_kid} has no public_key field",
                    context={"key_id": issuer_kid},
                )
            return issuer_kid, pk

    raise ManifestError(
        code="manifest.issuer_not_in_principals",
        message=(f"manifest issuer {issuer_kid} is not present in its own principals list"),
        context={"issuer": issuer_kid},
    )


def verify_manifest_signature(manifest: RawManifest) -> None:
    """Verify the manifest's own signature under the declared issuer key.

    Raises ``ManifestError`` on missing/malformed sig or on cryptographic
    failure. The underlying ``SignatureError`` code is carried in the error
    context for diagnostics.
    """
    sig = manifest.get("sig")
    if not isinstance(sig, str):
        raise ManifestError(
            code="manifest.missing_sig",
            message="manifest has no sig field",
            context={},
        )

    issuer_kid, public_key_b64 = _resolve_issuer_public_key(manifest)
    verify_key = load_public_key_b64(public_key_b64)
    signing_input = manifest_signing_bytes(manifest)
    manifest_id_value = manifest.get("id", "<missing>")

    try:
        verify_signature(
            signing_input=signing_input,
            signature_b64=sig,
            alg="ed25519",
            verify_key=verify_key,
            event_id=manifest_id_value,
            key_id=issuer_kid,
        )
    except SignatureError as exc:
        raise ManifestError(
            code="manifest.signature_invalid",
            message="manifest signature does not verify under the declared issuer key",
            context={
                "manifest_id": manifest_id_value,
                "issuer": issuer_kid,
                "underlying": exc.code,
            },
        ) from exc


def _resolve_scope_principal(event: RawEvent, manifest: RawManifest) -> dict[str, Any]:
    """Resolve the principal referenced by an event's scope_token."""
    scope_token = event.get("scope_token")
    if not isinstance(scope_token, str) or ":" not in scope_token:
        raise ScopeError(
            code="scope.missing_token",
            message=f"event has malformed scope_token {scope_token!r}",
            context={"seq": event.get("seq"), "scope_token": scope_token},
        )

    mid, _, idx_str = scope_token.rpartition(":")
    try:
        idx = int(idx_str)
    except ValueError as exc:
        raise ScopeError(
            code="scope.malformed_token",
            message=f"scope_token principal index is not an integer: {idx_str!r}",
            context={"scope_token": scope_token},
        ) from exc

    if mid != manifest.get("id"):
        raise ScopeError(
            code="scope.manifest_mismatch",
            message=(
                f"event scope_token references manifest {mid!r}, "
                f"active manifest is {manifest.get('id')!r}"
            ),
            context={
                "event_manifest": mid,
                "active_manifest": manifest.get("id"),
                "seq": event.get("seq"),
            },
        )

    principals = manifest.get("principals", [])
    if not 0 <= idx < len(principals):
        raise ScopeError(
            code="scope.principal_out_of_range",
            message=(
                f"principal index {idx} out of range (manifest has {len(principals)} principals)"
            ),
            context={"index": idx, "count": len(principals), "seq": event.get("seq")},
        )

    result: dict[str, Any] = principals[idx]
    return result


def evaluate_event_scope(event: RawEvent, manifest: RawManifest) -> bool:
    """Per spec §9.3: would this event's action pass scope evaluation?

    Returns True for non-tool events (they have no scope to evaluate) and
    True if any of the principal's scopes permits the action. Returns
    False if the manifest is expired, the tool is disallowed, or any
    resource path falls outside scope.

    Raises ``ScopeError`` if the scope_token cannot be resolved.
    """
    kind = event.get("kind", "")
    if not is_tool_kind(kind):
        return True

    principal = _resolve_scope_principal(event, manifest)

    # Manifest expiry. ISO 8601 RFC 3339 strings with fixed UTC suffix are
    # lexicographically ordered per spec §3.1.
    ts = event.get("ts", "")
    issued_at = manifest.get("issued_at", "")
    expires_at = manifest.get("expires_at", "")
    if not (issued_at <= ts <= expires_at):
        return False

    tool = event.get("tool")
    if not isinstance(tool, str):
        return False
    resources = event.get("resources", []) or []
    resource_paths = [r.get("path", "") for r in resources]

    for scope in principal.get("scopes", []):
        allow_tools = scope.get("allow_tools", [])
        deny_tools = scope.get("deny_tools", [])
        if any(tool_matches(p, tool) for p in deny_tools):
            continue
        if not any(tool_matches(p, tool) for p in allow_tools):
            continue

        allow_paths = scope.get("allow_paths", [])
        deny_paths = scope.get("deny_paths", [])

        paths_ok = True
        for rp in resource_paths:
            if any(path_matches(p, rp) for p in deny_paths):
                paths_ok = False
                break
            if allow_paths and not any(path_matches(p, rp) for p in allow_paths):
                paths_ok = False
                break
        if paths_ok:
            return True
    return False
