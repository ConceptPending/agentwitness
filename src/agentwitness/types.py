"""Type aliases for the on-disk event, manifest, signature, and chain shapes.

These are ``TypedDict`` declarations rather than dataclasses or pydantic
models: the verifier always works against the original parsed JSON dict so
canonicalisation (RFC 8785) never round-trips through a Python representation
that might change byte-level output. Runtime validation is the responsibility
of the modules that consume each shape.

Spec references:
- §3   Identifiers, time, paths
- §5   Event format
- §6.1 Chain checkpoint
- §8   Signing envelope
- §9   Authority manifest
"""

from __future__ import annotations

import sys
from typing import Any, Literal, TypeAlias, TypedDict

if sys.version_info >= (3, 11):
    from typing import NotRequired
else:
    from typing_extensions import NotRequired

# ---- Common ----


class SessionInfo(TypedDict):
    agentwitness_id: str
    platform_id: str | None


class AgentInfo(TypedDict):
    platform: str
    model: str
    model_version: str


class DelegationGrant(TypedDict):
    grantor_key_id: str
    grantee_key_id: str
    manifest_id: str
    issued_at: str


class ActorInfo(TypedDict):
    signer_key_id: str
    principal_key_id: str
    delegation: list[DelegationGrant]


OutcomeStatus: TypeAlias = Literal["ok", "error", "denied"]


class Outcome(TypedDict):
    status: OutcomeStatus
    code: str
    message: str


# ---- Tool event sub-shapes ----


HashedKind: TypeAlias = Literal["text", "binary", "json"]


class HashedValue(TypedDict):
    kind: HashedKind
    hash: str
    size: int


ResourceType: TypeAlias = Literal["file"]
ResourceOp: TypeAlias = Literal["read", "write", "delete", "mention", "execute"]


class ResourceOperation(TypedDict):
    type: ResourceType
    op: ResourceOp
    path: str
    before_hash: str | None
    after_hash: str | None


# ---- Event ----


EventKind: TypeAlias = Literal[
    "session.start",
    "session.end",
    "user.prompt",
    "tool.requested",
    "tool.completed",
    "tool.failed",
    "tool.denied",
    "subagent.start",
    "subagent.end",
    "agent.decision",
    "authority.update",
]


class Event(TypedDict):
    """An event as it appears in events.jsonl. Tool-specific fields are
    NotRequired and MUST be absent on non-tool kinds (spec §5)."""

    v: str
    id: str
    prev: str | None
    session: SessionInfo
    seq: int
    ts: str
    kind: EventKind
    agent: AgentInfo
    actor: ActorInfo
    scope_token: str
    outcome: Outcome
    # Tool-only fields. Required if kind starts "tool.", forbidden otherwise.
    tool: NotRequired[str]
    inputs: NotRequired[dict[str, HashedValue]]
    outputs: NotRequired[dict[str, HashedValue]]
    resources: NotRequired[list[ResourceOperation]]
    request_id: NotRequired[str]


TOOL_ONLY_FIELDS: frozenset[str] = frozenset(
    {"tool", "inputs", "outputs", "resources", "request_id"}
)


def is_tool_kind(kind: str) -> bool:
    return kind.startswith("tool.")


# ---- Manifest ----


class Scope(TypedDict):
    allow_tools: list[str]
    deny_tools: list[str]
    allow_paths: list[str]
    deny_paths: list[str]
    allow_delegates: list[str]


class Principal(TypedDict):
    key_id: str
    label: str
    public_key: str  # base64-encoded raw 32-byte Ed25519 public key
    scopes: list[Scope]


class Project(TypedDict):
    name: str
    root_hash: str | None


class Manifest(TypedDict):
    v: str
    id: str
    issued_at: str
    expires_at: str
    issuer: str  # key_id of issuing key
    project: Project
    principals: list[Principal]
    sig: str  # base64-encoded Ed25519 signature


# ---- Signature ----


class Signature(TypedDict):
    event_id: str
    key_id: str
    alg: Literal["ed25519"]
    sig: str  # base64-encoded raw 64-byte signature


# ---- Chain checkpoint ----


class SessionSummary(TypedDict):
    session_agentwitness_id: str
    first_event_id: str
    head_event_id: str
    head_seq: int
    first_ts: str
    last_ts: str
    manifest_ids: list[str]


class ChainCheckpoint(TypedDict):
    v: str
    sessions: list[SessionSummary]
    sig: str  # base64-encoded Ed25519 signature over the canonical body with sig absent


# ---- Raw types used while parsing ----

# A plain JSON-decoded object before structural validation. Functions that
# accept either a raw parsed dict or a TypedDict should annotate with this.
RawEvent: TypeAlias = dict[str, Any]
RawManifest: TypeAlias = dict[str, Any]
RawSignature: TypeAlias = dict[str, Any]
RawChain: TypeAlias = dict[str, Any]
