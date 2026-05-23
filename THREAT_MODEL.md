# Threat Model — agentwitness v0.1

**Status:** Draft. Evolves with the spec.
**Scope:** the on-disk format and verifier behaviour. Deployment posture is
not in scope here — that lives in the operating-model docs.

This is the authoritative description of what an agentwitness bundle does
and does not prove. If a README, launch post, or marketing line contradicts
this document, the other text is wrong and gets fixed.

## What a passing bundle proves

Given a bundle and the public keys named in its manifests, `agentwitness
verify` proves:

1. **Events were not modified after capture.** The per-event hash chain
   and per-event signatures bind every event's bytes to its position in
   the chain.
2. **Signed events came from the named key.** A valid Ed25519 signature
   over the canonical event body, by the key in `actor.signer_key_id`,
   attests that the holder of that key signed those bytes.
3. **Delegation chains end at a declared principal.** Where
   `actor.principal_key_id` differs from `actor.signer_key_id`, the
   manifest scope referenced by `scope_token` grants the signer permission
   to act on the principal's behalf.
4. **Scope decisions are internally consistent.** Where a `tool.denied`
   event appears, the action would have failed scope evaluation against
   the active manifest.

## What a passing bundle does not prove

1. **Completeness.** The bundle records what the recorder captured. It
   does not show that everything the agent did was captured. Hooks can be
   disabled, files deleted, the agent run outside the instrumented path.
   Completeness is a process problem — see below.
2. **Semantic intent.** "The agent edited `auth.py`" is in the record.
   Whether the edit was malicious, careless, scoped, or in good faith is
   a human judgment.
3. **Key security.** A stolen private key produces signatures that pass.
   Detection of theft requires key revocation, not the bundle.
4. **Causation.** Events are ordered. Order is not causation.
5. **External identity.** The bundle proves a key signed it. It does not
   prove the key belongs to a particular person, machine, or organisation.
   That needs a trust anchor — see spec §11.

## Threat actors considered

| Actor | Capabilities |
|---|---|
| Honest operator | Runs the recorder as intended. |
| Lazy operator | Disables hooks selectively to avoid friction. Runs the agent outside the instrumented path. |
| Compromised local environment | Has code execution as the operator user. Can read keychain entries and modify files. |
| Network-only attacker | Sees bundles in transit. No local access. |
| Hostile receiver | The verifying party would prefer to reject the bundle. |
| Malicious contractor | Generates a self-consistent bundle signed with their own key. |

## Attack scenarios

**A. Post-hoc event tampering.**
Adversary changes `outcome.message` after capture. `event_id` recomputes
differently from the stored value; verifier rejects with
`chain.event_id_mismatch`.

**B. Signature replacement.**
Adversary swaps a signature for one made with their own key.
`signature.key_id` no longer matches `actor.signer_key_id`; verifier
rejects with `signature.key_mismatch`. Forging both fields consistently
fails differently: the new key is not authorised by the manifest's
`principals`, so scope evaluation fails.

**C. Chain truncation.**
Adversary deletes events from the middle of `events.jsonl`. The first
surviving event's `prev` no longer matches its predecessor's id; verifier
rejects with `chain.prev_mismatch`. Truncation from the tail is
detectable only when a `chain.json` head checkpoint is available — see
the process controls section.

**D. Manifest swap.**
Adversary substitutes a more permissive manifest for the one in force.
Either the new manifest has a different `manifest_id` (events referencing
the old `scope_token` fail to resolve) or the issuer signature does not
validate.

**E. Recorder bypass.**
Adversary runs the agent without the hook installed. The bundle contains
no record of those actions. Verification of present events succeeds.
Catching the bypass requires CI enforcement that the bundle covers the
time window of the changes — process control, not bundle property.

**F. Malicious-contractor self-consistent bundle.**
Contractor signs with their own key, claiming events that did not happen.
The bundle verifies internally. The customer catches this only with a
trust anchor — pinned key, OIDC binding, organisation registry, or
out-of-band key exchange.

**G. Timing manipulation.**
Adversary sets event timestamps to misleading values. The chain does not
depend on timestamps. Order is provable. Absolute time needs an external
timestamping authority (RFC 3161 or a trusted signed clock); v0.1 does
not provide one.

## Process controls assumed by deployment

These live outside the spec but have to exist for the bundle's guarantees
to matter in practice:

- **Approved configuration.** Claude Code managed settings so the recorder
  cannot be silently disabled.
- **CI enforcement.** Reject PRs whose bundle is missing, unverifiable, or
  fails to cover the time window of the proposed changes.
- **Retained chain checkpoints.** Periodically commit signed chain heads
  to a shared store so tail truncation becomes detectable.
- **Review policy.** Reviewers consult `summary.md` and `diff-map.json`
  during code review.
- **Trust anchor.** Without one, a bundle proves consistency, not identity.

## Known weaknesses in v0.1

- Single-hop delegation only. Multi-hop is post-v0.
- Bash scopes are advisory. `argv[0]` is not a security boundary by itself
  (see spec §9.4).
- Ed25519 only. ECDSA P-256 may arrive in v0.2 for AAT interop.
- No timestamping authority. Order is provable; absolute time is not.
- No key revocation primitive. A compromised key remains valid for the
  lifetime of any manifest that names it.

## Versioning

Changes to what the bundle does or does not prove require a spec revision.
Document the change here first.

## Document history

| Version | Date | Editor | Notes |
|---|---|---|---|
| 0.1 | 2026-05-23 | Nick Williamson | Initial threat model for spec v0.1. |
