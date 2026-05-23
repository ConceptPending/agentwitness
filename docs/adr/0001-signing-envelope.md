# ADR 0001: Signing envelope — simple custom format, not DSSE

- **Status:** Accepted
- **Date:** 2026-05-23
- **Decider:** Nick Williamson

## Context

Each event in an agentwitness log needs a detached signature. Two main
options:

1. A small JSON object per signature — `{event_id, key_id, alg, sig}` —
   one per line in `signatures.jsonl`. This is what spec v0.1 §8 describes.
2. DSSE (Dead Simple Signing Envelope), the format used by in-toto and
   SLSA. DSSE wraps the payload in a Pre-Authentication Encoding (PAE)
   string that includes a payload-type discriminator, then signs the
   encoded bytes.

The choice shapes the on-disk format, verifier complexity, and how cleanly
agentwitness can interoperate with adjacent tooling (cosign, in-toto, the
broader SLSA ecosystem).

## Decision

Use the simple custom format for v0.1.

## Why

- DSSE's primary value is interop with tools that already consume it.
  Nothing in the current consumer set verifies agentwitness bundles via
  DSSE, and no concrete demand has surfaced for it.
- The simple format is small enough to read in one sitting and implement
  on both sides in a few dozen lines. DSSE adds PAE construction and a
  payload-type field that has no consumer.
- The signed bytes under v0.1 are the canonical event body. A future DSSE
  wrapper can sign the same bytes without invalidating existing signatures,
  as long as the v0.1 verifier remains supported.
- Spec §11 already commits to migration-friendliness for adjacent
  standards, and §14 lists DSSE in the open questions. This ADR resolves
  that question in the direction of "not yet."
- v0 implementation effort is bounded. Keeping the envelope small leaves
  more room for the parts that actually need to be right: canonicalisation,
  chain integrity, manifest evaluation.

## Consequences

- Signing and verification fit in roughly 50-80 lines of Python combined.
- Spec surface around signatures is self-contained and reviewable on its
  own.
- agentwitness bundles will not verify with cosign or in-toto tools
  out of the box. A consumer that requires DSSE must run an agentwitness
  verifier or use a translator.
- A later DSSE wrapper can produce DSSE-shaped bundles from v0.1 inputs
  without a breaking change to the underlying event format.

## Alternatives considered

**DSSE as the primary envelope.** Cross-ecosystem alignment, at the cost
of PAE handling on every verifier path and a payload-type field that has
no consumer today. Worth doing once a consumer asks.

**COSE (RFC 8152).** IETF standard, comprehensive cryptographic envelope.
CBOR-based, which clashes with the JSON-canonical (RFC 8785) choice
elsewhere in the spec. Verifier complexity is materially higher. Not
warranted at v0.

**JWS / JOSE.** Widespread JSON-native signing standard. Has documented
metadata-handling footguns (alg confusion, header injection) and an
internal canonicalisation model that does not compose cleanly with JCS.
Skipped.

## Revisit

Revisit if any of the following happens:

- A customer's CI tooling needs to verify agentwitness bundles via DSSE.
- in-toto or SLSA adoption inside the target buyer segment makes
  maintaining two parallel formats more expensive than switching.
- An IETF agent-attestation draft (AAT, AIVS, ATTP) reaches working-group
  adoption with DSSE-shaped semantics.
