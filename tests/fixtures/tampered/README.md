# Fixture: tampered

Identical to `valid/` except the `outcome.message` of the `tool.completed`
event (seq 2) has been mutated from `"patched 1 hunk"` to
`"patched 2 hunks"` after signing. The stored `id` and the signature in
`signatures.jsonl` are unchanged from the valid bundle, so the recomputed
event hash no longer matches.

## Contents

Same files as `valid/`. The only difference is byte-level on `events.jsonl`
line 3.

## Expected verifier behaviour

`agentwitness verify ./tampered` MUST exit non-zero with an error
identifying the mismatched event.

Specifically:

- Manifest verification succeeds (manifest is unchanged).
- Events seq 0 and seq 1 verify cleanly.
- Event seq 2 fails with `chain.event_id_mismatch`:
  - Stored `id`: `7d0ba3a1bfbe85fb08be773cbbedc90d44482c4ca76fb0a99174f9ff8d436f0b`
  - Recomputed `id`: a different SHA-256 (depends on the mutation).
- Subsequent chain validation halts at the first failure; the verifier
  does not silently continue.

The signature in `signatures.jsonl` for seq 2 would also fail to verify
against the mutated event body, but the spec verifier algorithm
(§8 step 2) checks the `id` first, so that's the error reported.

## Why this fixture

Demonstrates that the per-event hash chain catches post-capture content
mutation. This is the most common adversarial scenario for an
append-only log — quietly editing past entries.
