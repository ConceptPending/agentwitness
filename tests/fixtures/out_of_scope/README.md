# Fixture: out_of_scope

A bundle where the chain and signatures are all valid, but the manifest
does not authorise the action the recorder logged as `tool.completed`.
Models a buggy or malicious recorder that emits `tool.completed` for an
action that the spec (§9.3) requires it to emit as `tool.denied`.

## Contents

- `manifest.json` — same shape as `valid/`, but `allow_tools` is `["Read"]`
  only. The principal has no permission to use `Edit`. Different
  `manifest_id` than the valid fixture as a result.
- `events.jsonl` — three events with the same structure as `valid/`:
  `session.start`, `tool.requested` (Edit), `tool.completed` (Edit).
- `signatures.jsonl` — three signatures, all valid against the events.
- `chain.json` — head checkpoint, signed.

Every signature and hash here is correct. The bundle is internally
consistent. The violation is at the policy layer: the manifest forbade
the Edit, but the recorder completed it anyway.

## Expected verifier behaviour

`agentwitness verify ./out_of_scope` MUST exit non-zero with an error
identifying the unauthorised completion.

Specifically:

- Manifest verification succeeds.
- Chain integrity (every `id` and `prev`) verifies.
- Per-event signature verification succeeds.
- Scope evaluation rejects the `tool.completed` at seq 2 with
  `scope.unauthorised_completion`: the action does not match any
  `allow_tools` entry in the principal's scope.
- The `tool.requested` at seq 1 is also reported: per spec §9.3 it should
  have been followed by `tool.denied`, not `tool.completed`.

## Why this fixture

The verifier's job is not just to confirm that signatures match. It must
also confirm that the actions recorded as completed were actually
permitted by the manifest in force at the time. Without this check, a
recorder bug or a hostile recorder can produce internally-valid bundles
that overstate what was authorised.

This is the fixture that exercises the scope-evaluation half of the
verifier — the part that turns an event log into evidence of compliant
behaviour rather than just an immutable record.
