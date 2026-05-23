# Test fixtures

Hand-authored bundle fixtures used to drive the verifier (Phase 3 onward).

The fixtures are the canonical "what does the spec mean in practice"
artefact. Reading the spec while these fixtures sit next to it should
remove most ambiguity. If a fixture and the spec disagree, the spec is
the source of truth and the fixture gets regenerated.

## Layout

| Directory | Purpose |
|---|---|
| `valid/` | Three-event session, all signatures and scopes correct. Positive baseline. |
| `tampered/` | Identical to `valid/` except one event's `outcome.message` was mutated post-signing. Negative test for the hash chain. |
| `out_of_scope/` | Internally valid chain and signatures, but the manifest forbids the action the recorder logged as `tool.completed`. Negative test for scope evaluation. |
| `_keys/` | Test-only Ed25519 keypair shared across all fixtures. See `_keys/DO_NOT_USE.md`. |
| `_tools/` | Signature-calculator scaffolding used to author the fixtures. See `_tools/README.md`. |

The leading underscore on `_keys/` and `_tools/` marks them as not part
of the public surface or the test suite proper; pytest collection ignores
them by convention.

## How the fixtures were produced

1. Generate a deterministic Ed25519 keypair from a fixed, publicly
   documented seed.
2. Build each manifest body, compute its `manifest_id` per spec §7.3,
   sign it.
3. Build each event body, compute its `event_id` per spec §7.1, sign
   the canonical body with `id` present per spec §7.2.
4. Write `manifest.json`, `events.jsonl`, `signatures.jsonl`.
5. Build the session checkpoint, sign `chain.json`.

The Python used to drive the build lives only in `_tools/sign_event.py`
(helpers) and in the commit history. The fixtures themselves are the
artefacts.

## Expected verifier behaviour

See each fixture's `README.md`. In summary:

- `valid/` — verifier exits 0.
- `tampered/` — verifier exits non-zero, error class `chain.event_id_mismatch`.
- `out_of_scope/` — verifier exits non-zero, error class `scope.unauthorised_completion`.

These three outcomes are the Phase 3 acceptance criterion for the
verifier.
