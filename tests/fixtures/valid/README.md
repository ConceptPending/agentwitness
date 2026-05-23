# Fixture: valid

Three-event session showing the spec's minimum coherent shape. Used as the
positive baseline against which the verifier must succeed.

## Contents

- `manifest.json` — one principal (`nick-laptop`), one scope allowing `Edit`
  on `src/**`. Signed by the issuer key
  `5876ae0e136cb79740f05a4732f5a924f0a87d80c1553d26b8dbfdfa5158eac2`.
- `events.jsonl` — three events:
  - `seq 0`: `session.start` referencing the manifest.
  - `seq 1`: `tool.requested` — agent asks to Edit `src/app.ts`.
  - `seq 2`: `tool.completed` — `request_id` points at seq 1's `event_id`,
    `outcome.message = "patched 1 hunk"`.
- `signatures.jsonl` — three detached Ed25519 signatures in event order.
- `chain.json` — one-session checkpoint with head pointer, signed.

## Expected verifier behaviour

`agentwitness verify ./valid` MUST exit 0. Specifically:

- Manifest signature validates against the declared `issuer` key.
- Each event's stored `id` matches the recomputed SHA-256 of its canonical
  body with `id` absent (spec §7.1).
- Each event's `prev` matches the previous event's computed `id`.
- Each signature in `signatures.jsonl` matches its event under the key
  declared in `actor.signer_key_id`.
- The Edit action recorded in seq 1 / seq 2 is permitted by the principal's
  scope (Edit ∈ `allow_tools`; `src/app.ts` matches `src/**`).
- The `chain.json` head matches the last event in `events.jsonl` and its
  own signature validates.

## Reproducing

The signing key, key derivation seed, and content hashes used here are all
deterministic from the inputs in `tests/fixtures/_keys/` and the helper
functions in `tests/fixtures/_tools/sign_event.py`. The file content
hashed into the event is:

- `old_content`: `b"def greet(name):\n    print('hi')\n"` (33 bytes)
- `new_content`: `b"def greet(name):\n    print(f'hi, {name}')\n"` (42 bytes)
