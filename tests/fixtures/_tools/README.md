# Fixture tooling

These scripts are scaffolding for hand-authoring the fixture bundles in
sibling directories. They are not part of the agentwitness runtime.

The leading underscore on `_tools/` and `_keys/` signals that nothing in
here is part of the test suite proper or the public API.

## What lives here

- `sign_event.py` — a small calculator used to compute canonical event
  bytes, derive `event_id` per spec §7.1, and produce Ed25519 signatures
  for hand-authored fixtures. The fixtures themselves are checked in as
  final artefacts; this script documents how the cryptographic fields
  inside them were produced and lets a reviewer reproduce them.

## How to regenerate the test keypair

If the deterministic seed in `_keys/DO_NOT_USE.md` ever needs to change,
regenerate with:

```python
from nacl.signing import SigningKey
import binascii

seed = b"<your new public seed>"[:32]
sk = SigningKey(seed=seed)
pk = sk.verify_key
print(binascii.hexlify(bytes(sk)).decode())
print(binascii.hexlify(bytes(pk)).decode())
```

Then update every fixture that references the old `key_id`. Don't try to
keep older fixtures verifying against the new key — the easier path is to
regenerate the fixtures entirely.
