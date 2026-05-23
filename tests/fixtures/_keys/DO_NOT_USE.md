# Test fixture keys — do not use anywhere else

The Ed25519 keypair in this directory is generated from a fixed, publicly
documented seed and lives in the repository so that the fixtures under
`tests/fixtures/` are reproducible.

**The private key in this directory is not a secret.**

It exists only to sign fixture data. Do not use it for anything that
matters. Do not copy it into production. Do not use the same seed pattern
for any real key.

The seed used to derive the key is:

```
b"agentwitness-fixture-key-nick-laptop-v01"[:32]
```

If you need to regenerate the keys, see `tests/fixtures/_tools/README.md`.

The `key_id` (lowercase hex SHA-256 of the raw public key bytes) is:

```
5876ae0e136cb79740f05a4732f5a924f0a87d80c1553d26b8dbfdfa5158eac2
```

This `key_id` appears in every fixture's `manifest.json` and
`signatures.jsonl`.
