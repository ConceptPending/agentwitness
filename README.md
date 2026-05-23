# agentwitness

Record what your coding agent did, under whose authority, with what scope,
and produce signed evidence anyone can verify offline. Useful for PR review,
incident response, security questionnaires, and AI governance audits.

```
$ agentwitness summary
manifest: 7c6adca6eae24556f8215314cdb74094aa31fe3c747a508d3ef16fe60205a608
  issued:  2026-05-23 17:32:57
  expires: 2027-05-23 17:32:57

sessions (2):
  sess_d3cf2597d1b39167aa6e3a     3 events  2026-05-23 17:32:57 → 17:32:57  (claude-vis-test)
  sess_c23db027e0ddf6e57bf9b7    18 events  2026-05-23 14:14:23 → 14:48:01  (claude-session-2)

$ agentwitness blame src/auth.ts
events touching src/auth.ts:
  2026-05-23 14:18:42  tool.requested   Edit   sess_c23db027e0ddf6e  (ok)
  2026-05-23 14:18:43  tool.completed   Edit   sess_c23db027e0ddf6e  (ok)

$ agentwitness export -o ./evidence
Bundle written to ./evidence
Verify with: agentwitness verify ./evidence

$ agentwitness verify ./evidence
agentwitness verify: OK  (./evidence)
  events verified:   18
  sessions seen:     1
```

## Status

**v0.1, pre-release.** First useful end-to-end path is in: record via
Claude Code hooks, export a bundle, verify it. POSIX only (Linux and
macOS); Windows support pending a cross-platform writer lock. API may
shift before v0.2.

The repo is currently private. The PyPI package name is reserved but
the published artefact is a stub — install from source until v0.1.0
ships there.

## Quickstart

```bash
# Install from source while the repo is private
pipx install git+ssh://git@github.com/ConceptPending/agentwitness.git

# One-time setup: generates an Ed25519 keypair in your OS keychain,
# writes a default manifest, and adds hook entries to ~/.claude/settings.json
# A .bak of any existing settings.json is written first.
agentwitness install

# Use Claude Code normally. Every PreToolUse / PostToolUse / SessionStart
# fires a hook that records a signed event into <state>/sessions/.

# See what was recorded
agentwitness summary
agentwitness blame src/path/to/file

# Build an evidence bundle from the most recent session
agentwitness export -o ./evidence

# Confirm the bundle is internally consistent
agentwitness verify ./evidence

# Uninstall (conservative — keeps keychain and recorded sessions)
agentwitness uninstall
```

## What this proves — and what it doesn't

A bundle that passes `agentwitness verify` proves that the captured
events were not modified after capture and that each one was signed by
the key declared in the manifest.

It does **not** prove:

- **Completeness.** A hostile local environment can disable hooks, delete
  files, or run tools outside the instrumented path. The bundle records
  what was captured, not what existed.
- **External identity.** The bundle proves *a* key signed it — not that
  the key belongs to a particular person, machine, or organisation. That
  binding is a separate concern (pin the public key in a registry, post
  it on a known site, use Sigstore-style OIDC, etc.).
- **Semantic intent.** "The agent edited `auth.py`" is in the record.
  Whether that edit was malicious, careless, or in scope is a human
  judgment the bundle supports but does not make.

Full enumeration in [`THREAT_MODEL.md`](./THREAT_MODEL.md).

## Architecture

Three pieces, all small:

- **Recorder.** A Claude Code hook entry point (`agentwitness hook`)
  reads the hook payload, builds an event, signs it with the Ed25519
  key from the OS keychain, and appends it to `events.jsonl` plus
  `signatures.jsonl` inside a session directory.
- **Verifier.** Reads a bundle, recomputes every event id, checks every
  signature, evaluates each tool action against the manifest's scopes,
  and re-checks the chain checkpoint. Errors are accumulated and
  reported with stable error codes.
- **Spec.** [`spec/v0.1.md`](./spec/v0.1.md) defines the on-disk format
  both sides agree on — canonical serialisation (RFC 8785 JCS), the
  event schema, the signing envelope, the manifest, and the bundle
  layout. The spec is the source of truth; if the code and spec
  disagree, the spec wins.

## Configuration

State lives under:

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/agentwitness/` |
| Linux | `$XDG_DATA_HOME/agentwitness/` or `~/.local/share/agentwitness/` |
| Windows | `%APPDATA%/agentwitness/` (not yet supported in v0.1) |

Override either path for testing:

- `AGENTWITNESS_STATE_DIR` — overrides the state root.
- `AGENTWITNESS_CLAUDE_SETTINGS` — overrides the path to Claude Code's
  `settings.json` that the install command patches.

The signing key never leaves the OS keychain except as a working copy
in the recorder process. To rotate keys, run `agentwitness uninstall
--purge-keys` and then `agentwitness install` again. Old bundles still
verify against the old public key recorded in their manifest.

## Uninstall

```bash
# Default — strips hook entries, keeps keychain and recorded sessions
agentwitness uninstall

# Restore ~/.claude/settings.json from the .bak written at install time
agentwitness uninstall --restore-from-backup

# Also delete the keychain entry. Old bundles still verify (their
# manifest contains the public key) but you can no longer sign new events
# under that label.
agentwitness uninstall --purge-keys

# Also delete the state directory. Removes the manifest and every
# recorded session.
agentwitness uninstall --purge-state

# Shorthand for --purge-keys + --purge-state
agentwitness uninstall --purge-all
```

## Roadmap

Deferred to post-v0.1:

- Multi-hop delegation chains (subagent → tool token flow)
- ECDSA P-256 signing for interop with IETF AAT
- The optional `attestations/` bundle directory (RFC 3161 timestamps,
  Sigstore certificates, transparency-log inclusion proofs, remote
  witnesses) — reserved in the spec, no concrete formats yet
- DSSE envelope adoption
- TOML manifest authoring with a JSON canonical export
- Windows-compatible writer lock
- Multi-machine session merging
- Tarball bundle packaging
- Hosted dashboard / Cowork plugin (the Python API at
  `Recorder.bootstrap` is the integration surface)

See the open questions in [`spec/v0.1.md` §14](./spec/v0.1.md#14-open-questions).

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the local setup, test
commands, commit conventions, and review flow.

Bug reports and design discussion belong in
[GitHub issues](https://github.com/ConceptPending/agentwitness/issues).
Security issues: see [`SECURITY.md`](./SECURITY.md).

## License

[Apache License 2.0](./LICENSE) for the code.

The specification under [`spec/`](./spec/) is licensed
[CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/).
