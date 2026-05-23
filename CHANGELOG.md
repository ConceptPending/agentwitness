# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] — 2026-05-23

First functional release.

### Added

- Claude Code hook recorder. `agentwitness install` patches
  `~/.claude/settings.json` to invoke `agentwitness hook` on
  `PreToolUse`, `PostToolUse`, `PostToolUseFailure`,
  `UserPromptSubmit`, `SessionStart`, and `SessionEnd`. Each firing
  produces a signed event in the user-level state directory.
- Ed25519 signing under the operator's key, stored in the OS keychain
  via the `keyring` library (macOS Keychain, Linux Secret Service,
  Windows Credential Manager).
- `agentwitness verify` — recomputes every event id, checks every
  detached signature, evaluates each tool action against the manifest's
  scopes, validates the chain checkpoint, and returns structured
  errors with stable codes.
- `agentwitness summary` — lists the active manifest and every
  recorded session with event count, time range, and platform session
  id.
- `agentwitness blame <path>` — shows recorded events that touched a
  file, matching by exact path or trailing path segment.
- `agentwitness export -o DIR` — assembles a verifier-ready bundle
  from the most recent (or a chosen) session.
- `agentwitness uninstall` — strips hook entries; conservative by
  default (keeps keychain and recorded sessions). `--purge-keys`,
  `--purge-state`, `--purge-all`, and `--restore-from-backup` flags
  for deeper cleanup.
- `agentwitness.Recorder` library API for GUI / Cowork plugins that
  want to record without the CLI.
- Spec v0.1 (`spec/v0.1.md`, CC-BY-4.0) defining the canonical
  serialisation (RFC 8785 JCS), event format, hash chain, signing
  envelope, manifest, and evidence bundle layout. Reserves an
  `attestations/` extension point for future RFC 3161 timestamps,
  Sigstore certificates, transparency-log proofs, and remote
  witnesses.
- Threat model (`THREAT_MODEL.md`) enumerating what a bundle does
  and does not prove, with seven attack scenarios.
- Property-based tests via Hypothesis on the security-critical
  modules (`canonical`, `chain`, `signing`, `manifest`, `paths`).
- POSIX writer lock via `fcntl` so concurrent writers in the same
  session directory do not corrupt the chain.
- Subprocess latency benchmark at `scripts/bench_hook.py`. Baseline
  on macOS / Python 3.12: ~94 ms median per hook firing.

### Known limitations

- POSIX only. Windows requires a cross-platform writer lock; deferred.
- Single-hop delegation only. Multi-hop chains for subagent → tool
  delegation are post-v0.1.
- Ed25519 only. ECDSA P-256 deferred to v0.2 for IETF AAT interop.
- File paths from Claude Code's `tool_input` are recorded
  repo-relative when inside the session's `cwd`, absolute otherwise.
  Other tools (Bash, WebFetch, WebSearch) record with an empty
  `resources` list — only the tool name is captured.
- No tarball bundle packaging; export writes a directory layout.
- TOML manifest authoring is described in the spec but not yet
  implemented; manifests are JSON-only in v0.1.

## [0.0.1] — 2026-05-23

### Added

- Initial package name reservation on PyPI. No functional code.
