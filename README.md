# agentwitness

> Verifiable evidence for AI-assisted engineering.

Capture what your coding agent did, under whose authority, with what scope —
and export signed evidence for PR review, incident response, security
questionnaires, and AI governance audits.

## Status

Pre-release. Version `0.0.1` reserves the package name; the v0 implementation
is in active development.

- Repository: <https://github.com/ConceptPending/agentwitness>
- Homepage: <https://agentwitness.dev>

## Scope

`agentwitness` captures agent actions inside Claude Code via the platform's
hook system, signs them with an Ed25519 key under the operator's control,
chains them with a verifiable hash, and produces evidence bundles that
auditors, security reviewers, and third parties can independently verify.

Four ways the same artifact gets used:

1. **Engineering** — what changed and why?
2. **Security** — what was the agent allowed to do, and did it stay in scope?
3. **Compliance** — what evidence can we show?
4. **Legal / procurement** — can we verify contractor or vendor AI usage?

## What this proves — and what it doesn't

A signed, hash-chained event log proves that captured events were not modified
after capture, and that delegated actions trace back to a root signing key.

It does **not** by itself prove completeness: in a hostile local environment
hooks can be disabled, files deleted, and tools run outside the instrumented
path. Completeness is a process problem — approved plugin configuration, CI
enforcement, retained checkpoints — not a cryptography problem.

A fuller threat-model document ships alongside the v0 release.

## License

[Apache License 2.0](./LICENSE) for code. The accompanying specification will
be licensed CC-BY-4.0 in the `spec/` directory of the v0 release.

## Author

Nick Williamson — <https://nickw.info>
