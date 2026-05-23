# `agentwitness` specification

Versioned specifications for the agentwitness event log, authority manifest,
signing envelope, and evidence bundle formats.

## Versioning

Specs live in this directory under `v<major>.<minor>.md`. The `v` field on
every event and manifest carries `agentwitness/<major>.<minor>` and identifies
which spec governs that artefact.

Spec changes follow:

- **Patch** (`0.1.x`) — clarifications; no wire change. Patch revisions are
  noted in the spec's document-history table without producing a new file.
- **Minor** (`0.x`) — backward-compatible additions. New file, same major.
- **Major** (`x.0`) — breaking changes. New file plus a migration document.

## Status

| Version | Status | Editor |
|---|---|---|
| [v0.1](./v0.1.md) | Draft, open for review | Nick Williamson |

## License

The specification is licensed [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/).
The reference implementation in this repository is Apache-2.0 (see `../LICENSE`).
