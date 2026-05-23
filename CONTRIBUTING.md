# Contributing

Thanks for picking this up. agentwitness is a small, security-adjacent
library — the bar for changes is fewer surprises, not more features.

## Local setup

```bash
git clone git@github.com:ConceptPending/agentwitness.git
cd agentwitness
python -m pip install -e ".[dev]"
```

Python 3.10, 3.11, or 3.12. The same matrix runs in CI.

## Checks before opening a PR

```bash
ruff check .
ruff format --check .
mypy --strict src/agentwitness
pytest
```

All four must pass. The coverage gate is currently 85% branch coverage.

For the property tests in the security-critical modules (`canonical`,
`chain`, `signing`, `manifest`, `paths`), Hypothesis runs at the `dev`
profile by default (50 examples per property). To run the more
aggressive `ci` profile locally:

```bash
AGENTWITNESS_HYPOTHESIS_PROFILE=ci pytest
```

## Commit style

Conventional Commits. Each commit does one thing and explains *why* in
the body, not just *what*. Common prefixes:

- `feat(<scope>):` new behaviour
- `fix(<scope>):` bug fix
- `refactor(<scope>):` no behaviour change
- `docs:` documentation only
- `test:` tests only
- `ci:` CI configuration
- `chore:` housekeeping (deps, version bumps, formatting)

Subject line under ~70 characters. Body wrapped at ~72. Reference the
spec section number when the change touches the on-disk format, for
example "spec §6.1 chain checkpoint".

## Branches and merges

Branch off `main`. Push branches named `<type>/<short-slug>` — for
example `feat/recorder-primitives` or `fix/hook-command-resolution`.

PRs merge into `main` with `--no-ff` so each branch lands as a visible
unit in `git log --graph`. Squash if a branch has noisy intermediate
commits, but prefer landing a small number of well-shaped commits over
a single squash.

## Spec changes

The spec at [`spec/v0.1.md`](./spec/v0.1.md) is the source of truth for
the on-disk format. If the code and spec disagree, the spec wins. Any
change that affects the wire format requires:

1. A spec revision (bump the rev letter in the document history table).
2. A commit message that explains the motivation.
3. A test that locks in the new behaviour.

If a change would invalidate existing bundles produced by an older
version of the recorder, that is a major version bump — coordinate
before opening the PR.

## Threat model changes

[`THREAT_MODEL.md`](./THREAT_MODEL.md) is the authoritative description
of what the verifier proves and does not prove. If your change affects
either list, update `THREAT_MODEL.md` *first*, then make the code
change.

## Architecture Decision Records

Substantial design choices get an ADR under [`docs/adr/`](./docs/adr/).
Copy `docs/adr/template.md` and pick the next number. ADRs are short
and immutable once accepted — if a decision changes, add a new ADR that
supersedes the old one.

## Reporting bugs

Open an issue. Include:

- agentwitness version (`agentwitness --version`)
- OS and Python version
- The exact command you ran
- What you expected vs. what happened

For security issues, see [`SECURITY.md`](./SECURITY.md).

## Code of conduct

Be civil. Disagree about the work, not the person. No private code of
conduct doc exists yet; the [Contributor Covenant](https://www.contributor-covenant.org/)
captures the baseline.
