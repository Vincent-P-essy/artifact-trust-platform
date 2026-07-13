# Contributing

Contributions should preserve the security invariants in `docs/threat-model.md` and keep default
execution offline and deterministic.

## Development

```bash
uv sync --locked --extra dev
uv run ruff format --check src tests
uv run ruff check src tests
uv run mypy src
uv run pytest --cov=artifact_trust --cov-report=term-missing
```

Use Python 3.12. Regenerate `uv.lock` intentionally with `uv lock`, inspect dependency changes, and
commit the lockfile with the corresponding declaration change.

## Change requirements

- add a positive and negative test for each parser, policy or source-validation behavior;
- never place raw matched secrets in findings, logs, snapshots or test failure messages;
- keep subprocess executable selection fixed and pass argument arrays without a shell;
- document any new network access and keep it opt-in;
- add limits before accepting new archive, manifest or response formats;
- update the Rego and fallback implementation together and add parity cases;
- update threat model and limitations when a trust boundary changes;
- use inert fixtures and exact expected outcomes;
- preserve deterministic ordering and canonical JSON contracts;
- do not commit real private keys, tokens, customer data or proprietary source.

## Commit and review hygiene

Keep commits focused, explain security trade-offs, and include validation commands and observed
results in the pull request. Changes to signing, verification, source acquisition, policy or worker
isolation require explicit security review.
