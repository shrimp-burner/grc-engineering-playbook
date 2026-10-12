# Contributing

Thanks for taking a look. This is a small reference toolkit; the goal is clarity over cleverness.

## Guidelines

- **Standard library only.** No runtime dependencies; the value is that anyone can read and run it.
- **Small, readable modules.** Each module has one job; most expose a `run(data_dir)` entry point.
- **Tests for logic, not print output.** Unit-test the decisions (verification, dedupe, severity, parsing), not the formatting.
- **Example data stays fake.** Use the `acme-*` convention. Never commit real account IDs, keys, or customer data.
- **Fail closed.** If a tool can't determine an answer, it should surface an error, not a silent pass.

## Running locally

```bash
python -m grc_playbook demo        # end-to-end
python -m grc_playbook scenario    # narrated single-finding test case
python -m pytest -q                # unit tests
python scripts/policy_check.py     # mini policy-as-code over the Terraform example
```

## Adding a module

1. Add `src/grc_playbook/<name>.py` with a `run(data_dir: Path) -> dict` function.
2. Wire it into `cli.py`.
3. Add example data under `examples/`.
4. Add a test under `tests/`.

## Commit style

Conventional-ish and plain: `feat:`, `fix:`, `docs:`, `test:`. Keep the PR reviewable.
