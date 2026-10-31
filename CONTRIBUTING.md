# Contributing

Keep changes scoped and include a reproducible explanation of the behavior being changed. Preserve the signed payload contract or introduce a new schema identifier when compatibility changes.

## Required checks

```bash
python run.py test
python run.py check
python scripts/check_repository.py
python -m compileall -q src tests scripts
python -m build
```

Tests must cover meaningful invariants, including rejection paths. Avoid checks that simply repeat an implementation expression. Use synthetic fixtures and include no private keys, credentials or generated customer records. Keep UI labels, CLI output and documentation consistent with implemented assurance levels.

Core code is organized by responsibility. Keep normalization and policy validation separate from scoring, provenance and signing. Prefer explicit imports, descriptive names, type hints on public interfaces and docstrings describing trust-sensitive behavior. Keep HTML, CSS and JavaScript in their respective asset files. Use accessible labels, visible focus states and clear error feedback.

Review browser behavior and package assets after UI changes. Validate a built wheel from outside the source directory so path assumptions do not leak into installed behavior. Remote CI results must be checked before merging; locally passing checks do not establish that every operating system configuration passed.
