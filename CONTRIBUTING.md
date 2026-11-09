# Contributing to UnitGraph Guard

Thanks for helping improve conservative offline analysis of Linux services.

1. Open an issue describing the threat model or compatibility case; **do not post live secrets**.
2. Fork and create a focused branch. Make changes with a test covering both vulnerable and safe cases.
3. Install with `python -m pip install --no-deps -e .` and run `python -m unittest discover -s tests -v`.
4. Run `python scripts/build_release.py dist` and verify reproducibility/checksums.
5. Open a pull request documenting risk, supported systemd syntax, limitations and any new false positives.
6. Do not edit existing release tags; changes to package version require consistent updates in `pyproject.toml`, `__init__.py`, docs/changelog and CI tests.

## Design principles

- Keep runtime dependency-free and offline.
- Reject malformed or uncertain security-critical data instead of guessing semantics.
- New findings must be deterministic, explainable and non-disclosing.
- Avoid `eval`, `shell=True`, remote service calls or logic requiring elevated Linux permissions.
- Test across Python 3.11, 3.12, 3.13 and all three GitHub-hosted operating systems.
- Document systemd grammar assumptions explicitly, particularly for escape sequences and drop-ins.

Contribution is subject to the MIT license and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
