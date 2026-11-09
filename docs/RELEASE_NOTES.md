# UnitGraph Guard v0.1.0 — Initial public release

Offline, deterministic systemd `.service` hardening and dependency-graph change auditor.

## Included

- 24 explainable security rules covering privileged identities, execution bypasses, shell launchers, capabilities and missing sandbox protections.
- Explicit service unit and sorted drop-in composition with documented conservative systemd grammar subset.
- Ordering graph (`After` / `Before`), cycle detection, forbidden dependencies and policy-driven critical service relationships.
- Baseline-to-candidate diff with SHA-256 fingerprints, new/resolved/persistent findings and configurable CI blocking threshold.
- Deterministic JSON/SARIF output; secret-valued Environment directives are never printed in reports.
- Bounded strict input handling, symlink rejection where supported and exclusive report creation.
- Tests, synthetic fixtures, threat model, architecture, full Portuguese README, English README, MIT license.
- GitHub Actions matrix (3 operating systems × 3 Python versions), with release publication restricted to a successful, current `main` CI commit.
- Artifacts: source ZIP, Python Wheel, manifest and SHA-256 checksums.

## Scope and limitations

**Static advisory tool only.** No connection to Linux hosts or evaluation of effective kernel permissions. The tool does not emulate complete systemd syntax, runtime state or implicit dependency resolution. Always validate with `systemd-analyze verify` and `systemd-analyze security` on the target Linux host and review changes before deployment.
