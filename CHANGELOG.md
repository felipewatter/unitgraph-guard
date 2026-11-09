# Changelog

## [0.1.0] — 2026-11-09

### Added
- Initial offline `systemd` service hardening and static graph analyzer with 24 explainable rules.
- JSON schema v1 for snapshots and independently reviewed policies.
- Intra-snapshot `After` / `Before` cycle detection, graph policy constraints and stable SHA-256 fingerprints.
- Regression diff and severity-based security gate; JSON and SARIF 2.1.0 exports.
- Strict bounded input, duplicate-key rejection, symlink controls and exclusive output writes.
- Deterministic release bundle, per-file integrity manifest, SHA-256 checksums and Python Wheel.
- CI matrix and gated immutable release workflow; README in Portuguese and English.
