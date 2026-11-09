# UnitGraph Guard

**Offline systemd service hardening, dependency-graph and configuration-regression security gate.**

> UnitGraph Guard is a conservative, deterministic **static snapshot analyzer**. It does not execute service directives, access servers, or modify hosts. It is not a replacement for `systemd-analyze security` / `verify` or a production security assessment.

## Purpose

Systemd unit overrides can silently change service identity, hardening controls, execution behavior and dependencies. UnitGraph Guard merges explicitly supplied unit-file strings and drop-in fragments, produces 24 explainable findings (UG001–UG024), constructs an intra-snapshot ordering graph, and compares approved baseline vs candidate configuration.

- **Risk rules:** root identity, execution privilege bypass, ambient capabilities, environment-variable key names suggestive of secrets, broad writable paths, missing sandboxing, vulnerable command paths, shell launchers and missing `ExecStart`.
- **Dependency graph:** cycles among explicit `After=` / `Before=` edges, forbidden dependencies, missing required dependencies in strict snapshots, and critical-to-root dependency chains.
- **Change gating:** deterministic SHA-256 fingerprints; report `new`, `resolved` and `persistent` findings; block only newly introduced findings at the selected severity.
- **Outputs:** reproducible JSON and SARIF 2.1.0.
- **Adversarial input controls:** strict UTF-8 JSON, duplicate key rejection, bounded files and unit counts, symlink rejection and exclusive output writes.
- **Build pipeline:** matrix CI on Ubuntu/Windows/macOS with Python 3.11–3.13; immutable release tied to the exact successful `main` CI commit.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --no-deps -e .
unitgraph --version
```

## Commands

```bash
unitgraph audit --candidate examples/baseline.json --policy examples/policy.json --fail-on high
unitgraph compare --baseline examples/baseline.json --candidate examples/candidate-risky.json --policy examples/policy.json --fail-on high
unitgraph compare --baseline examples/baseline.json --candidate examples/candidate-risky.json --fail-on none --output review.json --sarif review.sarif
```

Exit codes: `0` means no gate violation; `2` means the security gate blocked the candidate; `3` means invalid input or an output I/O failure. CLI argument parse errors use argparse's standard `2` code.

## Snapshot schema

```json
{
  "schemaVersion": 1,
  "units": [
    {"name": "web.service", "content": "[Service]\nUser=web\nExecStart=/usr/local/bin/web\n", "dropins": []}
  ]
}
```

Policy: `{"schemaVersion":1,"criticalUnits":["web.service"],"allowedRootUnits":[],"forbiddenDependencies":["rescue.target"],"strictDependencies":false}`.

For complete schema and rule descriptions, see [docs/SCHEMA.md](docs/SCHEMA.md) and [docs/RULES.md](docs/RULES.md).

## Major limitations

This tool supports a documented **subset** of systemd syntax. It does not resolve live unit lookup paths, system/vendor/runtime drop-in precedence, aliases, escaped unit names, instances, templates, runtime specifier expansion, manager defaults, kernel enforcement, actual directory ACLs, or process behavior. Its graph only covers units explicitly supplied in the snapshot. Heuristic findings need human review. Never put actual secrets in snapshots.

Run `systemd-analyze verify` and `systemd-analyze security` on the intended Linux host before production deployment. See [SECURITY.md](SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Build and test

```bash
python -m pip install --no-deps -e .
python -m compileall -q src tests scripts
python -m unittest discover -s tests -v
python scripts/build_release.py dist
```

License: [MIT](LICENSE). Created by Felipe Watter. For full instructions, use the [Portuguese README](README.md).
