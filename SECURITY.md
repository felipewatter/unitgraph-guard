# Security policy

## Supported versions

| Version | Support |
|---|---|
| v0.1.x | Security fixes and compatibility review where feasible |
| Earlier / unpublished versions | No support commitment |

## Responsible reporting

For vulnerabilities in this project, use GitHub's **Report a vulnerability** feature in the repository Security tab when available, rather than opening a public issue containing exploit details, real credentials or production configurations. Include a minimal sanitized reproduction, expected vs observed behavior, impact, Python version and operating system. We cannot guarantee an SLA for this volunteer project.

## Safe use

- Always use synthetic data or sanitized snapshots; do **not** commit real passwords or tokens.
- Keep the independent `policy.json` protected and reviewed separately from candidate snapshots.
- Do not treat any grade, result or lack of findings as assurance of systemd or host security.
- Treat symlink and filesystem checks as defense in depth, not as a substitute for trusted workspace ownership.
- The program is read-only with respect to service configurations and never calls `systemctl` or SSH.
- Treat GitHub Actions runners and dependencies as an external supply-chain surface; the workflows pin actions by commit SHA, use read-only tokens in CI and write scope only for gated release.

## Privacy

No telemetry, analytics, network calls or remote uploads are implemented. JSON/SARIF findings redact environment **values** but can include unit names and variable names. Protect reports accordingly.
