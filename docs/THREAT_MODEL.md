# Threat model — UnitGraph Guard

## Security objective

Detect potentially dangerous **changes in declared systemd `.service` configuration** before merge or host deployment, with stable local evidence and no remote side effects.

## Assets

- Approved baseline snapshot; high-value representation of expected service configuration.
- Independent reviewed policy (root exceptions, critical units, forbidden dependencies).
- Candidate snapshot supplied by a contributor or change pipeline.
- CI decision (exit 0/2/3), JSON/SARIF reports and immutable GitHub release artifacts.

## Threat actors and trust boundaries

1. A contributor could submit a malicious candidate snapshot or attempt to alter the policy in the same PR.
2. An untrusted JSON file could exhaust memory, hide a duplicate field, use symlink indirection, or attempt report overwrites.
3. A service maintainer could weaken drop-in hardening or introduce privilege bypass prefixes, dangerous capabilities, cycles, dependencies or writable paths.
4. A failed or stale CI run must not cause a release of a different commit.

## Mitigations

| Threat | Control |
|---|---|
| Input bomb / malformed JSON | 2MB limit, UTF-8 decoding, regular-file check, duplicate-key and NaN rejection, bounded units and drop-ins |
| Host file symlinks | `O_NOFOLLOW` where supported; no permission to write inputs; output created with `O_EXCL` |
| Secret leakage to CI logs | Report only variable **key names**; no full directive values or command lines |
| Unauthorized root exceptions | Separate policy source and explicit allowlist; review changes to policy independently |
| Dangerous `ExecStart=+` / `!` | High/critical explainable rule; flags additive overrides |
| Hardening regressions | Independent 24-rule engine and stable fingerprint diff |
| Cyclic ordering | Deterministic strongly-connected-components analysis within provided units |
| Dependency-trust crossing | Critical unit -> root service check, forbidden dependencies |
| Untrusted PR release | Release gated on successful CI push to `main`, same-repo origin, exact tested SHA; refuses to rewrite tags/releases |

## Explicit non-goals and residual risks

- **Not a systemd or Linux sandbox simulator.** Host kernel configuration, filesystem ACLs, inherited manager settings, Linux capabilities in executed binaries, runtime tokens and network access remain unknown.
- **Not complete systemd grammar.** Generic drop-ins, templates, aliases, instance resolution, symlink unit paths, specifiers and full escaping are not interpreted.
- **Not complete graph reasoning.** Only explicit `After` / `Before` relationships among included units are used for cycle detection; missing units can hide a cycle.
- **Not a secrets scanner.** A secret can have an innocent variable name and a benign-looking variable can be flagged. Raw snapshot text still contains the value in process memory and original file.
- **Not an injection proof.** Shell invocation findings are review indicators.
- **Not an operational enforcement tool.** No `systemctl`, SSH, shell interpretation of unit text or server modifications.
- **Output race limits.** Directory entry changes by another privileged process, filesystems with different O_EXCL semantics or remote network filesystems are not modeled. Use private, trusted workspaces.
- **External actions.** GitHub Actions permissions, runner image behavior, package index availability and platform features can change; monitor CI failures.

## Security testing protocol

- Test every rule and its negative counterpart with synthetic fixtures.
- Test booleans, UMask, unsupported section names, malformed JSON, duplicate keys, symlinks, oversize inputs.
- Test deterministic fingerprints and reproducible release ZIP bytes.
- Test clean baseline and blocked candidate in every GitHub Actions matrix target.
- Verify exact `main` commit equals the release tag commit; ensure SHA-256 manifest aligns with the ZIP.

## Incident response

Do not auto-apply changes when a security gate fails. Preserve the report without credentials; validate with `systemctl cat`, `systemd-analyze verify`, `systemd-analyze security` and host change logs, then adjust the unit or request policy exception review. For issues in this open-source tool, use private vulnerability reporting if enabled; see `SECURITY.md`.
