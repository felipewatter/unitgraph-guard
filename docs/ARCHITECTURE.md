# Architecture — UnitGraph Guard

## Trust boundary

```
UNTRUSTED    candidate.json ─── strict bounded reader ─── source model
REVIEWED     baseline.json ──── strict bounded reader ─── source model
TRUSTED      policy.json ────── strict bounded reader ─── independent contract
                                                     │
                                                     ▼
                                           deterministic parser
                                                     │
                                      main unit + sorted drop-ins
                                                     │
                             ┌───────────────────────┴──────────────────────────┐
                             ▼                                                  ▼
                      security rules                                    ordering graph
                             └───────────────────────┬──────────────────────────┘
                                                     ▼
                                  stable SHA-256 finding fingerprints
                                                     │
                         audit all / compare new + resolved + persistent
                                                     │
                                     severity gate / JSON / SARIF
```

### Modules

| Component | Responsibility |
|---|---|
| `model.py` | Strict JSON parsing, whitelisted schema, size limits, untrusted file access, exclusive output writes |
| `parser.py` | Conservative systemd directive parsing, scalar-last-wins, list resets, lexicographic explicit drop-ins |
| `scan.py` | Explainable UG001–UG024 hardening rules, privilege-sensitive graph checks, Tarjan SCC cycles, fingerprints and diff |
| `report.py` | Redacted deterministic report JSON and SARIF 2.1.0 |
| `cli.py` | Strict argument routing, input protection, report publication and exit codes |
| `scripts/build_release.py` | Reproducible source ZIP, per-file manifest, SHA-256 checksums and optional wheel checksum |

### Stable fingerprints

`sha256("unitgraph-v1\\0<rule-id>\\0<unit-name>\\0<nonsecret-subject>")`

Findings do not hash or embed raw environment variable values. A correction to a secret variable's value does not cause a new fingerprint if the variable's key and severity remain the same. This is intentional: the rule detects **use of that kind of environment variable**, not its value.

### Comparison and exit codes

- `audit`: gate on every finding matching the configured severity threshold.
- `compare`: gate **only** on findings absent from the approved baseline.
- `--fail-on none`: collect findings without blocking.
- `0` pass, `2` blocked, `3` invalid input or output error.

### Source fidelity and limitations

The parser is **not an emulator of PID 1**. Snapshots must contain the already selected base unit and all relevant drop-ins. No live manager state, filesystem ACLs, template instantiation or runtime expansion is interpreted. Explicit drop-ins are ordered by filename in the snapshot; host-level drop-in precedence is intentionally outside this model.

The graph contains only explicit `After`/`Before` edges connecting units in the snapshot. Requisite/Requires/Wants are inspected separately for policy violations. The graph is not a full dependency transaction planner.

All operations are local; input strings are data and never passed to `shell=True`, network requests or system service managers.

### Safety properties

1. JSON fields outside a whitelist are rejected.
2. JSON duplicates and non-finite constants are rejected.
3. Read size bounded to 2 MB total; unit count 256, drop-ins 32 per unit, unit text 100 KB.
4. Regular-file input check with `O_NOFOLLOW` where available; no symbolic link inputs.
5. No output overwrites: `O_CREAT|O_EXCL` with restrictive mode `0600`; root folder of a report must already exist.
6. Findings are deterministic and omit suspected secret values.
7. CI and immutable release are gated against the exact current `main` commit.

See [THREAT_MODEL.md](THREAT_MODEL.md) and [SCHEMA.md](SCHEMA.md).
