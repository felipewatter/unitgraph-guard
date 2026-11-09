# Input schema — UnitGraph Guard v1

## Snapshot JSON

Required fields: `schemaVersion` (integer `1`), `units` (array of 1–256 entries). Every entry must contain `name` and `content`; `dropins` is optional.

```json
{
  "schemaVersion": 1,
  "units": [
    {
      "name": "app.service",
      "content": "[Unit]\nAfter=network.target\n[Service]\nUser=app\nExecStart=/usr/bin/app\n",
      "dropins": [
        {"name": "50-local.conf", "content": "[Service]\nNoNewPrivileges=yes\n"}
      ]
    }
  ]
}
```

| Field | Rules |
|---|---|
| `name` | Filename ending in `.service`, simple ASCII `A-Za-z0-9_.@:-`, max ~128 chars |
| `content` | UTF-8 text, nonempty, max 100,000 bytes |
| `dropins` | 0–32 objects with unique ASCII `*.conf` names and UTF-8 content, each max 100,000 bytes |
| `schemaVersion` | Exactly integer `1`; booleans are rejected |

Snapshot file limit: 2,000,000 bytes, regular file, not symlink. JSON object keys must be unique and all fields must match the schema. JSON `NaN` / `Infinity` are rejected. Input files should be stored in trusted directories.

## Policy JSON

```json
{
  "schemaVersion": 1,
  "criticalUnits": ["api.service"],
  "allowedRootUnits": ["approved-helper.service"],
  "forbiddenDependencies": ["rescue.target", "debug-root.service"],
  "strictDependencies": false
}
```

- `criticalUnits` marks services whose dependencies on root-run services trigger **UG023**.
- `allowedRootUnits` suppresses only UG001 for named units, **not** other hardening rules and not UG023.
- `forbiddenDependencies` applies to `Wants`, `Requires`, `Requisite`, `BindsTo`, and `After`.
- `strictDependencies=true` flags dependencies from `Requires`, `Requisite`, and `BindsTo` absent from the snapshot. Use only on inventories intended to be complete.
- All lists default to empty; `strictDependencies` defaults to false.
- Never let an untrusted change request author its own approval policy without review.

## Supported fragment syntax

- Sections `[Unit]`, `[Service]`, `[Install]`.
- `Key=Value`, no whitespace allowed in the key name. Leading/trailing whitespace on the value is stripped.
- Full-line `#` and `;` comments, and simple `\\` line continuations.
- Scalar assignments: last assignment wins, including within sorted drop-ins.
- List assignments such as `ExecStart`, `After`, `Before`, `Requires`, `Wants`, `Environment`, `ReadWritePaths` accumulate. A blank list assignment resets preceding values.
- *Drop-ins* must be explicitly included in the snapshot; their names are sorted lexicographically.
- Unknown directive names in supported sections are retained but **not** interpreted as hardening controls.

The parser deliberately **does not** implement all systemd syntax: prefix precedence across `/etc`, `/run` and vendor directories; templates/instances/aliases; `service.d` generic drop-ins; unit `Includes` or generators; nontrivial quoting/escaping; manager defaults; all list directive semantics; `ExecStart` specifier expansion; kernel enforcement. For `CapabilityBoundingSet=` an explicitly blank reset is recognized as a declared restrictive value, but intricate capability combination rules are not fully modeled. See the official systemd manuals and inspect the target host configuration before deployment.

## Report JSON

```json
{
  "schemaVersion": 1,
  "tool": "unitgraph-guard",
  "version": "0.1.0",
  "mode": "audit",
  "verdict": "blocked",
  "threshold": "high",
  "summary": {"total": 1, "info": 0, "low": 0, "medium": 0, "high": 1, "critical": 0},
  "findings": [
    {
      "ruleId": "UG001",
      "severity": "high",
      "unit": "example.service",
      "subject": "",
      "message": "Privileged service identity",
      "fingerprint": "...64 hex chars..."
    }
  ]
}
```

A comparison report uses `mode="compare"`, `gate="new-findings-only"`, and arrays `new`, `persistent`, `resolved` with independent summary counts. The `snapshot.json` SARIF artifact URI is a generic snapshot reference rather than an actual file-system path.

**Redaction:** rules report directive names and nonsecret subjects (unit names, environment keys, capabilities). They do not report environment values or full commands. Do not put live credentials in inputs: the process still reads raw source text into memory.
