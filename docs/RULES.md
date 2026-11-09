# Security rule catalog — v0.1.0

Rules use stable identifiers and predefined severities. They are **evidence-based heuristics**, not proof of exploitability. Some hardening controls may legitimately be unavailable to a particular workload; exceptions must be independently reviewed.

| Rule | Severity | Finding | Interpretation |
|---|---|---|---|
| UG001 | high | Privileged service identity | `User=` missing/root/0, except explicit policy allowlist or `DynamicUser=yes` |
| UG002 | critical | Execution privilege bypass prefix | `ExecStart*=` or related command begins with `+` or `!` systemd modifiers |
| UG003 | high | High-risk ambient/bounding capability | Explicit allowance of `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_SYS_PTRACE`, `CAP_SYS_RAWIO`, `CAP_DAC_OVERRIDE`, `CAP_BPF`, `CAP_NET_ADMIN` or `CAP_SYS_BOOT` |
| UG004 | medium | Potential secret in Environment | Variable **name** contains credential-like tokens; value never included in report |
| UG005 | high | Broad writable filesystem path | `ReadWritePaths=` / `BindPaths=` includes root or core system locations |
| UG006 | medium | NoNewPrivileges not enforced | Not enabled, except `DynamicUser=yes` implicit enforcement |
| UG007 | medium | ProtectSystem not strict | Less than `ProtectSystem=strict`, unless implied by dynamic user |
| UG008 | low | PrivateTmp not enabled | Service can share global temporary namespace, unless implicit with dynamic user |
| UG009 | medium | ProtectHome not enabled | Home directories not isolated, unless implied by dynamic user |
| UG010 | medium | Kernel tunables unprotected | `ProtectKernelTunables=` missing/false |
| UG011 | medium | Kernel modules unprotected | `ProtectKernelModules=` missing/false |
| UG012 | medium | Control groups unprotected | `ProtectControlGroups=` missing/false |
| UG013 | medium | Capability bounding set unrestricted | `CapabilityBoundingSet=` entirely missing unless dynamic user |
| UG014 | low | Address families unrestricted | `RestrictAddressFamilies=` absent or reset |
| UG015 | low | System call filtering absent | `SystemCallFilter=` absent or reset |
| UG016 | medium | World-writable default umask | `UMask=` value does not prohibit writes by others |
| UG017 | medium | Command interpreter shell | Explicit `sh` / `bash` etc with `-c`; manual review of command construction advised |
| UG018 | high | Executable or env file in shared temp | Command executable or `EnvironmentFile` points into `/tmp`, `/var/tmp` or `/dev/shm` |
| UG019 | medium | ExecStart missing | No effective `ExecStart` after drop-ins (may be intentional for some service types) |
| UG020 | high | Intra-snapshot ordering cycle | Strongly-connected component of explicit `After` / `Before` edges |
| UG021 | medium | Required dependency missing | Only in strict contract mode, for `Requires`/`Requisite`/`BindsTo` references not in snapshot |
| UG022 | high | Forbidden dependency listed | Dependency from `Wants`/`Requires`/`Requisite`/`BindsTo`/`After` appears in policy forbidden list |
| UG023 | high | Critical service depends on privileged service | Service in policy `criticalUnits` depends on a root-run service within snapshot |
| UG024 | medium | Conflicting service relation | Same unit both requires/wants and conflicts with a dependency |

## False-positive examples and review notes

`UG001`: vendor services commonly need elevated privileges. Use the policy allowlist only when approved; the exception suppresses UG001 only.

`UG017`: using an intentional shell interpreter with a constant command is not necessarily dangerous. Review whether any variable or untrusted data reaches the executed code.

`UG013`: an explicit empty `CapabilityBoundingSet=` is a restrictive configuration; the scanner treats it as **declared**. It does not model all repeated/inverted capability directives.

`UG019`: some service types may use `BusName`, `Sockets`, or other activation paths, outside the supported subset. Treat the finding as a review prompt.

`UG020`: graph only contains units included in snapshot and ordering edges; other systemd implicit dependencies or aliases are not considered.

## Risk gate

`--fail-on high` blocks critical and high rules. `--fail-on medium` blocks medium, high and critical. `--fail-on low` blocks all low-and-above. `--fail-on none` only reports.

`compare` blocks **only new findings**, not persistent findings. This encourages incremental hardening but is not a security certification of baseline.
