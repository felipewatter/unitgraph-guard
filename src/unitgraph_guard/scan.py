"""Deterministic, explainable offline security rules and dependency analysis."""
from __future__ import annotations

import hashlib
import posixpath
import re
import shlex
from dataclasses import dataclass
from typing import Iterable
from .model import InputError, Policy, Snapshot
from .parser import EffectiveUnit, compose

LEVEL = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RULE_DESCRIPTIONS: dict[str, tuple[str, str]] = {
    "UG001": ("Privileged service identity", "high"),
    "UG002": ("Execution privilege bypass prefix", "critical"),
    "UG003": ("High-risk ambient capability", "high"),
    "UG004": ("Potential secret in Environment directive", "medium"),
    "UG005": ("Broad writable filesystem path", "high"),
    "UG006": ("NoNewPrivileges not enforced", "medium"),
    "UG007": ("ProtectSystem not strict", "medium"),
    "UG008": ("PrivateTmp not enabled", "low"),
    "UG009": ("ProtectHome not enabled", "medium"),
    "UG010": ("Kernel tunables unprotected", "medium"),
    "UG011": ("Kernel modules unprotected", "medium"),
    "UG012": ("Control groups unprotected", "medium"),
    "UG013": ("Capability bounding set unrestricted", "medium"),
    "UG014": ("Address families unrestricted", "low"),
    "UG015": ("System call filtering absent", "low"),
    "UG016": ("World-writable default umask", "medium"),
    "UG017": ("Command interpreter launches a shell", "medium"),
    "UG018": ("Command or environment file under shared temporary directory", "high"),
    "UG019": ("ExecStart is missing", "medium"),
    "UG020": ("Intra-snapshot ordering cycle", "high"),
    "UG021": ("Required dependency missing from strict snapshot", "medium"),
    "UG022": ("Forbidden dependency listed", "high"),
    "UG023": ("Critical service requires a privileged service", "high"),
    "UG024": ("Conflicting service relation", "medium"),
}
RISK_CAPS = {"CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_SYS_RAWIO", "CAP_DAC_OVERRIDE", "CAP_BPF", "CAP_NET_ADMIN", "CAP_SYS_BOOT"}
TRUE = {"yes", "true", "on", "1"}
FALSE = {"no", "false", "off", "0", ""}
SECRET_RE = re.compile(r"(?i)(?:secret|password|passwd|token|private[_-]?key|api[_-]?key|credential)")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
SHARED = ("/tmp/", "/var/tmp/", "/dev/shm/")

@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    unit: str
    subject: str
    message: str
    fingerprint: str

    def to_dict(self) -> dict:
        return {"ruleId": self.rule_id, "severity": self.severity, "unit": self.unit,
                "subject": self.subject, "message": self.message, "fingerprint": self.fingerprint}


def finding(rule_id: str, unit: str, subject: str = "") -> Finding:
    title, severity = RULE_DESCRIPTIONS[rule_id]
    return Finding(rule_id, severity, unit, subject, title,
                   hashlib.sha256(f"unitgraph-v1\0{rule_id}\0{unit}\0{subject}".encode()).hexdigest())


def is_enabled(value: str, setting: str) -> bool:
    v = value.lower()
    if v in TRUE:
        return True
    if v in FALSE:
        return False
    raise InputError(f"invalid boolean for {setting}")


def has_strict_fs(u: EffectiveUnit) -> bool:
    return is_enabled(u.last("DynamicUser"), "DynamicUser") or u.last("ProtectSystem").lower() == "strict"


def is_root(u: EffectiveUnit) -> bool:
    return not is_enabled(u.last("DynamicUser"), "DynamicUser") and u.last("User").lower() in ("", "root", "0")


def _emits_for_unit(u: EffectiveUnit, policy: Policy) -> list[Finding]:
    name = u.name
    out: list[Finding] = []

    def add(rule: str, subject: str = "") -> None:
        out.append(finding(rule, name, subject))

    dynamic = is_enabled(u.last("DynamicUser"), "DynamicUser")
    if is_root(u) and name not in policy.allowed_root_units:
        add("UG001")
    privileged_exec = ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload")
    exec_items = [(key, value) for key in privileged_exec for value in u.all(key)]
    for key, value in exec_items:
        prefix = re.match(r"^[-+!@:]*(?=/|[A-Za-z0-9_])", value)
        modifiers = prefix.group(0) if prefix else ""
        if "+" in modifiers or "!" in modifiers:
            add("UG002", key)
        cmd = value[len(modifiers):]
        try:
            args = shlex.split(cmd)
        except ValueError:
            raise InputError(f"unbalanced quoted command in unit {name}") from None
        if not args:
            raise InputError(f"empty non-reset command in {name}")
        exe = args[0]
        if exe.startswith(SHARED):
            add("UG018", key)
        if exe.rsplit("/", 1)[-1] in ("sh", "bash", "dash", "zsh", "ksh") and any(re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", flag) for flag in args[1:]):
            add("UG017", key)
    if not u.all("ExecStart"):
        add("UG019")

    for cap_value in u.all("AmbientCapabilities"):
        if cap_value and not cap_value.startswith("~"):
            for cap in sorted(RISK_CAPS.intersection(cap_value.split())):
                add("UG003", cap)
    for cap_value in u.all("CapabilityBoundingSet"):
        if cap_value and not cap_value.startswith("~"):
            for cap in sorted(RISK_CAPS.intersection(cap_value.split())):
                add("UG003", "bounding:" + cap)
    for env in u.all("Environment"):
        try:
            assignments = shlex.split(env)
        except ValueError:
            raise InputError(f"unbalanced Environment assignment in {name}") from None
        for item in assignments:
            if "=" in item:
                namepart = item.split("=", 1)[0]
                if not ENV_KEY_RE.fullmatch(namepart):
                    raise InputError(f"invalid Environment variable name in {name}")
                if SECRET_RE.search(namepart):
                    add("UG004", namepart.upper())
    for value in u.all("EnvironmentFile"):
        for namepart in value.split():
            p = namepart.lstrip("-")
            if p.startswith(SHARED):
                add("UG018", "EnvironmentFile")
    for val in u.all("ReadWritePaths") + u.all("BindPaths"):
        for p in val.split():
            p = posixpath.normpath(p.lstrip("-+"))
            if p in ("/", "/etc", "/usr", "/var", "/root"):
                add("UG005", p)

    if not (dynamic or is_enabled(u.last("NoNewPrivileges"), "NoNewPrivileges")):
        add("UG006")
    protect_system = u.last("ProtectSystem").lower()
    if protect_system not in ("", "no", "yes", "true", "false", "full", "strict", "on", "off", "0", "1"):
        raise InputError(f"invalid ProtectSystem in {name}")
    if not has_strict_fs(u):
        add("UG007")
    private_tmp = u.last("PrivateTmp").lower()
    if not dynamic and private_tmp != "disconnected" and not is_enabled(private_tmp, "PrivateTmp"):
        add("UG008")
    protect_home = u.last("ProtectHome").lower()
    if protect_home not in ("", "no", "yes", "true", "false", "read-only", "tmpfs", "on", "off", "0", "1"):
        raise InputError(f"invalid ProtectHome in {name}")
    if not (dynamic or protect_home in ("yes", "true", "read-only", "tmpfs", "on", "1")):
        add("UG009")
    for key, rule in (("ProtectKernelTunables", "UG010"), ("ProtectKernelModules", "UG011"), ("ProtectControlGroups", "UG012")):
        if not is_enabled(u.last(key), key):
            add(rule)
    if (not u.present("CapabilityBoundingSet") or u.all("CapabilityBoundingSet") == ("~",)) and not dynamic:
        add("UG013")
    if not u.all("RestrictAddressFamilies"):
        add("UG014")
    if not u.all("SystemCallFilter"):
        add("UG015")
    mask = u.last("UMask")
    if mask:
        if not re.fullmatch("[0-7]{3,4}", mask):
            raise InputError(f"invalid UMask in {name}")
        if int(mask, 8) & 0o002 == 0:
            add("UG016")
    return out


def _strongly_connected(graph: dict[str, set[str]]) -> list[list[str]]:
    index = 0
    stack: list[str] = []
    onstack: set[str] = set()
    indices: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    components: list[list[str]] = []

    def visit(v: str) -> None:
        nonlocal index
        indices[v] = lowlink[v] = index
        index += 1
        stack.append(v)
        onstack.add(v)
        for w in sorted(graph[v]):
            if w not in indices:
                visit(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in onstack:
                lowlink[v] = min(lowlink[v], indices[w])
        if lowlink[v] == indices[v]:
            group = []
            while True:
                w = stack.pop()
                onstack.remove(w)
                group.append(w)
                if v == w:
                    break
            if len(group) > 1 or (len(group) == 1 and group[0] in graph[group[0]]):
                components.append(sorted(group))

    for vertex in sorted(graph):
        if vertex not in indices:
            visit(vertex)
    return sorted(components)


def evaluate(snapshot: Snapshot, policy: Policy) -> tuple[Finding, ...]:
    units = {unit.name: compose(unit) for unit in snapshot.units}
    out: list[Finding] = []
    graph = {name: set() for name in units}
    for name, u in units.items():
        out += _emits_for_unit(u, policy)
        for other in u.words("After"):
            if other in units:
                graph[other].add(name)
        for other in u.words("Before"):
            if other in units:
                graph[name].add(other)
        for key in ("Requires", "Requisite", "BindsTo"):
            for other in u.words(key):
                if policy.strict_dependencies and other not in units:
                    out.append(finding("UG021", name, other))
        for key in ("Requires", "Requisite", "Wants", "BindsTo", "After"):
            for other in u.words(key):
                if other in policy.forbidden_dependencies:
                    out.append(finding("UG022", name, other))
                if name in policy.critical_units and other in units and is_root(units[other]):
                    out.append(finding("UG023", name, other))
        for other in u.words("Conflicts"):
            if other in u.words("Requires") or other in u.words("Wants"):
                out.append(finding("UG024", name, other))
    for component in _strongly_connected(graph):
        out.append(finding("UG020", component[0], ",".join(component)))
    # A single finding per fingerprint, even if multiple directive instances restate a problem.
    return tuple(sorted({x.fingerprint: x for x in out}.values(), key=lambda x:(-LEVEL[x.severity], x.rule_id, x.unit, x.subject)))


def diff(base: Iterable[Finding], candidate: Iterable[Finding]) -> dict[str, tuple[Finding, ...]]:
    b = {x.fingerprint: x for x in base}
    c = {x.fingerprint: x for x in candidate}
    sorter = lambda records: tuple(sorted(records, key=lambda x:(-LEVEL[x.severity], x.rule_id, x.unit, x.subject)))
    return {"new": sorter(c[k] for k in c.keys() - b.keys()),
            "resolved": sorter(b[k] for k in b.keys() - c.keys()),
            "persistent": sorter(c[k] for k in c.keys() & b.keys())}
