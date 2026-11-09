"""Conservative subset of systemd unit-file syntax with explicit overrides."""
from __future__ import annotations

import re
from dataclasses import dataclass
from .model import InputError, Unit

KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")
SECTIONS = {"Unit", "Service", "Install"}
LIST_KEYS = {
    "ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload",
    "Environment", "EnvironmentFile", "ReadWritePaths", "ReadOnlyPaths",
    "InaccessiblePaths", "BindPaths", "AmbientCapabilities", "CapabilityBoundingSet",
    "SystemCallFilter", "RestrictAddressFamilies", "After", "Before", "Wants", "Requires",
    "Requisite", "BindsTo", "PartOf", "Conflicts", "SupplementaryGroups",
}


@dataclass(frozen=True)
class EffectiveUnit:
    name: str
    settings: dict[tuple[str, str], tuple[str, ...]]
    declared: frozenset[tuple[str, str]]

    def present(self, key: str, section: str = "Service") -> bool:
        return (section, key) in self.declared

    def all(self, key: str, section: str = "Service") -> tuple[str, ...]:
        return self.settings.get((section, key), ())

    def last(self, key: str, section: str = "Service") -> str:
        values = self.all(key, section)
        return values[-1] if values else ""

    def words(self, key: str, section: str = "Unit") -> tuple[str, ...]:
        return tuple(w for value in self.all(key, section) for w in value.split())


def parse_layer(content: str, filename: str) -> list[tuple[str, str, str]]:
    if '\x00' in content:
        raise InputError(f"NUL in unit configuration: {filename}")
    lines = content.splitlines()
    pairs: list[tuple[str, str, str]] = []
    section: str | None = None
    assembled = []
    for line in lines:
        if len(line) > 8192:
            raise InputError(f"oversized line in {filename}")
        if line.rstrip().endswith("\\"):
            assembled.append(line.rstrip()[:-1] + " ")
            if sum(map(len, assembled)) > 8192:
                raise InputError(f"oversized continuation in {filename}")
            continue
        physical = "".join(assembled) + line
        assembled.clear()
        s = physical.strip()
        if not s or s.startswith(("#", ";")):
            continue
        if s.startswith("["):
            if not s.endswith("]") or s[1:-1] not in SECTIONS:
                raise InputError(f"unsupported section in {filename}: {s[:64]}")
            section = s[1:-1]
            continue
        if section is None or "=" not in s:
            raise InputError(f"directive outside section or without '=' in {filename}")
        key, value = s.split("=", 1)
        if not KEY_RE.fullmatch(key):
            raise InputError(f"invalid directive name in {filename}")
        pairs.append((section, key, value.strip()))
        if len(pairs) > 4000:
            raise InputError(f"too many directives in {filename}")
    if assembled:
        raise InputError(f"unterminated continuation in {filename}")
    return pairs


def compose(unit: Unit) -> EffectiveUnit:
    merged: dict[tuple[str, str], list[str]] = {}
    declared: set[tuple[str, str]] = set()
    layers = [(unit.name, unit.content)] + [(d.name, d.content) for d in unit.dropins]
    for filename, content in layers:
        for section, key, value in parse_layer(content, filename):
            token = (section, key)
            declared.add(token)
            if key in LIST_KEYS:
                if value == "":
                    merged[token] = []
                else:
                    merged.setdefault(token, []).append(value)
            else:
                merged[token] = [value]
    return EffectiveUnit(unit.name, {k: tuple(v) for k, v in merged.items()}, frozenset(declared))
