"""Input schemas, limits, and bounded file I/O for untrusted snapshots."""
from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

VERSION = 1
MAX_FILE = 2_000_000
MAX_UNITS = 256
MAX_UNIT_TEXT = 100_000
MAX_DROPINS = 32
MAX_NAME = 128
UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,119}\.service$")
DROPIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,115}\.conf$")
DEP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$")

class InputError(ValueError):
    """Input invalid, unsafe, or outside supported model."""


def _object_no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise InputError(f"duplicate JSON field: {key}")
        out[key] = value
    return out


def _reject_constant(value: str) -> Any:
    raise InputError("JSON NaN and Infinity are not supported")


def load_json(path: Path) -> Any:
    """Read exact bounded bytes after a no-follow regular-file open."""
    if path.is_symlink():
        raise InputError(f"symbolic-link input is forbidden: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            mode = os.fstat(stream.fileno()).st_mode
            if not stat.S_ISREG(mode):
                raise InputError("input must be a regular file")
            if os.fstat(stream.fileno()).st_size > MAX_FILE:
                raise InputError(f"input exceeds {MAX_FILE} bytes")
            data = stream.read(MAX_FILE + 1)
            if len(data) > MAX_FILE:
                raise InputError(f"input exceeds {MAX_FILE} bytes")
    except OSError as exc:
        raise InputError(f"cannot read input {path.name}: {exc.strerror or type(exc).__name__}") from exc
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_object_no_dupes, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InputError(f"input is not strict UTF-8 JSON: {exc}") from exc


def _fields(value: Any, keys: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InputError(f"{context} must be a JSON object")
    extra = set(value) - keys
    if extra:
        raise InputError(f"unsupported {context} fields: {', '.join(sorted(extra))}")
    return value


def _strings(value: Any, name: str, *, regex: re.Pattern[str] | None = None, limit: int = 256) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > limit:
        raise InputError(f"{name} must be an array of at most {limit} items")
    out = []
    for v in value:
        if not isinstance(v, str) or not v or len(v) > MAX_NAME or (regex and not regex.fullmatch(v)):
            raise InputError(f"invalid entry in {name}")
        if v in out:
            raise InputError(f"duplicate entry in {name}: {v}")
        out.append(v)
    return tuple(sorted(out))


@dataclass(frozen=True)
class Dropin:
    name: str
    content: str


@dataclass(frozen=True)
class Unit:
    name: str
    content: str
    dropins: tuple[Dropin, ...]


@dataclass(frozen=True)
class Snapshot:
    units: tuple[Unit, ...]


@dataclass(frozen=True)
class Policy:
    critical_units: frozenset[str]
    allowed_root_units: frozenset[str]
    forbidden_dependencies: frozenset[str]
    strict_dependencies: bool


def parse_snapshot(value: Any) -> Snapshot:
    obj = _fields(value, {"schemaVersion", "units"}, "snapshot")
    if type(obj.get("schemaVersion")) is not int or obj["schemaVersion"] != VERSION:
        raise InputError("snapshot schemaVersion must be 1")
    rows = obj.get("units")
    if not isinstance(rows, list) or not (1 <= len(rows) <= MAX_UNITS):
        raise InputError(f"units must contain 1..{MAX_UNITS} service entries")
    out: list[Unit] = []
    seen = set()
    for row in rows:
        row = _fields(row, {"name", "content", "dropins"}, "unit")
        name = row.get("name")
        content = row.get("content")
        if not isinstance(name, str) or not UNIT_RE.fullmatch(name):
            raise InputError("unit name must be a simple .service filename")
        if name in seen:
            raise InputError(f"duplicate unit {name}")
        seen.add(name)
        if not isinstance(content, str) or not content or len(content.encode("utf-8")) > MAX_UNIT_TEXT:
            raise InputError(f"invalid or oversized unit content: {name}")
        drops = row.get("dropins", [])
        if not isinstance(drops, list) or len(drops) > MAX_DROPINS:
            raise InputError(f"dropins for {name} must contain at most {MAX_DROPINS} entries")
        parsed = []
        dseen = set()
        for d in drops:
            d = _fields(d, {"name", "content"}, "dropin")
            dn, dc = d.get("name"), d.get("content")
            if not isinstance(dn, str) or not DROPIN_RE.fullmatch(dn) or dn in dseen:
                raise InputError(f"invalid or duplicate dropin name for {name}")
            if not isinstance(dc, str) or not dc or len(dc.encode("utf-8")) > MAX_UNIT_TEXT:
                raise InputError(f"invalid dropin content for {name}")
            dseen.add(dn)
            parsed.append(Dropin(dn, dc))
        out.append(Unit(name, content, tuple(sorted(parsed, key=lambda d: d.name))))
    return Snapshot(tuple(sorted(out, key=lambda u: u.name)))


def parse_policy(value: Any) -> Policy:
    o = _fields(value, {"schemaVersion", "criticalUnits", "allowedRootUnits", "forbiddenDependencies", "strictDependencies"}, "policy")
    if type(o.get("schemaVersion")) is not int or o["schemaVersion"] != VERSION:
        raise InputError("policy schemaVersion must be 1")
    critical = _strings(o.get("criticalUnits", []), "criticalUnits", regex=UNIT_RE)
    roots = _strings(o.get("allowedRootUnits", []), "allowedRootUnits", regex=UNIT_RE)
    forbidden = _strings(o.get("forbiddenDependencies", []), "forbiddenDependencies", regex=DEP_RE, limit=256)
    strict = o.get("strictDependencies", False)
    if type(strict) is not bool:
        raise InputError("strictDependencies must be boolean")
    return Policy(frozenset(critical), frozenset(roots), frozenset(forbidden), strict)


def policy_default() -> Policy:
    return parse_policy({"schemaVersion": 1})


def ensure_destination(path: Path, inputs: list[Path]) -> None:
    if path.exists() or path.is_symlink():
        raise InputError(f"refusing to overwrite existing output: {path.name}")
    if not path.parent.is_dir():
        raise InputError(f"output directory does not exist: {path.parent}")
    if path.parent.is_symlink():
        raise InputError("output parent must not be a symlink")
    p = path.absolute()
    for source in inputs:
        if p == source.absolute():
            raise InputError("output cannot overwrite an input")


def write_exclusive(path: Path, content: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise InputError(f"cannot create output {path.name}: {exc.strerror or type(exc).__name__}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as file:
            file.write(content)
    except OSError as exc:
        path.unlink(missing_ok=True)
        raise InputError(f"cannot write output {path.name}: {exc.strerror or type(exc).__name__}") from exc
