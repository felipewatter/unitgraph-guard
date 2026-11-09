"""Offline CLI with fail-closed error codes and exclusive output creation."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from .__init__ import __version__
from .model import InputError, ensure_destination, load_json, parse_policy, parse_snapshot, policy_default, write_exclusive
from .report import audit_doc, compare_doc, json_text, sarif_doc
from .scan import LEVEL, diff, evaluate


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="unitgraph", description="Offline systemd .service hardening and graph regression analysis")
    p.add_argument("--version", action="version", version=f"unitgraph {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("audit", "compare"):
        s = sub.add_parser(name)
        s.add_argument("--candidate", type=Path, required=True, help="Candidate snapshot JSON")
        if name == "compare":
            s.add_argument("--baseline", type=Path, required=True, help="Trusted baseline snapshot JSON")
        s.add_argument("--policy", type=Path, help="Independent trusted policy JSON")
        s.add_argument("--fail-on", choices=["none", *LEVEL.keys()], default="high")
        s.add_argument("--output", type=Path, help="Write report to a NEW file; defaults to stdout")
        s.add_argument("--sarif", type=Path, help="Write SARIF to a NEW file")
    return p


def run(args: list[str] | None = None) -> int:
    parsed = build_parser().parse_args(args)
    sources = [parsed.candidate]
    if parsed.command == "compare":
        sources.append(parsed.baseline)
    if parsed.policy:
        sources.append(parsed.policy)
    outputs = [p for p in (parsed.output, parsed.sarif) if p is not None]
    try:
        if len({x.absolute() for x in outputs}) != len(outputs):
            raise InputError("JSON and SARIF output files must be different")
        for p in outputs:
            ensure_destination(p, sources)
        policy = parse_policy(load_json(parsed.policy)) if parsed.policy else policy_default()
        candidate = evaluate(parse_snapshot(load_json(parsed.candidate)), policy)
        if parsed.command == "audit":
            doc = audit_doc(candidate, parsed.fail_on)
            emitted = candidate
        else:
            baseline = evaluate(parse_snapshot(load_json(parsed.baseline)), policy)
            parts = diff(baseline, candidate)
            doc = compare_doc(parts, parsed.fail_on)
            emitted = parts["new"]
        json_out = json_text(doc)
        sarif_out = json_text(sarif_doc(emitted)) if parsed.sarif else None
        created = []
        try:
            if parsed.output:
                write_exclusive(parsed.output, json_out)
                created.append(parsed.output)
            if parsed.sarif and sarif_out is not None:
                write_exclusive(parsed.sarif, sarif_out)
                created.append(parsed.sarif)
        except InputError:
            for file in created:
                file.unlink(missing_ok=True)
            raise
        if not parsed.output:
            print(json_out, end="")
        return 2 if doc["verdict"] == "blocked" else 0
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return 3


def main() -> int:
    return run()
