"""Stable JSON and SARIF output; redact untrusted configuration values."""
from __future__ import annotations

import json
from typing import Iterable
from .__init__ import __version__
from .scan import Finding, LEVEL, RULE_DESCRIPTIONS


def summary(records: Iterable[Finding]) -> dict[str, int]:
    rows = list(records)
    return {"total": len(rows), **{s: sum(r.severity == s for r in rows) for s in LEVEL}}


def audit_doc(records: tuple[Finding, ...], threshold: str) -> dict:
    blocked = any(LEVEL[r.severity] >= LEVEL[threshold] for r in records) if threshold != "none" else False
    return {"schemaVersion": 1, "tool": "unitgraph-guard", "version": __version__, "mode": "audit",
            "verdict": "blocked" if blocked else "pass", "threshold": threshold,
            "summary": summary(records), "findings": [r.to_dict() for r in records]}


def compare_doc(parts: dict[str, tuple[Finding, ...]], threshold: str) -> dict:
    blocked = any(LEVEL[r.severity] >= LEVEL[threshold] for r in parts["new"]) if threshold != "none" else False
    return {"schemaVersion": 1, "tool": "unitgraph-guard", "version": __version__, "mode": "compare",
            "gate": "new-findings-only", "verdict": "blocked" if blocked else "pass", "threshold": threshold,
            "summary": {k: summary(v) for k, v in parts.items()},
            **{k: [r.to_dict() for r in v] for k, v in parts.items()}}


def sarif_doc(records: Iterable[Finding]) -> dict:
    rows = list(records)
    rules = sorted({r.rule_id for r in rows})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "unitgraph-guard", "version": __version__,
                "informationUri": "https://github.com/felipewatter/unitgraph-guard",
                "rules": [{"id": rule, "shortDescription": {"text": RULE_DESCRIPTIONS[rule][0]}} for rule in rules]}},
                "results": [{"ruleId": r.rule_id, "level": ("error" if r.severity in ("high", "critical") else "warning" if r.severity == "medium" else "note"),
                             "message": {"text": f"{r.message} (unit: {r.unit}; context: {r.subject or 'service'})"},
                             "fingerprints": {"unitgraph/v1": r.fingerprint},
                             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "snapshot.json"}}}]} for r in rows]}]}


def json_text(document: dict) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
