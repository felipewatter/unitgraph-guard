"""Synthetic service builders: fixtures contain no production configuration."""
from unitgraph_guard.model import parse_snapshot, policy_default
from unitgraph_guard.scan import evaluate

SECURE = """[Unit]
Description=Synthetic unit
[Service]
User=service
ExecStart=/usr/local/bin/service
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_UNIX
SystemCallFilter=@system-service
UMask=0077
"""


def scan(content=SECURE, *, name="demo.service", dropins=None, policy=None):
    source = {"schemaVersion": 1, "units": [{"name": name, "content": content, "dropins": dropins or []}]}
    return evaluate(parse_snapshot(source), policy or policy_default())


def rules(content=SECURE, **kw):
    return {r.rule_id for r in scan(content, **kw)}
