import json
import os
import tempfile
import unittest
from pathlib import Path
from unitgraph_guard.model import (InputError, load_json, parse_snapshot, parse_policy,
                                   policy_default, ensure_destination, write_exclusive)
from common import SECURE


class ModelTest(unittest.TestCase):
    def valid(self):
        return {"schemaVersion": 1, "units": [{"name": "demo.service", "content": SECURE}]}

    def test_roundtrip(self):
        v = parse_snapshot(self.valid())
        self.assertEqual(len(v.units), 1)
        self.assertEqual(v.units[0].name, "demo.service")

    def test_order_deterministic(self):
        a = self.valid()
        a["units"] += [{"name": "a.service", "content": SECURE}]
        self.assertEqual([u.name for u in parse_snapshot(a).units], ["a.service", "demo.service"])

    def test_policy_defaults(self):
        self.assertFalse(policy_default().strict_dependencies)

    def test_policy_explicit(self):
        p = parse_policy({"schemaVersion": 1, "criticalUnits": ["api.service"],
                          "allowedRootUnits": ["root.service"], "forbiddenDependencies": ["rescue.target"],
                          "strictDependencies": True})
        self.assertIn("api.service", p.critical_units)
        self.assertTrue(p.strict_dependencies)

    def test_reject_snapshots(self):
        invalid = [None, [], {}, {"schemaVersion": True, "units": []}, {"schemaVersion": 1, "units": []},
                   {"schemaVersion": 2, "units": [self.valid()["units"][0]]},
                   {"schemaVersion": 1, "units": "x"},
                   {"schemaVersion": 1, "units": [self.valid()["units"][0]], "unknown": 1}]
        for x in invalid:
            with self.subTest(data=x), self.assertRaises(InputError):
                parse_snapshot(x)

    def test_reject_units(self):
        bads = [{"name": "../../x.service", "content": SECURE}, {"name": "foo.socket", "content": SECURE},
                {"name": "demo.service", "content": ""}, {"name": 9, "content": SECURE},
                {"name": "demo.service", "content": SECURE, "wat": True},
                {"name": "demo.service", "content": SECURE, "dropins": "foo"},
                {"name": "demo.service", "content": SECURE, "dropins": [{"name": "../a.conf", "content": SECURE}]},
                {"name": "demo.service", "content": SECURE, "dropins": [{"name": "a.conf", "content": ""}]},
                {"name": "demo.service", "content": SECURE * 8000}]
        for row in bads:
            with self.subTest(row=str(row)[:50]), self.assertRaises(InputError):
                parse_snapshot({"schemaVersion": 1, "units": [row]})

    def test_reject_duplicate_units(self):
        row = self.valid()["units"][0]
        with self.assertRaises(InputError):
            parse_snapshot({"schemaVersion": 1, "units": [row, row]})

    def test_reject_duplicate_dropins(self):
        row = self.valid()["units"][0]
        row["dropins"] = [{"name": "10-a.conf", "content": SECURE}] * 2
        with self.assertRaises(InputError):
            parse_snapshot({"schemaVersion": 1, "units": [row]})

    def test_reject_policy(self):
        for item in ({}, {"schemaVersion": 1, "strictDependencies": 1},
                     {"schemaVersion": 1, "criticalUnits": ["../evil.service"]},
                     {"schemaVersion": 1, "allowedRootUnits": ["a.service", "a.service"]},
                     {"schemaVersion": 1, "unexpected": 1},
                     {"schemaVersion": 1, "forbiddenDependencies": "x"}):
            with self.subTest(item=item), self.assertRaises(InputError):
                parse_policy(item)

    def test_load_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "input.json"
            p.write_text('{"schemaVersion":1,"units":[]}', encoding="utf-8")
            self.assertEqual(load_json(p)["schemaVersion"], 1)

    def test_duplicate_keys_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "dup.json"
            p.write_text('{"schemaVersion":1,"schemaVersion":1}', encoding="utf-8")
            with self.assertRaises(InputError): load_json(p)

    def test_nonfinite_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "nf.json"
            p.write_text('{"v":NaN}', encoding="utf-8")
            with self.assertRaises(InputError): load_json(p)

    def test_non_utf8_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"
            p.write_bytes(b'\xff')
            with self.assertRaises(InputError): load_json(p)

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            a, link = Path(d) / "real", Path(d) / "link"
            a.write_text('{}')
            try: link.symlink_to(a)
            except OSError: self.skipTest("symlink unavailable")
            with self.assertRaises(InputError): load_json(link)

    def test_directory_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(InputError): load_json(Path(d))

    def test_limit_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "big"
            p.write_bytes(b'x' * 2_000_001)
            with self.assertRaises(InputError): load_json(p)

    def test_exclusive_output(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "out.json"
            ensure_destination(p, [])
            write_exclusive(p, '{}')
            with self.assertRaises(InputError): ensure_destination(p, [])
            with self.assertRaises(InputError): write_exclusive(p, 'bad')
            self.assertEqual(p.read_text(), '{}')

    def test_same_input_output_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "input"
            with self.assertRaises(InputError): ensure_destination(p, [p])

    def test_missing_output_dir_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(InputError): ensure_destination(Path(d) / "nope" / "x", [])

    def test_symlink_output_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            existing = Path(d) / "real"
            existing.write_text('safe')
            link = Path(d) / "out"
            try: link.symlink_to(existing)
            except OSError: self.skipTest("symlink unavailable")
            with self.assertRaises(InputError): ensure_destination(link, [])

class ExtendedModelTest(unittest.TestCase):
    def test_policy_forbidden_control_chars(self):
        with self.assertRaises(InputError):
            parse_policy({'schemaVersion':1,'forbiddenDependencies':['bad\nservice']})
