import unittest
from unitgraph_guard.model import InputError, parse_snapshot
from unitgraph_guard.parser import parse_layer, compose
from common import SECURE


class ParserTest(unittest.TestCase):
    def parse(self, content, dropins=None):
        row = {"name": "svc.service", "content": content, "dropins": dropins or []}
        return compose(parse_snapshot({"schemaVersion": 1, "units": [row]}).units[0])

    def test_scalar_last_wins(self):
        u = self.parse('[Service]\nUser=alice\nUser=bob\n')
        self.assertEqual(u.last('User'), 'bob')

    def test_dropin_order(self):
        u = self.parse('[Service]\nUser=alice\n', [
            {"name": "90-last.conf", "content": '[Service]\nUser=carol\n'},
            {"name": "10-first.conf", "content": '[Service]\nUser=bob\n'}])
        self.assertEqual(u.last('User'), 'carol')

    def test_execstart_reset(self):
        u = self.parse('[Service]\nExecStart=/bin/a\n', [
            {"name": "10-reset.conf", "content": '[Service]\nExecStart=\nExecStart=/bin/b\n'}])
        self.assertEqual(u.all('ExecStart'), ('/bin/b',))

    def test_dependencies_accumulate(self):
        u = self.parse('[Unit]\nAfter=a.service\nAfter=b.service c.service\n[Service]\nUser=alice\n')
        self.assertEqual(u.words('After'), ('a.service', 'b.service', 'c.service'))

    def test_dependencies_reset(self):
        u = self.parse('[Unit]\nAfter=a.service\n', [
            {"name": "20.conf", "content": '[Unit]\nAfter=\nAfter=b.service\n'}])
        self.assertEqual(u.words('After'), ('b.service',))

    def test_comments(self):
        self.assertEqual(self.parse(';comment\n# comment\n[Service]\nUser=alice\n').last('User'), 'alice')

    def test_continuation(self):
        u = self.parse('[Service]\nUser=alice\nExecStart=/bin/echo hello \\\n  world\n')
        self.assertEqual(u.last('ExecStart'), '/bin/echo hello    world')

    def test_unknown_directives_preserved(self):
        self.assertEqual(self.parse('[Service]\nMyExtension=x\n').last('MyExtension'), 'x')

    def test_missing_sections(self):
        for s in ('ExecStart=/bin/true', 'foo', '[Unknown]\nFoo=x', '[Service\nUser=x', '[Service]\nfoo bar'):
            with self.subTest(s=s), self.assertRaises(InputError): parse_layer(s, 'fixture')

    def test_reject_nul(self):
        with self.assertRaises(InputError): parse_layer('[Service]\nUser=x\x00', 'fixture')

    def test_reject_unterminated_continuation(self):
        with self.assertRaises(InputError): parse_layer('[Service]\nUser=x\\', 'fixture')

    def test_reject_line_size(self):
        with self.assertRaises(InputError): parse_layer('[Service]\nUser=' + 'a'*9000, 'fixture')

    def test_scope_sections(self):
        u = self.parse('[Unit]\nDescription=x\n[Service]\nUser=alice\n[Install]\nWantedBy=multi-user.target\n')
        self.assertEqual(u.last('WantedBy', 'Install'), 'multi-user.target')
