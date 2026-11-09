import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unitgraph_guard.cli import run
from common import SECURE

ROOT=Path(__file__).resolve().parents[1]
EXAMPLES=ROOT/'examples'


class CliTest(unittest.TestCase):
    def command(self,*args):
        stdout,stderr=io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
            ret=run(list(args))
        return ret,stdout.getvalue(),stderr.getvalue()

    def test_clean_example(self):
        code,out,err=self.command('audit','--candidate',str(EXAMPLES/'baseline.json'),'--policy',str(EXAMPLES/'policy.json'))
        self.assertEqual(code,0,err)
        self.assertEqual(json.loads(out)['verdict'],'pass')

    def test_risky_example(self):
        code,out,_=self.command('audit','--candidate',str(EXAMPLES/'candidate-risky.json'),'--policy',str(EXAMPLES/'policy.json'))
        self.assertEqual(code,2)
        self.assertEqual(json.loads(out)['verdict'],'blocked')

    def test_compare_example(self):
        code,out,err=self.command('compare','--baseline',str(EXAMPLES/'baseline.json'),'--candidate',str(EXAMPLES/'candidate-risky.json'),'--policy',str(EXAMPLES/'policy.json'))
        self.assertEqual(code,2,err)
        self.assertGreater(json.loads(out)['summary']['new']['high'],0)

    def test_compare_zero_new(self):
        code,out,_=self.command('compare','--baseline',str(EXAMPLES/'candidate-risky.json'),'--candidate',str(EXAMPLES/'candidate-risky.json'),'--policy',str(EXAMPLES/'policy.json'))
        self.assertEqual(code,0)
        self.assertEqual(json.loads(out)['summary']['new']['total'],0)

    def test_none_threshold(self):
        code,out,_=self.command('audit','--candidate',str(EXAMPLES/'candidate-risky.json'),'--fail-on','none')
        self.assertEqual(code,0)
        self.assertEqual(json.loads(out)['verdict'],'pass')

    def test_low_threshold(self):
        code,_,_=self.command('audit','--candidate',str(EXAMPLES/'candidate-risky.json'),'--fail-on','low')
        self.assertEqual(code,2)

    def test_report_files(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'report.json'; sar=Path(d)/'report.sarif'
            code,stdout,err=self.command('audit','--candidate',str(EXAMPLES/'candidate-risky.json'),'--output',str(out),'--sarif',str(sar))
            self.assertEqual(code,2,err)
            self.assertEqual(stdout,'')
            self.assertEqual(json.loads(sar.read_text())['version'],'2.1.0')
            self.assertEqual(json.loads(out.read_text())['schemaVersion'],1)

    def test_sarif_without_json_file(self):
        with tempfile.TemporaryDirectory() as d:
            sar=Path(d)/'report.sarif'
            code,out,err=self.command('audit','--candidate',str(EXAMPLES/'candidate-risky.json'),'--sarif',str(sar))
            self.assertEqual(code,2,err)
            self.assertEqual(json.loads(sar.read_text())['version'],'2.1.0')
            self.assertEqual(json.loads(out)['tool'],'unitgraph-guard')

    def test_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'exists.json';p.write_text('preserve')
            code,_,_=self.command('audit','--candidate',str(EXAMPLES/'baseline.json'),'--output',str(p))
            self.assertEqual(code,3)
            self.assertEqual(p.read_text(),'preserve')

    def test_same_output_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'same.json'
            code,_,_=self.command('audit','--candidate',str(EXAMPLES/'baseline.json'),'--output',str(p),'--sarif',str(p))
            self.assertEqual(code,3)
            self.assertFalse(p.exists())

    def test_missing_snapshot(self):
        code,_,err=self.command('audit','--candidate','/does-not-exist.json')
        self.assertEqual(code,3)
        self.assertIn('input error',err)

    def test_invalid_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'invalid.json';path.write_text('{}')
            code,_,_=self.command('audit','--candidate',str(path))
            self.assertEqual(code,3)

    def test_version_module(self):
        p=subprocess.run([sys.executable,'-m','unitgraph_guard','--version'],capture_output=True,text=True,check=False)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('0.1.0',p.stdout)

    def test_cli_help(self):
        p=subprocess.run([sys.executable,'-m','unitgraph_guard','--help'],capture_output=True,text=True,check=False)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('audit',p.stdout)
        self.assertIn('compare',p.stdout)
