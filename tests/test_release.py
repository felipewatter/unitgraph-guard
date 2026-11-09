import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unitgraph_guard import __version__

ROOT = Path(__file__).resolve().parents[1]
PREFIX = f'unitgraph-guard-v{__version__}'

class ReleaseTest(unittest.TestCase):
    def build(self, directory):
        proc = subprocess.run([sys.executable, str(ROOT/'scripts/build_release.py'), str(directory)],capture_output=True,text=True)
        self.assertEqual(proc.returncode,0,proc.stderr)
        return directory/(PREFIX+'-source.zip'), directory/(PREFIX+'-manifest.json'), directory/(PREFIX+'-SHA256SUMS.txt')

    def test_zip_present(self):
        with tempfile.TemporaryDirectory() as d:
            for p in self.build(Path(d)):self.assertTrue(p.exists())

    def test_manifest_matches_zip(self):
        with tempfile.TemporaryDirectory() as d:
            a,m,_ = self.build(Path(d))
            manifest=json.loads(m.read_text())
            self.assertEqual(manifest['version'],__version__)
            with zipfile.ZipFile(a) as z:
                self.assertEqual(len(z.namelist()),len(manifest['sha256']))
                for name in z.namelist():
                    self.assertTrue(name.startswith(PREFIX+'/'))
                    self.assertNotIn('..',name.split('/'))
                    rel=name.split('/',1)[1]
                    self.assertEqual(hashlib.sha256(z.read(name)).hexdigest(),manifest['sha256'][rel])

    def test_checksums(self):
        with tempfile.TemporaryDirectory() as d:
            a,m,c=self.build(Path(d))
            actual={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (a,m)}
            reported={name:digest for digest,name in (line.split('  ',1) for line in c.read_text().splitlines())}
            self.assertEqual(actual,reported)

    def test_deterministic(self):
        with tempfile.TemporaryDirectory() as a,tempfile.TemporaryDirectory() as b:
            left=self.build(Path(a));right=self.build(Path(b))
            self.assertEqual([hashlib.sha256(p.read_bytes()).hexdigest() for p in left],
                             [hashlib.sha256(p.read_bytes()).hexdigest() for p in right])

    def test_exclude_local_junk(self):
        with tempfile.TemporaryDirectory() as d:
            a,_,_=self.build(Path(d))
            with zipfile.ZipFile(a) as z:
                for name in z.namelist():
                    self.assertNotIn('__pycache__',name)
                    self.assertNotIn('.egg-info',name)
                    self.assertNotIn('/dist/',name)
                    self.assertNotIn('/.git/',name)
                    self.assertFalse(name.endswith('.pyc'))

    def test_docs_and_workflows_present(self):
        with tempfile.TemporaryDirectory() as d:
            a,_,_=self.build(Path(d))
            with zipfile.ZipFile(a) as z:
                names=set(z.namelist())
                for required in ['README.md','README.en.md','LICENSE','SECURITY.md','docs/THREAT_MODEL.md',
                                 'docs/ARCHITECTURE.md','docs/SCHEMA.md','.github/workflows/ci.yml',
                                 '.github/workflows/release.yml','pyproject.toml']:
                    with self.subTest(required=required):self.assertIn(PREFIX+'/'+required,names)

    def test_wheel_checksum_included(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)
            wheel=folder/f'unitgraph_guard-{__version__}-py3-none-any.whl'
            wheel.write_bytes(b'test-fixture-only')
            _,_,checksums=self.build(folder)
            self.assertIn(wheel.name,checksums.read_text())
