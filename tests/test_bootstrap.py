"""Shell bootstrap failures must stop before package installation or activation.

Only curl/dpkg/apt and a fictional release's lifecycle are substituted. All
downloaded data, extracted files and logs live in disposable temporary paths.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.geteuid() == 0, 'Bootstrap requires root; CI runs this isolated suite with sudo')
class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='makeover-bootstrap-test-')
        self.base = Path(self.temporary.name)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.log = self.base / 'calls.jsonl'
        self.environment = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'],
                                TEST_DATA=str(self.base), TEST_LOG=str(self.log))
        self.archive = self.base / 'proxmox-makeover-0.1-beta.tar.gz'
        self.members = {
            'proxmox-makeover/install.sh': b'#!/bin/bash\nset -eu\nprintf \'["stage"]\\n\' >> "$TEST_LOG"\n',
            'proxmox-makeover/scripts/lifecycle.py': (
                b'import json,os,sys\n'
                b'with open(os.environ["TEST_LOG"],"a") as f: f.write(json.dumps([sys.argv[1]])+"\\n")\n'
                b'if sys.argv[1]=="session-check" and os.environ.get("TEST_BUSY"): sys.exit(1)\n'
            ),
        }
        self.write_archive()
        self.stub('curl', '''import os,pathlib,sys,json,shutil
args=sys.argv[1:]
url=next(x for x in args if x.startswith('https://'))
target=pathlib.Path(args[args.index('-o')+1])
with open(os.environ['TEST_LOG'],'a') as f: f.write(json.dumps(['download',url,str(target)])+'\\n')
if os.environ.get('TEST_DOWNLOAD_FAIL'): sys.exit(22)
source=pathlib.Path(os.environ['TEST_DATA'])/url.rsplit('/',1)[-1]
shutil.copyfile(source,target)
''')
        self.stub('dpkg-query', '''import os,sys
if sys.argv[-1]=='pve-manager':
 print(os.environ.get('TEST_PVE_VERSION','9.2.26'))
else:
 if sys.argv[-1] in os.environ.get('TEST_MISSING','').split(','): sys.exit(1)
 print('installed')
''')
        self.stub('apt-get', '''import json,os,sys
with open(os.environ['TEST_LOG'],'a') as f: f.write(json.dumps(['apt']+sys.argv[1:])+'\\n')
if os.environ.get('TEST_APT_FAIL'): sys.exit(100)
''')

    def tearDown(self):
        self.temporary.cleanup()

    def stub(self, name, body):
        path = self.bin / name
        path.write_text('#!/usr/bin/python3\n' + body)
        path.chmod(0o755)

    def write_archive(self, extra=None):
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, data in self.members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(data))
            if extra:
                archive.addfile(extra, io.BytesIO(b'x' * extra.size) if extra.isfile() else None)
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        (self.base / 'SHA256SUMS').write_text(f'{digest}  {self.archive.name}\n')

    def run_bootstrap(self, *args, success=True):
        result = subprocess.run(['bash', str(ROOT / 'bootstrap.sh'), *args],
                                env=self.environment, text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        # The bootstrap must remove its private download directory even on failure.
        for call in calls:
            if call[0] == 'download':
                self.assertFalse(Path(call[2]).parent.exists())
                self.assertTrue(call[1].startswith('https://github.com/vipgabe09267/SLL_Proxmox_Makeover/releases/download/v0.1-beta/'))
        return calls

    def test_download_verify_stage_then_activate_without_package_changes(self):
        calls = self.run_bootstrap()
        self.assertEqual([call[0] for call in calls], ['download', 'download', 'session-check', 'stage', 'activate'])

    def test_stage_only_retains_staging_without_activation(self):
        calls = self.run_bootstrap('--stage-only')
        self.assertEqual([call[0] for call in calls], ['download', 'download', 'stage'])

    def test_only_missing_packages_are_installed_without_upgrading_existing_packages(self):
        self.environment['TEST_MISSING'] = 'python3-pil,python3-fido2'
        calls = self.run_bootstrap()
        installs = [call for call in calls if call[:2] == ['apt', 'install']]
        self.assertEqual(len(installs), 1)
        self.assertEqual(installs[0][-2:], ['python3-pil', 'python3-fido2'])
        self.assertIn('--no-upgrade', installs[0])
        self.assertLess([c[0] for c in calls].index('session-check'), [c[0] for c in calls].index('apt'))

    def test_active_console_prevents_packages_staging_and_activation(self):
        self.environment.update(TEST_BUSY='1', TEST_MISSING='python3-pil')
        calls = self.run_bootstrap(success=False)
        self.assertEqual([call[0] for call in calls], ['download', 'download', 'session-check'])

    def test_apt_failure_prevents_staging_and_activation(self):
        self.environment.update(TEST_APT_FAIL='1', TEST_MISSING='python3-pil')
        calls = self.run_bootstrap(success=False)
        self.assertEqual([call[0] for call in calls], ['download', 'download', 'session-check', 'apt'])

    def test_corrupted_archive_never_reaches_installer_or_apt(self):
        with self.archive.open('ab') as output:
            output.write(b'corrupted')
        calls = self.run_bootstrap(success=False)
        self.assertTrue(all(call[0] == 'download' for call in calls))

    def test_checksum_cannot_select_another_file(self):
        (self.base / 'SHA256SUMS').write_text('0' * 64 + '  /etc/passwd\n')
        calls = self.run_bootstrap(success=False)
        self.assertTrue(all(call[0] == 'download' for call in calls))

    def test_checksum_rejects_extra_lines(self):
        with (self.base / 'SHA256SUMS').open('a') as output:
            output.write('0' * 64 + '  another-file\n')
        calls = self.run_bootstrap(success=False)
        self.assertTrue(all(call[0] == 'download' for call in calls))

    def test_download_failure_prevents_all_installer_actions(self):
        self.environment['TEST_DOWNLOAD_FAIL'] = '1'
        calls = self.run_bootstrap(success=False)
        self.assertEqual([call[0] for call in calls], ['download'])

    def test_other_pve_major_is_rejected_before_network(self):
        self.environment['TEST_PVE_VERSION'] = '8.4.1'
        self.assertEqual(self.run_bootstrap(success=False), [])

    def test_unsafe_archive_paths_and_links_are_rejected(self):
        for name, kind in [('proxmox-makeover/../../escape', tarfile.REGTYPE),
                           ('/tmp/makeover-escape', tarfile.REGTYPE),
                           ('proxmox-makeover/symlink', tarfile.SYMTYPE)]:
            with self.subTest(name=name):
                info = tarfile.TarInfo(name)
                info.type = kind
                info.linkname = '/etc/passwd' if kind == tarfile.SYMTYPE else ''
                info.size = 1 if kind == tarfile.REGTYPE else 0
                self.write_archive(info)
                calls = self.run_bootstrap(success=False)
                self.assertTrue(all(call[0] == 'download' for call in calls))

    def test_help_and_bad_options_do_not_download(self):
        self.assertEqual(self.run_bootstrap('--help'), [])
        self.assertEqual(self.run_bootstrap('--force', success=False), [])
        self.assertEqual(self.run_bootstrap('--stage-only', 'extra', success=False), [])


if __name__ == '__main__':
    unittest.main()
