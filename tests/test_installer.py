"""Installer lifecycle and guard regression tests; all writes are temporary."""
import importlib.util
import importlib.machinery
import fcntl
import json
import os
import pwd
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

REPO = Path(__file__).resolve().parents[1]
LEGACY = REPO / 'tests/fixtures/legacy'
spec = importlib.util.spec_from_file_location('makeover_lifecycle', REPO / 'scripts/lifecycle.py')
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='makeover-install-test-')
        self.root = Path(self.tmp.name)
        self.put('/usr/share/pve-manager/index.html.tpl', '<head>\n<!-- current package -->\n<script src="/pve2/js/pvemanagerlib.js"></script>\n</head>\n')
        self.put('/usr/share/pve-manager/js/pvemanagerlib.js', '\n'.join("Ext.define('" + name + "', {});" for name in ('PVE.window.LoginWindow', 'PVE.node.Summary', 'PVE.node.StatusView')))
        self.put('/usr/share/javascript/proxmox-widget-toolkit/themes/theme-proxmox-dark.css', '/* current vendor theme */')
        self.put('/usr/share/javascript/proxmox-widget-toolkit/images/proxmox_logo.svg', '<svg>current native</svg>')
        self.put('/usr/share/pve-manager/images/proxmox_logo.png', b'current native logo')
        self.put('/usr/share/pve-manager/images/logo-128.png', b'current native icon')
        self.layout = lifecycle.Layout(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, name, data):
        path = self.root / name.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode() if isinstance(data, str) else data)
        return path

    def invoke(self, *arguments, expected=0):
        result = subprocess.run(['bash', str(REPO / 'install.sh'), '--root', str(self.root), *arguments], capture_output=True, text=True)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def cli(self, command, *arguments, expected=0):
        result = subprocess.run(['python3', str(REPO / 'scripts/lifecycle.py'), command, '--root', str(self.root), *arguments], capture_output=True, text=True)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def test_fixture_install_real_helper_and_modes(self):
        self.invoke('--no-activate')
        template = self.layout.path('/usr/share/pve-manager/index.html.tpl').read_text()
        self.assertIn('BEGIN SOUTHLAND BRANDING', template)
        self.assertIn('current package', template)
        manifest = self.layout.json(lifecycle.MANIFEST)
        self.assertEqual(manifest['version'], '0.1-beta')
        for name in ('/usr/local/libexec/sll-pveproxy', '/usr/local/libexec/sll-pvedaemon', '/usr/local/sbin/proxmox-makeover'):
            self.assertEqual(self.layout.path(name).stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.layout.path(lifecycle.CONFIG).stat().st_mode & 0o777, 0o600)
        self.cli('status')
        self.assertFalse(self.layout.path('/etc/systemd/system/sls-proxmox-branding.timer').exists())
        self.assertTrue(self.layout.path('/usr/local/lib/site_perl/PVE/API2/SLLPasskeys.pm').is_file())
        self.assertEqual(self.layout.path('/usr/local/libexec/proxmox-makeover/passkeys.py').stat().st_mode & 0o777, 0o755)
        self.assertTrue(self.layout.path('/usr/local/share/sls-proxmox-branding/makeover/login-passkeys.js').is_file())

    @unittest.skipUnless(os.geteuid() == 0, 'Live constructor ownership checks require root; no host write occurs')
    def test_double_slash_root_is_live_and_alternate_fixture_spelling_is_normalized(self):
        # Constructor-only regression: never invoke install/service actions on
        # either spelling of the live filesystem root.
        with patch.object(lifecycle.Layout, 'json', side_effect=lambda _name, default=None: default):
            live = lifecycle.Layout('//')
        self.assertTrue(live.live)
        self.assertEqual(live.root, Path('/'))
        fixture = lifecycle.Layout('/' + str(self.root))
        self.assertFalse(fixture.live)
        self.assertEqual(fixture.root, self.root)

    def test_staging_never_changes_installed_canonical_files(self):
        marker = self.put(lifecycle.HELPER, b'current installer')
        self.put(lifecycle.CONFIG, b'current config')
        with self.layout.locked(), patch.object(lifecycle, 'run', side_effect=AssertionError('Staging invoked a subprocess')):
            lifecycle.stage(self.layout, REPO)
        self.assertEqual(marker.read_bytes(), b'current installer')
        self.assertEqual(self.layout.path(lifecycle.CONFIG).read_bytes(), b'current config')
        self.assertFalse(self.layout.path(lifecycle.DROPINS[0]).exists())
        staged = self.layout.json(lifecycle.PENDING)
        self.assertTrue(self.layout.path(staged['release'] + '/install.sh').is_file())
        self.assertFalse(self.layout.path(staged['release'] + '/.dev').exists())

    def test_stage_and_archive_share_allowlist_and_exclude_private_state(self):
        source = self.root / 'source'
        source.mkdir()
        for item in lifecycle.selected_release_inputs(REPO):
            target = source / item.relative_to(REPO)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item, target)
        for relative in ('.env', '.passkeys-browser/state.json', 'tests/private/credential.json',
                         'tests/fixtures/generated/state.json', 'docs/recovery.key'):
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('private fixture material must not be staged or published')
        with self.layout.locked():
            lifecycle.stage(self.layout, source)
        release = self.layout.path(self.layout.json(lifecycle.PENDING)['release'])
        for relative in ('.env', '.passkeys-browser', 'tests/private', 'tests/fixtures/generated/state.json', 'docs/recovery.key'):
            self.assertFalse((release / relative).exists(), relative)
        self.assertTrue((release / 'scripts/release_inputs.py').is_file())
        self.assertTrue((release / 'login-passkeys.js').is_file())
        result = subprocess.run(['python3', str(source / 'tools/build-release.py')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        import tarfile
        with tarfile.open(source / 'dist/proxmox-makeover-0.1-beta.tar.gz') as archive:
            names = set(archive.getnames())
        self.assertEqual(names, {'proxmox-makeover/' + str(item.relative_to(release)) for item in release.rglob('*') if item.is_file()})
        self.assertFalse(any('private fixture material' in (release / name).read_text(errors='ignore') for name in ('.gitignore', 'README.md')))

    def test_upgrade_preserves_configuration_and_uploaded_artwork(self):
        self.invoke()
        path = self.layout.path(lifecycle.CONFIG)
        config = json.loads(path.read_text())
        config['company_name'] = 'Example Operations'
        path.write_text(json.dumps(config))
        logo = self.layout.path('/usr/local/share/sls-proxmox-branding/assets/SLS_Proxmox.png')
        # Existing valid custom artwork is preserved exactly across upgrades.
        custom = (REPO / 'assets/SLS_Proxmox_Favicon.png').read_bytes()
        logo.write_bytes(custom)
        self.invoke()
        self.assertEqual(json.loads(path.read_text())['company_name'], 'Example Operations')
        self.assertEqual(logo.read_bytes(), custom)

    def test_failure_restores_previous_payload_and_keeps_evidence(self):
        marker = self.put(lifecycle.HELPER, b'#!/bin/sh\nexit 0\n')
        marker.chmod(0o755)
        before = marker.read_bytes()
        self.put('/usr/share/pve-manager/index.html.tpl', '<future unknown architecture>')
        self.invoke(expected=1)
        self.assertEqual(marker.read_bytes(), before)
        latest = self.layout.json(lifecycle.STATE + '/latest-transaction.json')
        transaction = self.layout.json(latest['transaction'] + '/transaction.json')
        self.assertEqual(transaction['status'], 'rolled-back')
        self.assertFalse(self.layout.path(lifecycle.DROPINS[0]).exists())

    def test_fresh_failed_install_removes_all_new_canonical_files(self):
        self.put('/usr/share/pve-manager/index.html.tpl', '<future unknown architecture>')
        before = {str(path.relative_to(self.root)): path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        self.invoke(expected=1)
        after = {str(path.relative_to(self.root)): path.read_bytes() for path in self.root.rglob('*')
                 if path.is_file() and not str(path.relative_to(self.root)).startswith(('var/lib/proxmox-makeover/', 'run/lock/'))
                 and str(path.relative_to(self.root)) != 'var/lib/sls-proxmox-branding/overlay.lock'}
        self.assertEqual(after, before)
        self.assertFalse(self.layout.path(lifecycle.MANIFEST).exists())
        self.assertFalse(self.layout.path('/etc/sls-proxmox-branding.disabled').exists())

    def test_failed_recovery_keeps_maintenance_marker_until_guarded_rollback(self):
        self.invoke()
        with self.layout.locked(), patch.object(lifecycle, 'helper_locked', side_effect=RuntimeError('apply failed')), patch.object(lifecycle, 'restore_snapshot', side_effect=RuntimeError('recovery failed')):
            with self.assertRaisesRegex(RuntimeError, 'apply failed'):
                lifecycle.install(self.layout, REPO, False)
        self.assertEqual(self.layout.json(lifecycle.MAINTENANCE)['status'], 'recovery-required')
        latest = self.layout.json(lifecycle.STATE + '/latest-transaction.json')
        self.assertEqual(self.layout.json(latest['transaction'] + '/transaction.json')['status'], 'recovery-required')
        with self.layout.locked():
            lifecycle.rollback(self.layout, False)
        self.assertFalse(self.layout.path(lifecycle.MAINTENANCE).exists())

    def test_interrupted_marker_survives_failure_to_prepare_recovery(self):
        self.invoke()
        self.layout.save(lifecycle.MAINTENANCE, {'operation': 'install', 'pid': os.getpid(), 'status': 'recovery-required'})
        with self.layout.locked(), patch.object(lifecycle, 'snapshot', side_effect=RuntimeError('snapshot unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'snapshot unavailable'):
                lifecycle.rollback(self.layout, False)
        self.assertEqual(self.layout.json(lifecycle.MAINTENANCE)['status'], 'recovery-required')

    def test_passkey_credentials_survive_upgrade_uninstall_and_rollback(self):
        self.invoke()
        private = self.layout.path(lifecycle.STATE + '/passkeys')
        private.mkdir(mode=0o700)
        path = self.put(lifecycle.STATE + '/passkeys/state.json', b'isolated credential state')
        path.chmod(0o600)
        self.invoke()
        self.cli('uninstall')
        self.assertEqual(path.read_bytes(), b'isolated credential state')
        self.cli('rollback')
        self.assertEqual(path.read_bytes(), b'isolated credential state')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def poisoned_dependencies(self):
        directory = self.root / 'unavailable-python-dependencies'
        for name in ('PIL', 'fido2'):
            path = directory / name
            path.mkdir(parents=True, exist_ok=True)
            (path / '__init__.py').write_text('raise RuntimeError("dependency intentionally unavailable")\n')
        return str(directory)

    def test_recovery_preflight_does_not_import_broken_extension_dependencies(self):
        self.layout.live = True
        with patch.object(lifecycle.shutil, 'which', return_value='/usr/bin/native-tool'), patch.object(lifecycle, 'run', return_value='10.0-test') as command:
            lifecycle.preflight(self.layout, recovery=True)
        self.assertEqual(command.call_count, 1)
        self.assertEqual(command.call_args.args[0][0], 'dpkg-query')

    def test_fresh_uninstall_works_without_pillow_or_fido2(self):
        self.invoke()
        with patch.dict(os.environ, {'PYTHONPATH': self.poisoned_dependencies()}):
            self.cli('uninstall')
        self.assertFalse(self.layout.path(lifecycle.HELPER).exists())
        self.assertFalse(self.layout.path(lifecycle.DROPINS[0]).exists())
        self.assertNotIn('BEGIN SOUTHLAND BRANDING', self.layout.path('/usr/share/pve-manager/index.html.tpl').read_text())

    def test_legacy_rollback_works_without_pillow_or_fido2(self):
        self.legacy_setup()
        self.invoke()
        self.beta_save()
        with patch.dict(os.environ, {'PYTHONPATH': self.poisoned_dependencies()}):
            self.cli('rollback')
            self.validate_restored_legacy()

    def test_guarded_uninstall_can_unload_after_interrupted_recovery(self):
        self.invoke()
        self.layout.save(lifecycle.MAINTENANCE, {'operation': 'rollback', 'pid': os.getpid(), 'status': 'recovery-required'})
        with self.layout.locked():
            lifecycle.uninstall(self.layout, False)
        self.assertFalse(self.layout.path(lifecycle.MAINTENANCE).exists())
        self.assertFalse(self.layout.path(lifecycle.DROPINS[0]).exists())

    def test_beta_rollback_target_still_validates_its_dependencies_after_restore(self):
        self.invoke()
        self.invoke()
        checked = []

        def preflight(_layout, recovery=False):
            checked.append(recovery)
            if not recovery:
                raise RuntimeError('target passkey dependency unavailable')

        with self.layout.locked(), patch.object(lifecycle, 'preflight', side_effect=preflight):
            with self.assertRaisesRegex(RuntimeError, 'target passkey dependency unavailable'):
                lifecycle.rollback(self.layout, False)
        self.assertEqual(checked, [True, False])
        self.assertFalse(self.layout.path(lifecycle.MAINTENANCE).exists())  # Prior fixture payload was restored completely.

    def test_failed_beta_restore_returns_to_removed_native_state_without_beta_health(self):
        self.invoke()
        self.cli('uninstall')

        def preflight(_layout, recovery=False):
            if not recovery:
                raise RuntimeError('beta dependency still broken')

        with self.layout.locked(), patch.object(lifecycle, 'preflight', side_effect=preflight), patch.object(lifecycle, 'loaded_api_health', side_effect=AssertionError('Removed native state must not require the beta API')):
            with self.assertRaisesRegex(RuntimeError, 'beta dependency still broken'):
                lifecycle.rollback(self.layout, False)
        self.assertFalse(self.layout.path(lifecycle.MAINTENANCE).exists())
        self.assertFalse(self.layout.path(lifecycle.HELPER).exists())
        self.assertEqual(self.layout.json(lifecycle.MANIFEST)['status'], 'removed')

    def test_activate_after_removal_does_not_leave_maintenance_marker(self):
        self.invoke()
        self.cli('uninstall')
        self.cli('activate', expected=1)
        self.assertFalse(self.layout.path(lifecycle.MAINTENANCE).exists())

    def test_resident_health_uses_fixed_loopback_without_credentials(self):
        self.layout.live = True
        connection = MagicMock()
        response = connection.getresponse.return_value
        response.status = 200
        response.read.return_value = json.dumps({'data': {'version': '0.1-beta', 'primary_passkeys': True, 'supported': False, 'rp': None}}).encode()
        with patch.object(lifecycle.http.client, 'HTTPSConnection', return_value=connection) as factory:
            result = lifecycle.loaded_api_health(self.layout)
        self.assertFalse(result['supported'])  # Missing RP config is not an unloaded module.
        self.assertEqual(factory.call_args.args, ('127.0.0.1', 8006))
        self.assertEqual(connection.request.call_args.args, ('GET', '/api2/json/sll-passkeys/status'))
        headers = connection.request.call_args.kwargs['headers']
        self.assertNotIn('Cookie', headers)
        self.assertNotIn('Authorization', headers)

    def test_resident_health_rejects_broken_configured_passkey_verifier(self):
        self.layout.live = True
        connection = MagicMock()
        response = connection.getresponse.return_value
        response.status = 200
        response.read.return_value = json.dumps({'data': {'version': '0.1-beta', 'primary_passkeys': True,
            'supported': False, 'rp': {'id': 'pve.example.test', 'name': 'Fixture', 'origin': 'https://pve.example.test'}}}).encode()
        with patch.object(lifecycle.http.client, 'HTTPSConnection', return_value=connection), patch.object(lifecycle.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'health check failed'):
                lifecycle.loaded_api_health(self.layout)

    def test_resident_health_rejects_native_fallback_and_hides_response_data(self):
        self.layout.live = True
        connection = MagicMock()
        response = connection.getresponse.return_value
        response.status = 200
        response.read.return_value = b'{"data":{"version":"0.1.0","unexpected":"do-not-log-this"}}'
        with patch.object(lifecycle.http.client, 'HTTPSConnection', return_value=connection), patch.object(lifecycle.time, 'sleep'):
            with self.assertRaises(RuntimeError) as caught:
                lifecycle.loaded_api_health(self.layout)
        self.assertNotIn('do-not-log-this', str(caught.exception))
        self.assertEqual(connection.request.call_count, 6)

    def test_staged_uninstall_keeps_all_loaded_modules_until_activation(self):
        self.invoke()
        before = {name: self.layout.path(name).read_bytes() for name in self.layout.json(lifecycle.MANIFEST)['files']}
        self.layout.live = True
        with self.layout.locked(), patch.object(lifecycle, 'run', side_effect=AssertionError('Staged uninstall invoked a service')):
            lifecycle.uninstall(self.layout, False)
        for name, data in before.items():
            self.assertEqual(self.layout.path(name).read_bytes(), data)
        self.assertEqual(self.layout.json(lifecycle.MANIFEST)['status'], 'pending-uninstall')

    def test_symlinked_target_rejected_before_any_payload_write(self):
        external = self.root / 'external'
        external.mkdir()
        path = self.root / 'usr/local'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(external, target_is_directory=True)
        self.invoke(expected=1)
        self.assertEqual(list(external.iterdir()), [])
        self.assertFalse(self.layout.path(lifecycle.CONFIG).exists())

    def test_malicious_lock_symlinks_never_modify_target(self):
        victim = self.put('/victim', b'preserve these bytes')
        victim.chmod(0o640)
        for name, context in ((lifecycle.CONTROL_LOCK, self.layout.presentation_locked),
                              (lifecycle.STATE + '/install.lock', self.layout.locked)):
            lock = self.root / name.lstrip('/')
            lock.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            lock.symlink_to(victim)
            with self.assertRaisesRegex(RuntimeError, 'symlink'):
                with context():
                    self.fail('A symlink lock was opened')
            self.assertEqual(victim.read_bytes(), b'preserve these bytes')
            self.assertEqual(victim.stat().st_mode & 0o777, 0o640)
            lock.unlink()

    @unittest.skipUnless(os.geteuid() == 0, 'Production ownership checks require isolated root fixtures')
    def test_live_path_rejects_writable_module_parents_without_host_mutation(self):
        with tempfile.TemporaryDirectory(prefix='makeover-mode-test-', dir=pwd.getpwuid(0).pw_dir) as directory:
            parent = Path(directory) / 'modules'
            parent.mkdir()
            parent.chmod(0o775)
            with self.assertRaisesRegex(RuntimeError, 'group/world-writable'):
                lifecycle.checked_path(parent / 'extension.pm', owner=0)
            parent.chmod(0o1777)
            with self.assertRaisesRegex(RuntimeError, 'group/world-writable'):
                lifecycle.checked_path(parent / 'extension.pm', owner=0)
            parent.chmod(0o755)
            self.assertEqual(lifecycle.checked_path(parent / 'extension.pm', owner=0), parent / 'extension.pm')
        # This reads the native lock-directory metadata only; no file is made.
        self.assertEqual(lifecycle.checked_path('/run/lock', owner=0), Path('/run/lock'))

    def test_lock_open_rejects_symlink_created_after_path_check(self):
        victim = self.put('/victim', b'unchanged')
        victim.chmod(0o640)
        real_open = os.open
        for name, context in ((lifecycle.CONTROL_LOCK, self.layout.presentation_locked),
                              (lifecycle.STATE + '/install.lock', self.layout.locked)):
            lock = self.root / name.lstrip('/')

            def swap_then_open(path, flags, *args, **kwargs):
                if Path(path) == lock:
                    self.assertTrue(flags & os.O_NOFOLLOW)
                    lock.symlink_to(victim)
                return real_open(path, flags, *args, **kwargs)

            with patch.object(lifecycle.os, 'open', side_effect=swap_then_open):
                with self.assertRaises(OSError):
                    with context():
                        self.fail('Raced symlink was opened')
            self.assertEqual(victim.read_bytes(), b'unchanged')
            self.assertEqual(victim.stat().st_mode & 0o777, 0o640)
            lock.unlink()

    def test_uninstall_restores_current_package_preserves_local_edits_and_config(self):
        self.invoke()
        template = self.layout.path('/usr/share/pve-manager/index.html.tpl')
        fresh = '<head>\n<script src="/pve2/js/pvemanagerlib.js"></script>\n<!-- new package template -->\n</head>\n'
        template.write_text(fresh)
        icon = self.layout.path('/usr/share/pve-manager/images/logo-128.png')
        icon.write_bytes(b'new package icon')
        self.cli('apply')
        custom_css = self.layout.path('/usr/local/share/sls-proxmox-branding/assets/southland.css')
        custom_css.write_text('/* external customization */')
        self.cli('uninstall', '--no-activate')
        self.assertEqual(template.read_text(), fresh)
        self.assertEqual(icon.read_bytes(), b'new package icon')
        self.assertEqual(custom_css.read_text(), '/* external customization */')
        self.assertTrue(self.layout.path(lifecycle.CONFIG).exists())
        self.assertFalse(self.layout.path(lifecycle.DROPINS[0]).exists())
        self.assertEqual(self.layout.json(lifecycle.MANIFEST)['status'], 'removed')

    def test_upgrade_rollback_restores_previous_release(self):
        self.invoke()
        installed = self.layout.path('/usr/local/share/sls-proxmox-branding/makeover/makeover.css')
        installed.write_text('/* local prior presentation */')
        self.invoke()
        self.assertNotEqual(installed.read_text(), '/* local prior presentation */')
        self.cli('rollback')
        self.assertEqual(installed.read_text(), '/* local prior presentation */')
        self.assertIn('BEGIN SOUTHLAND BRANDING', self.layout.path('/usr/share/pve-manager/index.html.tpl').read_text())

    def legacy_setup(self):
        """Install the actual handoff helper/API and its schema 1 settings."""
        self.put(lifecycle.HELPER, (LEGACY / 'sls-proxmox-branding').read_bytes()).chmod(0o755)
        self.put('/usr/local/lib/site_perl/PVE/API2/SLLCustoms.pm', (LEGACY / 'SLLCustoms.pm').read_bytes())
        self.put(lifecycle.CONFIG, (LEGACY / 'config.json').read_bytes()).chmod(0o600)
        for name in ('southland.css', 'southland.js'):
            self.put('/usr/local/share/sls-proxmox-branding/assets/' + name, (LEGACY / name).read_bytes())
        for name in ('makeover.css', 'makeover.js'):
            self.put('/usr/local/share/sls-proxmox-branding/makeover/' + name, (LEGACY / name).read_bytes())
        for name in ('SLS_Proxmox.png', 'SLS_Proxmox_Favicon.png'):
            self.put('/usr/local/share/sls-proxmox-branding/assets/' + name, (REPO / 'assets' / name).read_bytes())
        lifecycle.helper(self.layout)
        self.assertEqual(lifecycle.digest(self.layout.path(lifecycle.HELPER).read_bytes()), lifecycle.LEGACY_SCHEMA1_HELPER)

    def validate_restored_legacy(self):
        self.assertEqual(self.layout.path('/usr/local/lib/site_perl/PVE/API2/SLLCustoms.pm').read_bytes(), (LEGACY / 'SLLCustoms.pm').read_bytes())
        config = self.layout.json(lifecycle.CONFIG)
        self.assertEqual(config['schema_version'], 1)
        self.assertNotIn('update_safe', config)
        self.assertNotIn('fonts', config)
        self.assertEqual(config['company_name'], 'Saved during beta')
        # Load and execute the real legacy validator with inert native API
        # registration stubs; no live config, permissions or API are queried.
        script = r'''
BEGIN {
    package PVE::RESTHandler; sub register_method { }
    $INC{'PVE/RESTHandler.pm'} = 1;
    $INC{'PVE/JSONSchema.pm'} = 1;
    $INC{'PVE/RPCEnvironment.pm'} = 1;
    $INC{'PVE/Tools.pm'} = 1;
}
use JSON::PP;
require $ARGV[0];
open my $fh, '<', $ARGV[1] or die $!;
local $/;
my $config = JSON::PP::decode_json(<$fh>);
my $clean = PVE::API2::SLLCustoms::validate_config($config);
print JSON::PP::encode_json($clean);
'''
        result = subprocess.run(['perl', '-e', script, str(self.layout.path('/usr/local/lib/site_perl/PVE/API2/SLLCustoms.pm')), str(self.layout.path(lifecycle.CONFIG))], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['company_name'], 'Saved during beta')
        lifecycle.helper(self.layout, '--check')
        retained = list(self.layout.path(lifecycle.STATE + '/retained').glob('*/config-schema2.json'))
        self.assertTrue(retained)
        self.assertEqual(json.loads(retained[0].read_text())['update_safe'], False)

    def beta_save(self):
        config = self.layout.json(lifecycle.CONFIG)
        config.update(schema_version=2, company_name='Saved during beta', update_safe=False)
        self.layout.save(lifecycle.CONFIG, config)
        # A valid different uploaded logo survives restoration to legacy too.
        logo = self.layout.path(lifecycle.ARTWORK[0])
        logo.write_bytes((REPO / 'assets/SLS_Proxmox_Favicon.png').read_bytes())
        self.cli('apply')

    def test_actual_legacy_uninstall_keeps_beta_values_in_compatible_schema(self):
        self.legacy_setup()
        self.invoke()
        manifest = self.layout.json(lifecycle.MANIFEST)
        for name in (lifecycle.CONFIG, *lifecycle.ARTWORK):
            self.assertIsNotNone(manifest['files'][name]['original'])
        self.beta_save()
        self.cli('uninstall')
        self.validate_restored_legacy()
        self.assertEqual(self.layout.path(lifecycle.ARTWORK[0]).read_bytes(), (REPO / 'assets/SLS_Proxmox_Favicon.png').read_bytes())
        self.assertFalse(self.layout.path(lifecycle.MAINTENANCE).exists())

    def test_actual_legacy_rollback_keeps_beta_values_in_compatible_schema(self):
        self.legacy_setup()
        self.invoke()
        self.beta_save()
        self.cli('rollback')
        self.validate_restored_legacy()
        self.assertEqual(self.layout.path(lifecycle.ARTWORK[0]).read_bytes(), (REPO / 'assets/SLS_Proxmox_Favicon.png').read_bytes())
        self.assertFalse(self.layout.path(lifecycle.MAINTENANCE).exists())

    def test_interrupted_uninstall_retains_legacy_bridge_after_beta_compensation(self):
        self.legacy_setup()
        self.invoke()
        current = lifecycle.Layout(self.root)
        self.assertFalse(current.legacy_lock_required)
        attempts = []

        def interrupted_reload(layout):
            attempts.append(lifecycle.digest(layout.path(lifecycle.HELPER).read_bytes()))
            if len(attempts) == 1:
                self.assertEqual(attempts[-1], lifecycle.LEGACY_SCHEMA1_HELPER)
                raise RuntimeError('legacy daemon loaded; console blocked proxy reload')
            raise RuntimeError('active console blocks compensation reload')

        with current.locked(), patch.object(lifecycle, 'restart_daemons', side_effect=interrupted_reload):
            with self.assertRaisesRegex(RuntimeError, 'legacy daemon loaded'):
                lifecycle.uninstall(current, False)
        self.assertNotEqual(attempts[-1], lifecycle.LEGACY_SCHEMA1_HELPER)
        self.assertFalse(current.json(lifecycle.MANIFEST)['legacy_lock_required'])
        latest = current.json(lifecycle.STATE + '/latest-transaction.json')
        transaction = current.json(latest['transaction'] + '/transaction.json')
        self.assertEqual(transaction['status'], 'recovery-required')
        self.assertTrue(transaction['legacy_lock_required'])
        recovered = lifecycle.Layout(self.root)
        self.assertTrue(recovered.legacy_lock_required)
        with recovered.presentation_locked():
            for name in (lifecycle.CONTROL_LOCK, lifecycle.LEGACY_API_LOCK):
                with recovered.path(name).open('a') as probe:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertEqual(current.json(lifecycle.MAINTENANCE)['status'], 'recovery-required')

    def test_snapshot_preparation_failure_restores_active_watcher_without_enablement_changes(self):
        self.invoke()
        before = self.layout.path(lifecycle.HELPER).read_bytes()
        self.layout.live = True
        operations = (
            lambda: lifecycle.install(self.layout, REPO, True),
            lambda: lifecycle.uninstall(self.layout, True),
            lambda: lifecycle.rollback(self.layout, True),
        )
        for operation in operations:
            with self.subTest(operation=operation):
                with patch.object(lifecycle, 'preflight'), patch.object(lifecycle, 'guard_sessions'), patch.object(lifecycle, 'capture_event_states', return_value={lifecycle.EVENT_PATH: {'ActiveState': 'active', 'UnitFileState': 'enabled'}}), patch.object(lifecycle, 'canonical_helper_processes', return_value=[]), patch.object(lifecycle, 'run', return_value='') as command, patch.object(lifecycle, 'snapshot', side_effect=OSError('snapshot disk full')):
                    with self.assertRaisesRegex(OSError, 'snapshot disk full'):
                        operation()
                actions = [call.args[0][1] for call in command.call_args_list]
                self.assertEqual(actions, ['stop', 'start'])
                self.assertEqual(self.layout.path(lifecycle.HELPER).read_bytes(), before)
                self.assertFalse(self.layout.path(lifecycle.MAINTENANCE).exists())

    def test_snapshot_preparation_failure_preserves_inactive_watcher(self):
        self.invoke()
        self.layout.live = True
        with patch.object(lifecycle, 'preflight'), patch.object(lifecycle, 'guard_sessions'), patch.object(lifecycle, 'capture_event_states', return_value={lifecycle.EVENT_PATH: {'ActiveState': 'inactive', 'UnitFileState': 'disabled'}}), patch.object(lifecycle, 'canonical_helper_processes', return_value=[]), patch.object(lifecycle, 'run', return_value='') as command, patch.object(lifecycle, 'snapshot', side_effect=OSError('snapshot disk full')):
            with self.assertRaisesRegex(OSError, 'snapshot disk full'):
                lifecycle.uninstall(self.layout, True)
        self.assertEqual(command.call_args_list, [])
        self.assertFalse(self.layout.path(lifecycle.MAINTENANCE).exists())

    def test_failed_watcher_preparation_recovery_retains_maintenance_marker(self):
        self.invoke()
        self.layout.live = True

        def command(arguments, **_kwargs):
            if arguments[1] == 'start':
                raise RuntimeError('watcher start failed')
            return 'active'

        with patch.object(lifecycle, 'preflight'), patch.object(lifecycle, 'guard_sessions'), patch.object(lifecycle, 'capture_event_states', return_value={lifecycle.EVENT_PATH: {'ActiveState': 'active', 'UnitFileState': 'enabled'}}), patch.object(lifecycle, 'canonical_helper_processes', return_value=[]), patch.object(lifecycle, 'run', side_effect=command), patch.object(lifecycle, 'snapshot', side_effect=OSError('snapshot disk full')):
            with self.assertRaisesRegex(OSError, 'snapshot disk full'):
                lifecycle.install(self.layout, REPO, True)
        self.assertEqual(self.layout.json(lifecycle.MAINTENANCE)['status'], 'recovery-required')

    def test_event_producers_pause_before_natural_service_drain_without_killing_writer(self):
        self.layout.live = True
        captured = {unit: {'LoadState': 'loaded', 'ActiveState': 'active', 'UnitFileState': 'enabled'}
                    for unit in (lifecycle.EVENT_TIMER, lifecycle.EVENT_PATH, lifecycle.EVENT_SERVICE)}
        service = iter(('active', 'inactive'))

        def command(arguments, **_kwargs):
            return next(service) if arguments[1] == 'show' else ''

        lease = {'safe_to_clear': True}
        with patch.object(lifecycle, 'capture_event_states', return_value=captured), patch.object(lifecycle, 'canonical_helper_processes', return_value=[]), patch.object(lifecycle, 'run', side_effect=command) as commands, patch.object(lifecycle.time, 'sleep'):
            with self.assertRaisesRegex(OSError, 'preparation failed'):
                with lifecycle.preparing_transaction(self.layout, lease):
                    raise OSError('preparation failed')
        self.assertEqual([call.args[0][1:] for call in commands.call_args_list], [
            ['stop', lifecycle.EVENT_TIMER], ['stop', lifecycle.EVENT_PATH],
            ['show', '--property=ActiveState', '--value', lifecycle.EVENT_SERVICE],
            ['show', '--property=ActiveState', '--value', lifecycle.EVENT_SERVICE],
            ['start', lifecycle.EVENT_TIMER], ['start', lifecycle.EVENT_PATH],
        ])
        self.assertEqual(self.layout.event_states, captured)
        self.assertTrue(lease['safe_to_clear'])

    def test_canonical_helper_scan_excludes_unrelated_fixture_and_never_logs_arguments(self):
        proc = self.root / 'proc'
        expected = str(self.layout.path(lifecycle.HELPER))
        for pid, arguments in ((101, ['/usr/bin/python3', expected, '--automatic']),
                               (102, ['/usr/bin/python3', expected, '--root', str(self.root)]),
                               (103, ['/usr/bin/python3', expected, '--root', '/unrelated-fixture']),
                               (104, ['/bin/sh', '-c', 'a string mentioning ' + expected])):
            directory = proc / str(pid)
            directory.mkdir(parents=True)
            (directory / 'cmdline').write_bytes(b'\0'.join(value.encode() for value in arguments))
        self.assertEqual(lifecycle.canonical_helper_processes(self.layout, proc), [102])
        self.layout.live = True
        with patch.object(lifecycle, 'canonical_helper_processes', return_value=[102]):
            with self.assertRaisesRegex(RuntimeError, 'PIDs 102'):
                lifecycle.ensure_no_helper_processes(self.layout)

    def test_event_drain_timeout_restores_producers_without_snapshot_or_service_kill(self):
        self.invoke()
        before = self.layout.path(lifecycle.HELPER).read_bytes()
        self.layout.live = True
        captured = {unit: {'LoadState': 'loaded', 'ActiveState': 'active', 'UnitFileState': 'enabled'}
                    for unit in (lifecycle.EVENT_TIMER, lifecycle.EVENT_PATH, lifecycle.EVENT_SERVICE)}
        with patch.object(lifecycle, 'preflight'), patch.object(lifecycle, 'guard_sessions'), patch.object(lifecycle, 'capture_event_states', return_value=captured), patch.object(lifecycle, 'run', return_value='active') as command, patch.object(lifecycle, 'snapshot', side_effect=AssertionError('snapshot began before drain')), patch.object(lifecycle.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'natural completion'):
                lifecycle.install(self.layout, REPO, True)
        mutations = [call.args[0][1:] for call in command.call_args_list if call.args[0][1] != 'show']
        self.assertEqual(mutations, [['stop', lifecycle.EVENT_TIMER], ['stop', lifecycle.EVENT_PATH],
                                     ['start', lifecycle.EVENT_TIMER], ['start', lifecycle.EVENT_PATH]])
        self.assertEqual(self.layout.path(lifecycle.HELPER).read_bytes(), before)
        self.assertFalse(self.layout.path(lifecycle.MAINTENANCE).exists())

    def test_prepared_event_states_survive_old_marker_and_committed_history_is_ignored(self):
        self.invoke()
        states = {lifecycle.EVENT_TIMER: {'LoadState': 'loaded', 'ActiveState': 'active', 'UnitFileState': 'enabled'}}
        self.layout.event_states = states
        with self.layout.presentation_locked():
            transaction = lifecycle.snapshot(self.layout, [lifecycle.HELPER], 'interrupted-event-pause')
            self.layout.save(lifecycle.MAINTENANCE, {'operation': 'old-marker', 'pid': os.getpid()})
        current = lifecycle.Layout(self.root)
        self.assertEqual(current.event_states, states)
        with current.maintenance('recovery', recover=True) as lease:
            with patch.object(lifecycle, 'capture_event_states', return_value={}):
                with lifecycle.preparing_transaction(current, lease):
                    self.assertEqual(current.json(lifecycle.MAINTENANCE)['event_states'], states)
        lifecycle.transaction_status(current, transaction, 'committed')
        self.assertEqual(lifecycle.Layout(self.root).event_states, {})

    def test_paused_actual_legacy_writer_cannot_be_overtaken_by_new_publication(self):
        self.legacy_setup()
        self.invoke()
        loader = importlib.machinery.SourceFileLoader('isolated_legacy_writer', str(LEGACY / 'sls-proxmox-branding'))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        old = importlib.util.module_from_spec(spec)
        loader.exec_module(old)
        reached, resume = threading.Event(), threading.Event()
        failures = []
        original_atomic = old.atomic

        def pause_first_publication(path, *arguments, **keywords):
            if '/usr/share/' in str(path) and not reached.is_set():
                reached.set()
                if not resume.wait(8):
                    raise RuntimeError('fixture publication timeout')
            return original_atomic(path, *arguments, **keywords)

        def writer():
            try:
                old.main()
            except BaseException as error:
                failures.append(error)

        old.atomic = pause_first_publication
        with patch.object(sys, 'argv', [str(LEGACY / 'sls-proxmox-branding'), '--root', str(self.root)]):
            thread = threading.Thread(target=writer)
            thread.start()
            try:
                self.assertTrue(reached.wait(3))
                current = lifecycle.Layout(self.root)
                current.legacy_lock_required = True
                before = current.path(lifecycle.HELPER).read_bytes()
                with current.locked():
                    with self.assertRaisesRegex(RuntimeError, 'legacy presentation helper is still running'):
                        lifecycle.install(current, REPO, False)
                self.assertEqual(current.path(lifecycle.HELPER).read_bytes(), before)
            finally:
                resume.set()
                thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertFalse(failures)
        # Once that exact historical process finishes naturally, a retry owns
        # the old overlay lock through replacement and publishes all modules.
        with current.locked():
            actual_helper = lifecycle.helper_locked

            def held_old_overlay(layout, *arguments):
                with layout.path(lifecycle.LEGACY_OVERLAY_LOCK).open('a') as probe:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return actual_helper(layout, *arguments)

            with patch.object(lifecycle, 'helper_locked', side_effect=held_old_overlay):
                lifecycle.install(current, REPO, False)
        served = current.path('/usr/share/pve-manager/js/sll-makeover.js').read_bytes()
        self.assertIn((REPO / 'login-passkeys.js').read_bytes(), served)
        self.assertIn((REPO / 'native-security.js').read_bytes(), served)
        self.assertIsNone(current.legacy_overlay)

    def test_canonical_mutations_and_recovery_hold_shared_lock(self):
        original_write = lifecycle.Layout.write
        original_unlink = lifecycle.Layout.unlink

        def check_locked(layout, name):
            if name.startswith(('/usr/local/', '/etc/')):
                self.assertTrue(layout.path(lifecycle.MAINTENANCE).exists())
                with layout.path(lifecycle.CONTROL_LOCK).open('a') as stream:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)

        def write(layout, name, *args, **kwargs):
            check_locked(layout, name)
            return original_write(layout, name, *args, **kwargs)

        def unlink(layout, name, *args, **kwargs):
            check_locked(layout, name)
            return original_unlink(layout, name, *args, **kwargs)

        with patch.object(lifecycle.Layout, 'write', write), patch.object(lifecycle.Layout, 'unlink', unlink):
            with self.layout.locked():
                lifecycle.install(self.layout, REPO, False)
                lifecycle.install(self.layout, REPO, False)
                lifecycle.rollback(self.layout, False)
                lifecycle.uninstall(self.layout, False)
        self.assertFalse(self.layout.path(lifecycle.MAINTENANCE).exists())

    def test_session_guard_checks_api_and_detached_processes(self):
        self.layout.live = True
        with patch.object(lifecycle, 'run', return_value='[]') as command, patch.object(lifecycle, 'process_sessions', return_value=[{'pid': 123, 'process': 'termproxy'}]):
            with self.assertRaisesRegex(RuntimeError, 'Active Proxmox tasks'):
                lifecycle.guard_sessions(self.layout)
            self.assertIn('active', command.call_args.args[0])
        with patch.object(lifecycle, 'run', return_value='[{"status":"RUNNING","upid":"test"}]'), patch.object(lifecycle, 'process_sessions', return_value=[]):
            with self.assertRaisesRegex(RuntimeError, 'Active Proxmox tasks'):
                lifecycle.guard_sessions(self.layout)
        with patch.object(lifecycle, 'run', return_value='[]'), patch.object(lifecycle, 'process_sessions', return_value=[]):
            lifecycle.guard_sessions(self.layout)

    def test_fresh_private_controls_ignore_squatted_legacy_filename(self):
        victim = self.put('/victim', b'untouched')
        victim.chmod(0o640)
        legacy = self.root / lifecycle.LEGACY_API_LOCK.lstrip('/')
        legacy.parent.mkdir(parents=True)
        legacy.symlink_to(victim)
        overlay = self.root / lifecycle.LEGACY_OVERLAY_LOCK.lstrip('/')
        overlay.symlink_to(victim)
        with self.layout.presentation_locked():
            self.assertTrue(self.layout.path(lifecycle.CONTROL_LOCK).is_file())
            self.assertEqual(self.layout.path(lifecycle.STATE).stat().st_mode & 0o777, 0o700)
        self.assertTrue(legacy.is_symlink())
        self.invoke()
        self.assertTrue(legacy.is_symlink())
        self.assertTrue(overlay.is_symlink())
        self.assertEqual(victim.read_bytes(), b'untouched')
        self.assertEqual(victim.stat().st_mode & 0o777, 0o640)

    def test_legacy_bridge_flag_survives_interrupted_helper_replacement(self):
        self.legacy_setup()
        adopted = lifecycle.Layout(self.root)
        self.assertTrue(adopted.legacy_lock_required)
        legacy = self.put(lifecycle.LEGACY_API_LOCK, b'')
        legacy.chmod(0o644)
        before = legacy.stat()
        with adopted.locked(), adopted.presentation_locked():
            for name in (lifecycle.CONTROL_LOCK, lifecycle.LEGACY_API_LOCK):
                with adopted.path(name).open('a') as probe:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            transaction = lifecycle.snapshot(adopted, [lifecycle.HELPER], 'fixture-partial-install')
            adopted.write(lifecycle.HELPER, b'new helper already replaced the legacy bytes', 0o755)
        self.assertTrue(transaction['legacy_lock_required'])
        recovering = lifecycle.Layout(self.root)
        self.assertTrue(recovering.legacy_lock_required)
        after = legacy.stat()
        self.assertEqual((before.st_uid, before.st_gid, before.st_mode), (after.st_uid, after.st_gid, after.st_mode))

    def test_committed_beta_drops_legacy_bridge_but_rollback_retains_history(self):
        self.legacy_setup()
        self.invoke()
        self.assertFalse(self.layout.json(lifecycle.MANIFEST)['legacy_lock_required'])
        latest = self.layout.json(lifecycle.STATE + '/latest-transaction.json')
        self.assertTrue(self.layout.json(latest['transaction'] + '/transaction.json')['legacy_lock_required'])
        # Simulate a reboot clearing the old shared lock and a local squatter.
        legacy = self.root / lifecycle.LEGACY_API_LOCK.lstrip('/')
        legacy.unlink()
        victim = self.put('/victim', b'preserved')
        legacy.symlink_to(victim)
        current = lifecycle.Layout(self.root)
        self.assertFalse(current.legacy_lock_required)
        with current.presentation_locked():
            pass
        with current.locked():
            with self.assertRaisesRegex(RuntimeError, 'symlink'):
                lifecycle.rollback(current, False)
        self.assertTrue(current.legacy_lock_required)
        self.assertEqual(victim.read_bytes(), b'preserved')
        self.assertTrue(legacy.is_symlink())

    def test_process_guard_excludes_idle_workers_and_guest_runtime(self):
        proc = self.root / 'fake-proc'
        for pid, args in ((10, ['pvedaemon worker']), (11, ['pveproxy worker']), (12, ['spiceproxy worker']),
                          (13, ['qemu-system-x86_64', '-vnc', 'unix:100.vnc', '-spice', 'port=61000']),
                          (14, ['/usr/bin/termproxy', '5900']), (15, ['task UPID:PVE:abcd:vncshell:'])):
            directory = proc / str(pid)
            (directory / 'fd').mkdir(parents=True)
            (directory / 'cmdline').write_bytes(b'\0'.join(item.encode() for item in args))
        sessions = lifecycle.process_sessions(proc)
        self.assertEqual({item['pid'] for item in sessions}, {14, 15})

    def test_process_guard_finds_connected_spice_worker(self):
        proc = self.root / 'fake-proc'
        (proc / 'net').mkdir(parents=True)
        (proc / 'net/tcp').write_text('header\n0: 00000000:0C38 00000000:ABCD 01 0 0 0 0 0 54321\n')
        directory = proc / '55'
        (directory / 'fd').mkdir(parents=True)
        (directory / 'cmdline').write_bytes(b'spiceproxy worker\0')
        (directory / 'fd/5').symlink_to('socket:[54321]')
        sessions = lifecycle.process_sessions(proc)
        self.assertEqual([item['pid'] for item in sessions], [55])


if __name__ == '__main__':
    unittest.main()
