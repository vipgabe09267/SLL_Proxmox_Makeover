"""Exercise overlay safety against isolated package trees, never the running host."""
import copy
import contextlib
import fcntl
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
import zlib
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('makeover_helper', str(REPO / 'sls-proxmox-branding'))
spec = importlib.util.spec_from_loader(loader.name, loader)
helper = importlib.util.module_from_spec(spec)
loader.exec_module(helper)


def fixture(root):
    def put(name, data):
        path = root / name.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode() if isinstance(data, str) else data)
    put(helper.TEMPLATE, '<html><head>\n<!-- vendor layout marker A -->\n<script src="/pve2/js/pvemanagerlib.js"></script>\n</head><body>current vendor layout</body></html>\n')
    put(helper.MANAGER + '/js/pvemanagerlib.js', "\n".join("Ext.define('" + name + "', {});" for name in ('PVE.window.LoginWindow', 'PVE.node.Summary', 'PVE.node.StatusView')))
    put(helper.WIDGETS + '/themes/theme-proxmox-dark.css', '/* current native theme */')
    for name in ('images/proxmox_logo.png', 'images/logo-128.png'):
        put(helper.MANAGER + '/' + name, b'current native PNG')
    put(helper.WIDGETS + '/images/proxmox_logo.svg', b'<svg>current native SVG</svg>')
    for name in ('login-passkeys.js', 'native-security.js', 'makeover.js', 'makeover.css'):
        put(helper.MAKEOVER_SOURCE + '/' + name, (REPO / name).read_bytes())
    for name in ('SLS_Proxmox.png', 'SLS_Proxmox_Favicon.png'):
        put('/usr/local/share/sls-proxmox-branding/assets/' + name, (REPO / 'assets' / name).read_bytes())
    for name in ('southland.js', 'southland.css'):
        put('/usr/local/share/sls-proxmox-branding/assets/' + name, (REPO / name).read_bytes())
    for name in ('dm-sans.ttf', 'oxanium.ttf'):
        put('/usr/local/share/sls-proxmox-branding/assets/fonts/' + name, (REPO / 'assets/fonts' / name).read_bytes())
    put(helper.MAKEOVER_CONFIG, json.dumps(helper.DEFAULT_MAKEOVER_CONFIG))
    return root


class HelperTests(unittest.TestCase):
    def test_double_slash_root_cannot_bypass_live_uid_guard(self):
        # Read-only root identity check; fail before any private directory,
        # lock or managed output can be created.
        self.assertEqual(helper.no_symlinks('//'), Path('/'))
        with patch.object(helper.os, 'geteuid', return_value=1000), patch.object(helper.sys, 'argv', ['helper', '--root', '//']), patch.object(helper, 'private_directory', side_effect=AssertionError('A live nonroot call reached filesystem mutation')):
            with self.assertRaisesRegex(RuntimeError, 'requires root'):
                helper.main()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='makeover-test-')
        self.root = fixture(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def run_helper(self, *args, expected=0):
        proc = subprocess.run([str(REPO / 'sls-proxmox-branding'), '--root', str(self.root), *args], capture_output=True, text=True)
        self.assertEqual(proc.returncode, expected, proc.stdout + proc.stderr)
        return proc

    def config(self, **updates):
        path = self.root / helper.MAKEOVER_CONFIG.lstrip('/')
        config = json.loads(path.read_text())
        config.update(updates)
        path.write_text(json.dumps(config))

    def test_current_layout_and_native_js_preserved(self):
        native_js = self.root / (helper.MANAGER + '/js/pvemanagerlib.js').lstrip('/')
        before = native_js.read_bytes()
        self.run_helper()
        self.run_helper('--check')
        template = (self.root / helper.TEMPLATE.lstrip('/')).read_text()
        self.assertIn('vendor layout marker A', template)
        self.assertIn('current vendor layout', template)
        self.assertEqual(template.count(helper.BEGIN), 1)
        self.assertEqual(native_js.read_bytes(), before)
        self.run_helper()
        self.assertEqual((self.root / helper.TEMPLATE.lstrip('/')).read_text(), template)

    def test_fonts_are_local_preserved_by_repair_and_removed_with_overlay(self):
        self.config(fonts={'login': 'dm-sans', 'dashboard': 'oxanium'})
        self.run_helper()
        generated = self.root / (helper.MANAGER + '/js/sll-makeover-config.js').lstrip('/')
        self.assertIn('"fonts":{"dashboard":"oxanium","login":"dm-sans"}', generated.read_text())
        for name in ('dm-sans.ttf', 'oxanium.ttf'):
            served = self.root / (helper.MANAGER + '/css/sls-' + name).lstrip('/')
            self.assertEqual(served.read_bytes(), (REPO / 'assets/fonts' / name).read_bytes())
        template = self.root / helper.TEMPLATE.lstrip('/')
        template.write_text(template.read_text().replace('vendor layout marker A', 'new package'))
        self.run_helper('--automatic')
        self.run_helper('--check')
        self.assertIn('"fonts":{"dashboard":"oxanium","login":"dm-sans"}', generated.read_text())
        self.run_helper('--remove')
        self.assertFalse((self.root / (helper.MANAGER + '/css/sls-dm-sans.ttf').lstrip('/')).exists())

    def test_old_schema_two_font_defaults_are_in_memory_only(self):
        path = self.root / helper.MAKEOVER_CONFIG.lstrip('/')
        config = json.loads(path.read_text())
        del config['fonts']
        original = json.dumps(config).encode()
        path.write_bytes(original)
        self.assertEqual(helper.load_makeover_config(path)['fonts'], {'login': 'default', 'dashboard': 'default'})
        self.run_helper()
        self.assertEqual(path.read_bytes(), original)

    def test_fonts_reject_css_urls_and_unknown_keys(self):
        for value in ('https://example.org/font.ttf', 'url(https://example.org)', 'serif; color:red',
                      '__proto__', 'constructor', '', None, True, [], {}):
            config = copy.deepcopy(helper.DEFAULT_MAKEOVER_CONFIG)
            config['fonts']['login'] = value
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, 'Invalid Makeover font'):
                helper.validate_config(config)
        for value in ({}, {'login': 'default'}, {'login': 'default', 'dashboard': 'default', 'url': 'https://example.org'}):
            config = copy.deepcopy(helper.DEFAULT_MAKEOVER_CONFIG)
            config['fonts'] = value
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, 'font fields'):
                helper.validate_config(config)

    def test_native_security_is_bundled_once_and_changes_content_version(self):
        first = json.loads(self.run_helper('--dry-run').stdout)['version']
        self.run_helper()
        generated = self.root / (helper.MANAGER + '/js/sll-makeover.js').lstrip('/')
        self.assertEqual(generated.read_bytes(), b'\n;\n'.join((REPO / name).read_bytes() for name in ('login-passkeys.js', 'native-security.js', 'makeover.js')))
        source = self.root / (helper.MAKEOVER_SOURCE + '/native-security.js').lstrip('/')
        source.write_bytes(source.read_bytes() + b'\n/* native security integration change */\n')
        second = json.loads(self.run_helper('--dry-run').stdout)['version']
        self.assertNotEqual(first, second)
        self.run_helper()
        self.run_helper('--check')
        self.assertTrue(generated.read_bytes().startswith((REPO / 'login-passkeys.js').read_bytes() + b'\n;\n' + source.read_bytes() + b'\n;\n'))

    def test_package_replacement_repairs_and_remove_keeps_new_vendor_layout(self):
        self.run_helper()
        template = self.root / helper.TEMPLATE.lstrip('/')
        fresh = '<head>\n<script src="/pve2/js/pvemanagerlib.js"></script>\n<!-- vendor layout B -->\n</head>\n'
        template.write_text(fresh)
        native_icon = self.root / (helper.MANAGER + '/images/logo-128.png').lstrip('/')
        native_icon.write_bytes(b'new package icon')
        self.run_helper('--automatic')
        self.assertIn('vendor layout B', template.read_text())
        self.run_helper('--remove')
        self.assertEqual(template.read_text(), fresh)
        self.assertEqual(native_icon.read_bytes(), b'new package icon')
        self.run_helper('--enable')
        self.run_helper('--check')

    def test_update_protection_off_skips_automatic_repair_but_allows_manual_apply(self):
        self.run_helper()
        self.config(update_safe=False, company_name='Example Operations')
        generated = self.root / (helper.MANAGER + '/js/sll-makeover-config.js').lstrip('/')
        before = generated.read_bytes()
        self.run_helper('--automatic')
        self.assertEqual(before, generated.read_bytes())
        self.run_helper()
        self.assertIn('Example Operations', generated.read_text())
        template = self.root / helper.TEMPLATE.lstrip('/')
        template.write_text(template.read_text().replace('vendor layout marker A', 'changed vendor layout'))
        self.run_helper('--automatic')
        self.config(update_safe=True)
        self.run_helper('--automatic')
        self.run_helper('--check')

    def test_legacy_parent_lock_maintenance_fails_fast_and_installer_can_apply(self):
        lock = self.root / 'run/lock/sll-proxmox-makeover.lock'
        lock.parent.mkdir(parents=True)
        marker = self.root / helper.MAINTENANCE.lstrip('/')
        marker.parent.mkdir(parents=True, mode=0o700)
        marker.write_text('{"operation":"fixture-install"}')
        marker.chmod(0o600)
        before = {p: p.read_bytes() for p in (self.root / 'usr/share').rglob('*') if p.is_file()}
        private_lock = self.root / helper.CONTROL_LOCK.lstrip('/')
        with lock.open('a') as parent, private_lock.open('a') as private:
            fcntl.flock(parent, fcntl.LOCK_EX)
            fcntl.flock(private, fcntl.LOCK_EX)
            manual = subprocess.run([str(REPO / 'sls-proxmox-branding'), '--root', str(self.root)], capture_output=True, text=True, timeout=2)
            self.assertEqual(manual.returncode, 1, manual.stdout + manual.stderr)
            self.assertIn('maintenance', manual.stderr)
            automatic = subprocess.run([str(REPO / 'sls-proxmox-branding'), '--root', str(self.root), '--automatic'], capture_output=True, text=True, timeout=2)
            self.assertEqual(automatic.returncode, 0, automatic.stdout + automatic.stderr)
            self.assertEqual(json.loads(automatic.stdout)['status'], 'maintenance-skipped')
            for path, data in before.items():
                self.assertEqual(path.read_bytes(), data)
            installed = subprocess.run([str(REPO / 'sls-proxmox-branding'), '--root', str(self.root), '--lock-held'], capture_output=True, text=True, timeout=3)
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        marker.unlink()
        self.run_helper('--check')

    def test_maintenance_is_rechecked_after_shared_lock_acquisition(self):
        real_locked = helper.locked
        marker = self.root / helper.MAINTENANCE.lstrip('/')
        before = {p: p.read_bytes() for p in (self.root / 'usr/share').rglob('*') if p.is_file()}

        @contextlib.contextmanager
        def enter_maintenance_after_lock(path):
            with real_locked(path):
                if path.name == 'control.lock':
                    marker.write_text('{"operation":"raced-fixture-install"}')
                    marker.chmod(0o600)
                yield

        with patch.object(__import__('sys'), 'argv', ['helper', '--root', str(self.root)]), patch.object(helper, 'locked', enter_maintenance_after_lock):
            with self.assertRaisesRegex(RuntimeError, 'maintenance'):
                helper.main()
        for path, data in before.items():
            self.assertEqual(path.read_bytes(), data)

    def test_unknown_architecture_and_bad_config_leave_every_target_unchanged(self):
        template = self.root / helper.TEMPLATE.lstrip('/')
        for mutation in ('template', 'config'):
            if mutation == 'template':
                template.write_text('<html>future unknown layout</html>')
            else:
                fixture(self.root)
                self.config(website_url='javascript:alert(1)')
            snapshots = {p: p.read_bytes() for p in (self.root / 'usr/share').rglob('*') if p.is_file()}
            self.run_helper(expected=1)
            for p, before in snapshots.items():
                self.assertEqual(p.read_bytes(), before)

    def test_symlink_input_and_target_rejected_without_external_write(self):
        target = self.root / (helper.MANAGER + '/images/proxmox_logo.png').lstrip('/')
        external = self.root / 'external'
        external.write_bytes(b'protected')
        target.unlink()
        target.symlink_to(external)
        self.run_helper(expected=1)
        self.assertEqual(external.read_bytes(), b'protected')

    def test_source_values_encode_as_data(self):
        self.config(company_name='Example </script><img onerror=alert(1)>')
        self.run_helper()
        raw = (self.root / (helper.MANAGER + '/js/sll-makeover-config.js').lstrip('/')).read_text()
        self.assertNotIn('</script>', raw)
        data = json.loads(raw.split('Object.freeze(', 1)[1].rsplit(');', 1)[0])
        self.assertEqual(data['company_name'], 'Example </script><img onerror=alert(1)>')

    def test_legacy_config_migrates_in_memory_without_overwriting_operator_file(self):
        config = copy.deepcopy(helper.DEFAULT_MAKEOVER_CONFIG)
        config['schema_version'] = 1
        del config['update_safe']
        del config['fonts']
        path = self.root / helper.MAKEOVER_CONFIG.lstrip('/')
        path.write_text(json.dumps(config))
        before = path.read_bytes()
        self.run_helper()
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(helper.load_makeover_config(path)['update_safe'], True)

    def test_remove_preserves_external_asset_changes(self):
        self.run_helper()
        target = self.root / (helper.MANAGER + '/images/logo-128.png').lstrip('/')
        target.write_bytes(b'owner replaced this later')
        self.run_helper('--remove')
        self.assertEqual(target.read_bytes(), b'owner replaced this later')

    def test_invalid_png_crc_trailing_data_and_no_pixels(self):
        valid = (REPO / 'assets/SLS_Proxmox_Favicon.png').read_bytes()
        metadata = helper.validate_png(valid, 'favicon')
        self.assertEqual(metadata['width'], 1254)
        invalid_crc = bytearray(valid)
        invalid_crc[29] ^= 1
        def chunk(kind, data):
            return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
        ihdr = struct.pack('>IIBBBBB', 64, 64, 8, 6, 0, 0, 0)
        bad_pixels = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', ihdr) + chunk(b'IDAT', zlib.compress(b'bad pixels')) + chunk(b'IEND', b'')
        for candidate in (bytes(invalid_crc), valid + b'payload', b'<svg/>', bad_pixels):
            with self.assertRaises(Exception):
                helper.validate_png(candidate, 'favicon')

    def test_write_failure_rolls_overlay_back(self):
        before = {p: p.read_bytes() for p in (self.root / 'usr/share').rglob('*') if p.is_file()}
        real_atomic = helper.atomic
        count = [0]
        def fail_once(path, data, mode=0o644):
            if str(path).startswith(str(self.root / 'usr/share')):
                count[0] += 1
                if count[0] == 4:
                    raise OSError('injected disk failure')
            return real_atomic(path, data, mode)
        with patch.object(sys := __import__('sys'), 'argv', ['helper', '--root', str(self.root)]), patch.object(helper, 'atomic', fail_once):
            with self.assertRaisesRegex(RuntimeError, 'Rollback: complete'):
                helper.main()
        for p, data in before.items():
            self.assertEqual(p.read_bytes(), data)
        self.assertFalse((self.root / (helper.MANAGER + '/js/sll-makeover.js').lstrip('/')).exists())


if __name__ == '__main__':
    unittest.main()
