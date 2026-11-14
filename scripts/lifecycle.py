#!/usr/bin/env python3
"""Local, reversible Proxmox Makeover installation and explicit activation.

Live staging never changes canonical application files. --root is an isolated
filesystem fixture: it never invokes systemd, pvesh, apt, or daemon programs.
"""
import argparse
import contextlib
import datetime
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import uuid

# Load from this trusted source/installed script directory, never a caller's
# working directory or PYTHONPATH. The release builder uses the same selector.
_release_spec = importlib.util.spec_from_file_location('_makeover_release_inputs', Path(__file__).with_name('release_inputs.py'))
_release_module = importlib.util.module_from_spec(_release_spec)
_release_spec.loader.exec_module(_release_module)
selected_release_inputs = _release_module.selected_inputs

VERSION = '0.1-beta'
STATE = '/var/lib/proxmox-makeover'
MANIFEST = STATE + '/manifest.json'
PENDING = STATE + '/staged.json'
HELPER = '/usr/local/sbin/sls-proxmox-branding'
CONFIG = '/etc/sll-proxmox-makeover/config.json'
ARTWORK = ('/usr/local/share/sls-proxmox-branding/assets/SLS_Proxmox.png',
           '/usr/local/share/sls-proxmox-branding/assets/SLS_Proxmox_Favicon.png')
CONTROL_LOCK = STATE + '/control.lock'
MAINTENANCE = STATE + '/maintenance.json'
LEGACY_API_LOCK = '/run/lock/sll-proxmox-makeover.lock'
LEGACY_OVERLAY_LOCK = '/run/lock/sls-proxmox-branding.lock'
EVENT_TIMER = 'sls-proxmox-branding.timer'
EVENT_PATH = 'sls-proxmox-branding.path'
EVENT_SERVICE = 'sls-proxmox-branding.service'
# Exact pre-beta helper shipped in the 2026-11-08 implementation handoff.
LEGACY_SCHEMA1_HELPER = '017b2d18d60e6148e8330264bf59464fbc4d9ded98f79753e47b12b5f4d64908'
RETAIN_UNTIL_UNLOAD = {
    HELPER, '/usr/local/sbin/proxmox-makeover',
    '/usr/local/libexec/proxmox-makeover/lifecycle.py',
    '/usr/local/libexec/sll-pveproxy', '/usr/local/libexec/sll-pvedaemon',
    '/usr/local/lib/site_perl/PVE/API2/SLLCustoms.pm',
    '/usr/local/lib/site_perl/PVE/API2/SLLPasskeys.pm',
    '/usr/local/lib/site_perl/SLL/Makeover/Bootstrap.pm',
    '/usr/local/libexec/proxmox-makeover/passkeys.py',
    '/usr/local/libexec/proxmox-makeover/release_inputs.py',
}
DROPINS = ('/etc/systemd/system/pveproxy.service.d/sll-makeover.conf',
           '/etc/systemd/system/pvedaemon.service.d/sll-makeover.conf')
DEPENDENCIES = 'apt install python3 python3-pil python3-fido2 python3-cryptography perl liburi-perl libwww-perl libio-compress-perl'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(argv, **kwargs):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=90, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{shlex.join(map(str, argv))} failed: {result.stderr.strip() or result.stdout.strip()}')
    return result.stdout


def checked_path(path, owner=None):
    """Reject symlinks and unowned existing components without resolving them."""
    # Linux treats repeated leading slashes as the same filesystem root;
    # pathlib intentionally preserves exactly two, which must never select
    # fixture mode for the live host.
    path = Path('/' + os.path.abspath(str(path)).lstrip('/'))
    for part in [*reversed(path.parents), path]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError(f'Refusing symlink: {part}')
        if owner is not None and info.st_uid != owner:
            raise RuntimeError(f'Refusing path not owned by uid {owner}: {part}')
        if owner is not None and info.st_mode & 0o022:
            # Debian's shared lock directory is deliberately sticky/writable;
            # its opened lock files still require O_NOFOLLOW and root ownership.
            shared_lock_directory = (part == Path('/run/lock') and
                                     stat.S_ISDIR(info.st_mode) and
                                     info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
            if not shared_lock_directory:
                raise RuntimeError(f'Refusing group/world-writable managed path: {part}')
        if part != path and not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f'Parent is not a directory: {part}')
    return path


class Layout:
    def __init__(self, root):
        self.legacy_overlay = None
        self.event_states = {}
        self.root = checked_path(root)
        if not self.root.is_dir():
            raise RuntimeError('The --root directory must already exist.')
        self.live = self.root.samefile(Path('/'))
        if self.live:
            self.root = Path('/')
        if self.live and os.geteuid() != 0:
            raise RuntimeError('Run this command as root on the Proxmox host.')
        self.owner = 0 if self.live else None
        checked_path(self.root, self.owner)
        helper_path = self.path(HELPER)
        self.legacy_lock_required = helper_path.is_file() and digest(helper_path.read_bytes()) == LEGACY_SCHEMA1_HELPER
        manifest = self.json(MANIFEST, {})
        self.legacy_lock_required = self.legacy_lock_required or bool(manifest.get('legacy_lock_required'))
        latest = self.json(STATE + '/latest-transaction.json')
        if latest:
            transaction = self.json(latest['transaction'] + '/transaction.json', {})
            if transaction.get('status') in ('prepared', 'recovery-required'):
                self.legacy_lock_required = self.legacy_lock_required or bool(transaction.get('legacy_lock_required'))
                self.event_states = transaction.get('event_states', {})

    def path(self, name):
        if not name.startswith('/') or '..' in Path(name).parts:
            raise RuntimeError(f'Invalid managed path: {name}')
        return checked_path(self.root / name.lstrip('/'), self.owner)

    def write(self, name, data, mode=0o644):
        target = self.path(name)
        if target.exists() and not target.is_file():
            raise RuntimeError(f'Managed target is not a regular file: {target}')
        target.parent.mkdir(parents=True, exist_ok=True)
        checked_path(target.parent, self.owner)
        fd, temporary = tempfile.mkstemp(prefix='.makeover-', dir=target.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), mode)
            os.replace(temporary, target)
            directory = os.open(target.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def unlink(self, name):
        target = self.path(name)
        if target.exists():
            if not target.is_file():
                raise RuntimeError(f'Managed target is not a regular file: {target}')
            target.unlink()

    def json(self, name, default=None):
        target = self.path(name)
        return json.loads(target.read_text()) if target.exists() else default

    def save(self, name, value):
        self.write(name, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode(), 0o600)

    @contextlib.contextmanager
    def locked(self):
        path = self.path(STATE)
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.stat().st_mode & 0o077:
            raise RuntimeError(f'Installation state directory must be private (0700): {path}')
        lock = self.path(STATE + '/install.lock')
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise RuntimeError('The installer lock is not a trusted regular file.')
            os.fchmod(stream.fileno(), 0o600)
            fcntl.flock(stream, fcntl.LOCK_EX)
            yield

    @contextlib.contextmanager
    def presentation_locked(self):
        """Serialize canonical changes with the API, APT and path helpers."""
        path = self.path(CONTROL_LOCK)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.parent.stat().st_mode & 0o077:
            raise RuntimeError('The private Makeover control directory must have mode 0700.')
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise RuntimeError('The presentation lock is not a trusted regular file.')
            os.fchmod(stream.fileno(), 0o600)
            fcntl.flock(stream, fcntl.LOCK_EX)
            # Private first, legacy second is the only permitted lock order.
            if self.legacy_lock_required:
                legacy = self.path(LEGACY_API_LOCK)
                legacy.parent.mkdir(parents=True, exist_ok=True)
                legacy_fd = os.open(legacy, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                with os.fdopen(legacy_fd, 'a') as compatibility:
                    info = os.fstat(compatibility.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                        raise RuntimeError('The legacy compatibility lock is not trusted.')
                    # Never remove, chown or chmod a legacy shared-directory file.
                    fcntl.flock(compatibility, fcntl.LOCK_EX)
                    yield
            else:
                yield

    @contextlib.contextmanager
    def maintenance(self, operation, recover=False):
        """Block new API reads/writes between individual locked mutation phases."""
        interrupted = False
        prior_events = self.event_states
        with self.presentation_locked():
            if self.path(MAINTENANCE).exists():
                interrupted = True
                marker = self.json(MAINTENANCE)
                prior_events = marker.get('event_states', prior_events) if isinstance(marker, dict) else prior_events
                if not recover:
                    raise RuntimeError('Interrupted installer maintenance marker exists. Review the retained transaction, then run rollback in a clear interruption window.')
                pid = marker.get('pid') if isinstance(marker, dict) else None
                if isinstance(pid, int) and pid != os.getpid():
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        pass
                    else:
                        raise RuntimeError(f'Installer maintenance process {pid} still exists; recovery refused.')
            self.save(MAINTENANCE, {'operation': operation, 'pid': os.getpid(), 'version': VERSION})
        # The caller marks an operation unsafe immediately before changing
        # canonical files, and safe again only after complete recovery.
        # Failure before a recovery snapshot must not clear an older marker
        # whose interrupted canonical state has not yet been restored.
        lease = {'safe_to_clear': not interrupted, 'event_states': prior_events}
        try:
            yield lease
        except BaseException:
            with self.presentation_locked():
                if lease['safe_to_clear']:
                    self.unlink(MAINTENANCE)
                else:
                    self.save(MAINTENANCE, {'operation': operation, 'pid': os.getpid(),
                                           'version': VERSION, 'status': 'recovery-required',
                                           'event_states': lease.get('event_states', {})})
                    print('Installer recovery is incomplete. The maintenance marker remains; review the retained transaction and run guarded rollback before resuming Makeover.', file=sys.stderr)
            raise
        else:
            with self.presentation_locked():
                self.unlink(MAINTENANCE)
        finally:
            self.release_legacy_overlay()

    def acquire_legacy_overlay(self):
        """Caller holds private then legacy API locks; never kill a writer."""
        if not self.legacy_lock_required or self.legacy_overlay is not None:
            return
        path = self.path(LEGACY_OVERLAY_LOCK)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise RuntimeError('The legacy presentation lock is not trusted.')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('A legacy presentation helper is still running. Wait for it to finish before retrying.') from None
            self.legacy_overlay = fd
        except BaseException:
            os.close(fd)
            raise

    def release_legacy_overlay(self):
        if self.legacy_overlay is not None:
            os.close(self.legacy_overlay)
            self.legacy_overlay = None

    @contextlib.contextmanager
    def legacy_overlay_locked(self):
        self.acquire_legacy_overlay()
        try:
            yield
        finally:
            # Release before the enclosing private/API locks, including a
            # failed very first helper replacement. An old API child must not
            # retain its API lock while waiting on our abandoned overlay lock.
            self.release_legacy_overlay()


def read_source(source, relative):
    path = checked_path(source / relative)
    if not path.is_file():
        raise RuntimeError(f'Missing release file: {relative}')
    return path.read_bytes()


def payload(source):
    files = {
        HELPER: ('sls-proxmox-branding', 0o755),
        '/usr/local/sbin/proxmox-makeover': ('scripts/proxmox-makeover', 0o755),
        '/usr/local/libexec/proxmox-makeover/lifecycle.py': ('scripts/lifecycle.py', 0o755),
        '/usr/local/libexec/proxmox-makeover/passkeys.py': ('scripts/passkeys.py', 0o755),
        '/usr/local/libexec/proxmox-makeover/release_inputs.py': ('scripts/release_inputs.py', 0o644),
        '/usr/local/libexec/sll-pveproxy': ('sll-pveproxy', 0o755),
        '/usr/local/libexec/sll-pvedaemon': ('sll-pvedaemon', 0o755),
        '/usr/local/lib/site_perl/SLL/Makeover/Bootstrap.pm': ('SLL/Makeover/Bootstrap.pm', 0o644),
        '/usr/local/lib/site_perl/PVE/API2/SLLCustoms.pm': ('PVE/API2/SLLCustoms.pm', 0o644),
        '/usr/local/lib/site_perl/PVE/API2/SLLPasskeys.pm': ('PVE/API2/SLLPasskeys.pm', 0o644),
        CONFIG: ('config.json', 0o600),
        '/usr/local/share/sls-proxmox-branding/assets/southland.css': ('southland.css', 0o644),
        '/usr/local/share/sls-proxmox-branding/assets/southland.js': ('southland.js', 0o644),
        '/usr/local/share/sls-proxmox-branding/makeover/makeover.css': ('makeover.css', 0o644),
        '/usr/local/share/sls-proxmox-branding/makeover/makeover.js': ('makeover.js', 0o644),
        '/usr/local/share/sls-proxmox-branding/makeover/native-security.js': ('native-security.js', 0o644),
        '/usr/local/share/sls-proxmox-branding/makeover/login-passkeys.js': ('login-passkeys.js', 0o644),
        DROPINS[0]: ('systemd/pveproxy-sll-makeover.conf', 0o644),
        DROPINS[1]: ('systemd/pvedaemon-sll-makeover.conf', 0o644),
        '/etc/systemd/system/sls-proxmox-branding.service': ('systemd/sls-proxmox-branding.service', 0o644),
        '/etc/systemd/system/sls-proxmox-branding.path': ('systemd/sls-proxmox-branding.path', 0o644),
        '/etc/apt/apt.conf.d/99sls-proxmox-branding': ('hooks/99sls-proxmox-branding', 0o644),
    }
    for name in ('SLS_Proxmox.png', 'SLS_Proxmox_Favicon.png',
                 'fonts/dm-sans.ttf', 'fonts/oxanium.ttf',
                 'fonts/DM-Sans-OFL.txt', 'fonts/Oxanium-OFL.txt'):
        files['/usr/local/share/sls-proxmox-branding/assets/' + name] = ('assets/' + name, 0o644)
    result = {name: (read_source(source, relative), mode) for name, (relative, mode) in files.items()}
    return result


def preflight(layout, recovery=False):
    if not layout.live:
        return
    missing = [name for name in ('python3', 'perl', 'pvesh', 'systemctl', 'dpkg-query') if not shutil.which(name)]
    if missing:
        if recovery:
            raise RuntimeError(f'Native Proxmox recovery commands are missing: {", ".join(missing)}. Repair the native host tools before guarded removal/recovery.')
        raise RuntimeError(f'Missing commands: {", ".join(missing)}. On PVE 9 install dependencies first: {DEPENDENCIES}')
    version = run(['dpkg-query', '-W', '-f=${Version}', 'pve-manager']).strip()
    if recovery:
        if not version:
            raise RuntimeError('Native pve-manager is unavailable; guarded recovery requires the native Proxmox installation.')
        # Unloading a broken extension must not depend on the packages that
        # broke it, nor require a now-unsupported major PVE version to be old.
        return
    if not re.match(r'^9\.', version):
        raise RuntimeError(f'This beta supports PVE 9 only; found pve-manager {version}.')
    try:
        run(['/usr/bin/python3', '-c', 'from PIL import Image; Image.new("RGBA", (1,1)).load()'])
        run(['/usr/bin/python3', '-I', '-c',
             'from importlib.metadata import version; import re; '
             'from fido2.server import Fido2Server; '
             'from fido2.webauthn import AuthenticationResponse, RegistrationResponse; '
             'import cryptography; '
             'v=tuple(map(int,re.match(r"^(\\d+)\\.(\\d+)",version("fido2")).groups())); '
             'assert (1,2) <= v < (3,0), "python3-fido2 >=1.2,<3 is required"'])
        run(['perl', '-MPVE::API2', '-MPVE::AccessControl', '-MPVE::RESTHandler',
             '-MPVE::RPCEnvironment', '-MPVE::APIServer::Formatter', '-MHTTP::Response',
             '-MAuthen::PAM', '-MCompress::Zlib', '-MDigest::SHA', '-MJSON::PP', '-MMIME::Base64', '-MURI', '-e', '1'])
    except RuntimeError as error:
        raise RuntimeError(f'Dependency preflight failed. Install dependencies first: {DEPENDENCIES}\n{error}') from error


def socket_sessions(proc_root):
    sessions = set()
    for name in ('net/tcp', 'net/tcp6'):
        path = proc_root / name
        if not path.exists():
            continue
        for line in path.read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10 or fields[3] != '01':
                continue
            ports = [int(fields[index].rsplit(':', 1)[1], 16) for index in (1, 2)]
            if any(port == 3128 or 5900 <= port <= 5999 or 61000 <= port <= 61999 for port in ports):
                sessions.add(fields[9])
    unix = proc_root / 'net/unix'
    if unix.exists():
        for line in unix.read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 8 and fields[5] == '03' and re.search(r'(\.vnc(?:$|\W)|spice)', fields[7], re.I):
                sessions.add(fields[6])
    return sessions


def process_sessions(proc_root=Path('/proc')):
    """Check processes independently of task API, including detached consoles."""
    socket_inodes = socket_sessions(proc_root)
    result = []
    for directory in proc_root.iterdir():
        if not directory.name.isdigit() or int(directory.name) == os.getpid():
            continue
        try:
            raw = (directory / 'cmdline').read_bytes()
            arguments = [item.decode(errors='replace') for item in raw.split(b'\0') if item]
            command = ' '.join(arguments)
            first = Path(arguments[0]).name if arguments else ''
            # Never classify an ordinary QEMU guest's -vnc/-spice arguments as
            # an attached session; idle PVE daemon workers are likewise safe.
            task = bool(re.search(r'(?:^|\s)task\s+UPID:', command))
            console = first in ('termproxy', 'vncshell', 'vncproxy', 'vncterm')
            console = console or bool(re.search(r'(?:^|\s)(?:/\S*/)?(?:termproxy|vncshell|vncproxy|vncterm)(?:\s|$)', command))
            console = console or (first == 'dtach' and 'vzctlconsole' in command)
            connected = False
            if first in ('pveproxy', 'spiceproxy') or re.match(r'^(pveproxy|spiceproxy) worker', command):
                for descriptor in (directory / 'fd').iterdir():
                    try:
                        link = os.readlink(descriptor)
                    except FileNotFoundError:
                        continue
                    match = re.fullmatch(r'socket:\[(\d+)\]', link)
                    if match and match.group(1) in socket_inodes:
                        connected = True
                        break
            if task or console or connected:
                result.append({'pid': int(directory.name), 'process': command[:250]})
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError as error:
            raise RuntimeError(f'Cannot inspect process {directory.name}; activation refused.') from error
    return result


def guard_sessions(layout):
    if not layout.live:
        return
    # source=active is essential: the endpoint defaults to archived tasks.
    node = socket.gethostname().split('.')[0]
    response = run(['pvesh', 'get', f'/nodes/{node}/tasks', '--source', 'active',
                    '--limit', '100000', '--output-format', 'json'])
    tasks = json.loads(response)
    if not isinstance(tasks, list):
        raise RuntimeError('Task API did not return a list; activation refused.')
    active = [task for task in tasks if not task.get('endtime') and
              str(task.get('status', 'RUNNING')).upper() == 'RUNNING']
    processes = process_sessions()
    if active or processes:
        details = json.dumps({'active_tasks': active, 'console_processes': processes}, indent=2)
        raise RuntimeError('Active Proxmox tasks or console sessions exist. Close them and coordinate an interruption window, then retry. No force bypass is available.\n' + details)


def helper(layout, *arguments):
    argv = [str(layout.path(HELPER))]
    if not layout.live:
        argv.extend(['--root', str(layout.root)])
    argv.extend(arguments)
    return run(argv)


def helper_locked(layout, *arguments):
    """Caller holds the shared lock; old helper has only its overlay lock."""
    program = layout.path(HELPER).read_bytes()
    if b'--lock-held' in program:
        return helper(layout, *arguments, '--lock-held')
    if b'/run/lock/sll-proxmox-makeover.lock' in program:
        raise RuntimeError('Restored helper uses an unknown shared-lock protocol; review before reapplying.')
    # An intentionally restored legacy helper takes this lock itself. Its
    # producers remain paused, while the caller still owns the legacy API lock.
    layout.release_legacy_overlay()
    return helper(layout, *arguments)


def current_preferences(layout):
    return {name: layout.path(name).read_bytes() for name in (CONFIG, *ARTWORK) if layout.path(name).exists()}


def restore_preferences(layout, preferences, reason):
    """Keep user values, downgrade only for the exact recognized old helper."""
    if not preferences:
        return
    current = dict(preferences)
    config_bytes = current.get(CONFIG)
    program = layout.path(HELPER)
    if config_bytes and program.exists() and digest(program.read_bytes()) == LEGACY_SCHEMA1_HELPER:
        config = json.loads(config_bytes)
        if config.get('schema_version') == 2:
            if type(config.get('update_safe')) is not bool:
                raise RuntimeError('Cannot downgrade an invalid schema 2 configuration.')
            retained = STATE + '/retained/' + stamp() + '/config-schema2.json'
            layout.write(retained, config_bytes, 0o600)
            config = dict(config)
            config.pop('update_safe')
            config.pop('fonts', None)
            config['schema_version'] = 1
            current[CONFIG] = (json.dumps(config, indent=2) + '\n').encode()
            print(f'{reason}: retained schema 2 settings at {layout.path(retained)}; preserved current text/colors in compatible schema 1.')
        elif config.get('schema_version') != 1:
            raise RuntimeError('Cannot restore unsupported settings to the recognized schema 1 helper.')
    for name, data in current.items():
        layout.write(name, data, 0o600 if name == CONFIG else 0o644)


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]


def stage(layout, source):
    # Validate the complete release before storing it. Never execute a remote
    # fetch, package installation, or a service action while staging.
    payload(source)
    release = STATE + '/releases/' + VERSION + '-' + stamp()
    for path in selected_release_inputs(source):
        relative = path.relative_to(source)
        checked_path(path)
        mode = 0o755 if path.name in ('install.sh', 'proxmox-makeover', 'sls-proxmox-branding', 'sll-pveproxy', 'sll-pvedaemon') else 0o644
        layout.write(release + '/' + str(relative), path.read_bytes(), mode)
    layout.save(PENDING, {'version': VERSION, 'release': release, 'status': 'staged'})
    print(f'Proxmox Makeover {VERSION} staged; installed presentation and daemons were untouched.')
    print('Activate in a coordinated interruption window after closing consoles and tasks:')
    print('bash ' + shlex.quote(str(layout.path(release + '/install.sh'))) + ' --activate')


def snapshot(layout, names, operation):
    transaction = STATE + '/transactions/' + stamp()
    before = {}
    for name in names:
        path = layout.path(name)
        if path.exists():
            if not path.is_file():
                raise RuntimeError(f'Managed target is not a regular file: {path}')
            data = path.read_bytes()
            blob = transaction + '/blobs/' + digest(data)
            layout.write(blob, data, 0o600)
            before[name] = {'blob': blob, 'mode': stat.S_IMODE(path.stat().st_mode), 'sha256': digest(data)}
        else:
            before[name] = None
    document = {'operation': operation, 'status': 'prepared', 'files': before,
                'manifest': layout.json(MANIFEST), 'version': VERSION, 'transaction': transaction,
                'legacy_lock_required': layout.legacy_lock_required,
                'event_states': layout.event_states}
    layout.save(transaction + '/transaction.json', document)
    layout.save(STATE + '/latest-transaction.json', {'transaction': transaction})
    return document


def restore_snapshot(layout, transaction, skip=()):
    for name, entry in transaction['files'].items():
        if name in skip:
            continue
        if entry is None:
            layout.unlink(name)
        else:
            data = layout.path(entry['blob']).read_bytes()
            if digest(data) != entry['sha256']:
                raise RuntimeError(f'Recovery backup hash mismatch for {name}')
            layout.write(name, data, entry['mode'])
    if transaction.get('manifest') is None:
        layout.unlink(MANIFEST)
    else:
        layout.save(MANIFEST, transaction['manifest'])


def transaction_status(layout, transaction, status):
    transaction['status'] = status
    layout.save(transaction['transaction'] + '/transaction.json', transaction)


def restart_daemons(layout):
    if not layout.live:
        return
    guard_sessions(layout)
    run(['systemctl', 'daemon-reload'])
    # Recheck immediately before each daemon lifecycle; a new session must
    # never be dismissed just because the first guard passed.
    guard_sessions(layout)
    run(['systemctl', 'restart', 'pvedaemon.service'])
    guard_sessions(layout)
    run(['systemctl', 'restart', 'pveproxy.service'])
    run(['systemctl', 'is-active', '--quiet', 'pvedaemon.service', 'pveproxy.service'])


def watcher_exists():
    return run(['systemctl', 'show', '--property=LoadState', '--value', 'sls-proxmox-branding.path']).strip() != 'not-found'


def capture_event_states(layout):
    if not layout.live:
        return {}
    states = {}
    for unit in (EVENT_TIMER, EVENT_PATH, EVENT_SERVICE):
        output = run(['systemctl', 'show', '--property=LoadState,ActiveState,UnitFileState', unit])
        fields = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
        if fields.get('LoadState') == 'not-found':
            continue
        if fields.get('LoadState') not in ('loaded', 'masked') or fields.get('ActiveState') not in ('active', 'activating', 'reloading', 'inactive', 'failed', 'deactivating'):
            raise RuntimeError(f'Cannot determine the existing presentation unit state: {unit}')
        states[unit] = fields
    return states


def canonical_helper_processes(layout, proc_root=Path('/proc')):
    """Report PIDs only; never log process arguments or terminate APT."""
    expected = str(layout.path(HELPER))
    processes = []
    for directory in proc_root.iterdir():
        if not directory.name.isdigit() or int(directory.name) == os.getpid():
            continue
        try:
            arguments = [value.decode(errors='replace') for value in (directory / 'cmdline').read_bytes().split(b'\0') if value]
            if not any(argument.startswith('/') and os.path.normpath(argument) == expected for argument in arguments):
                continue
            # A production canonical helper used for an unrelated isolated
            # fixture does not write this target node's presentation.
            target = next((arguments[index + 1] for index, value in enumerate(arguments[:-1]) if value == '--root'), '/')
            target = next((value.split('=', 1)[1] for value in arguments if value.startswith('--root=')), target)
            if Path('/' + os.path.abspath(target).lstrip('/')) != layout.root:
                continue
            processes.append(int(directory.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            raise RuntimeError('Cannot inspect a running process before presentation activation.') from None
    return processes


def ensure_no_helper_processes(layout):
    if layout.live:
        processes = canonical_helper_processes(layout)
        if processes:
            raise RuntimeError('A canonical presentation helper is running (PIDs ' + ', '.join(map(str, processes)) + '). Wait for APT/manual work to finish; no process was terminated.')


def restore_event_producers(layout, states, *, success=False, operation=None, restore_enablement=False):
    if not layout.live:
        return
    for unit in (EVENT_TIMER, EVENT_PATH):
        if success and operation == 'install' and unit == EVENT_PATH:
            continue  # Healthy install explicitly enables its new path unit.
        state = states.get(unit)
        if not state:
            continue
        if success and unit == EVENT_PATH and not layout.path('/etc/systemd/system/' + unit).exists():
            continue  # An introduced path has just been removed intentionally.
        if restore_enablement and unit == EVENT_PATH:
            enabled = state.get('UnitFileState')
            if enabled in ('enabled', 'enabled-runtime'):
                run(['systemctl', 'enable', *(['--runtime'] if enabled == 'enabled-runtime' else []), unit])
            elif enabled == 'disabled':
                run(['systemctl', 'disable', unit])
        if state['ActiveState'] in ('active', 'activating', 'reloading'):
            run(['systemctl', 'start', unit])
        elif restore_enablement:
            run(['systemctl', 'stop', unit])


def recover_event_producers(layout, maintenance, errors):
    if not errors:
        try:
            restore_event_producers(layout, layout.event_states, restore_enablement=True)
        except Exception as error:
            errors.append('presentation producer recovery')
            print(f'Presentation producer recovery needs review: {error}', file=sys.stderr)


def abort_before_mutation(layout, maintenance, transaction):
    errors = []
    if maintenance['safe_to_clear']:
        recover_event_producers(layout, maintenance, errors)
    transaction_status(layout, transaction, 'recovery-required' if errors or not maintenance['safe_to_clear'] else 'rolled-back')
    if errors:
        maintenance['safe_to_clear'] = False


@contextlib.contextmanager
def preparing_transaction(layout, maintenance):
    """Pause producers and naturally drain their writer before source swaps."""
    captured = capture_event_states(layout)
    # Interrupted recovery preserves the original desired producer states even
    # when a failed earlier attempt has correctly left those producers paused.
    layout.event_states = {**captured, **maintenance.get('event_states', {})}
    maintenance['event_states'] = layout.event_states
    try:
        # Persist desired states before pausing the first producer. This also
        # covers interruption before snapshot() has written its transaction.
        with layout.presentation_locked():
            marker = layout.json(MAINTENANCE)
            if marker is not None:
                marker['event_states'] = layout.event_states
                layout.save(MAINTENANCE, marker)
        if layout.live:
            for unit in (EVENT_TIMER, EVENT_PATH):
                if captured.get(unit, {}).get('ActiveState') in ('active', 'activating', 'reloading', 'deactivating'):
                    run(['systemctl', 'stop', unit])
            if captured.get(EVENT_SERVICE, {}).get('ActiveState') in ('active', 'activating', 'reloading', 'deactivating'):
                for attempt in range(31):
                    state = run(['systemctl', 'show', '--property=ActiveState', '--value', EVENT_SERVICE]).strip()
                    if state in ('inactive', 'failed'):
                        break
                    if attempt == 30 or state not in ('active', 'activating', 'reloading', 'deactivating'):
                        raise RuntimeError('Presentation repair is still running. Wait for natural completion before retrying; no service was killed.')
                    time.sleep(0.5)
            ensure_no_helper_processes(layout)
        yield
    except BaseException:
        if maintenance['safe_to_clear']:
            try:
                restore_event_producers(layout, captured)
            except Exception as error:
                maintenance['safe_to_clear'] = False
                print(f'Presentation watcher preparation recovery needs review: {error}', file=sys.stderr)
        raise


def requires_passkey_backend(manifest):
    return bool(manifest and manifest.get('status') in ('active', 'fixture', 'pending-uninstall')
                and 'primary_passkeys' in manifest.get('features', []))


def loaded_api_health(layout):
    """Check resident proxy and protected daemon dispatch without a ticket.

    The exact public status route is protected and therefore forwarded by the
    native proxy to pvedaemon. A loopback-only TLS connection intentionally
    accepts the host's own Proxmox certificate; it uses no proxy or credentials.
    """
    if not layout.live:
        return {'version': VERSION, 'primary_passkeys': True, 'supported': False,
                'rp_configured': False, 'fixture': True}
    for attempt in range(6):
        connection = http.client.HTTPSConnection('127.0.0.1', 8006, timeout=4,
                                                 context=ssl._create_unverified_context())
        try:
            connection.request('GET', '/api2/json/sll-passkeys/status',
                               headers={'Accept': 'application/json', 'Connection': 'close'})
            response = connection.getresponse()
            raw = response.read(65537)
            if response.status != 200 or len(raw) > 65536:
                raise RuntimeError('Resident Makeover status route is unavailable or oversized.')
            value = json.loads(raw)
            data = value.get('data') if isinstance(value, dict) else None
            if not isinstance(data, dict) or data.get('version') != VERSION or data.get('primary_passkeys') is not True or type(data.get('supported')) is not bool:
                raise RuntimeError('Resident Makeover API version or passkey capability does not match the installed release.')
            configured = data.get('rp') is not None
            if configured and not data['supported']:
                raise RuntimeError('The configured primary passkey relying party cannot use its verifier.')
            return {**{key: data[key] for key in ('version', 'primary_passkeys', 'supported')},
                    'rp_configured': configured}
        except (OSError, ValueError, http.client.HTTPException, RuntimeError):
            if attempt == 5:
                raise RuntimeError('Resident Makeover API health check failed after activation. Native services being active is insufficient; review retained recovery evidence.') from None
            time.sleep(0.5)
        finally:
            connection.close()


def install(layout, source, activate):
    source = checked_path(source)
    files = payload(source)
    if layout.live and not activate:
        stage(layout, source)
        return
    preflight(layout)
    guard_sessions(layout)
    old = layout.json(MANIFEST, {})
    if old.get('status') == 'pending-uninstall':
        raise RuntimeError('An uninstall is staged. Complete it with activate before installing again.')
    for name in files:
        layout.path(name)
    entries = dict(old.get('files', {}))
    with layout.maintenance('install') as maintenance:
        with preparing_transaction(layout, maintenance):
            with layout.presentation_locked():
                # Include preserved data in recovery evidence and baseline tracking
                # even when installation does not overwrite a single byte of it.
                transaction = snapshot(layout, [*files, '/etc/sls-proxmox-branding.disabled'], 'install')
        changed = False
        try:
            with layout.presentation_locked(), layout.legacy_overlay_locked():
                ensure_no_helper_processes(layout)
                maintenance['safe_to_clear'] = False
                changed = True
                for name, (data, mode) in files.items():
                    path = layout.path(name)
                    if name in (CONFIG, *ARTWORK) and path.exists():
                        data = path.read_bytes()
                    else:
                        layout.write(name, data, mode)
                    original = entries.get(name, {}).get('original', transaction['files'][name])
                    entries[name] = {'original': original, 'installed': digest(data), 'mode': mode}
                    if name == HELPER:
                        ensure_no_helper_processes(layout)
                if layout.live:
                    for module in ('PVE/API2/SLLCustoms.pm', 'PVE/API2/SLLPasskeys.pm', 'SLL/Makeover/Bootstrap.pm'):
                        run(['perl', '-I/usr/local/lib/site_perl', '-c', '/usr/local/lib/site_perl/' + module])
                print(helper_locked(layout, '--enable'), end='')
            layout.release_legacy_overlay()
            if layout.live:
                restart_daemons(layout)
                health = loaded_api_health(layout)
                run(['systemctl', 'enable', '--now', 'sls-proxmox-branding.path'])
            else:
                health = loaded_api_health(layout)
            restore_event_producers(layout, layout.event_states, success=True, operation='install')
            manifest = {'version': VERSION, 'status': 'active' if layout.live else 'fixture',
                        'features': ['primary_passkeys'], 'health': health,
                        # Healthy beta daemons use private controls exclusively.
                        # The prior transaction retains any legacy bridge needed
                        # for rollback or interrupted-upgrade recovery.
                        'legacy_lock_required': False,
                        'files': entries, 'source': str(source), 'transaction': transaction['transaction']}
            layout.save(MANIFEST, manifest)
            layout.unlink(PENDING)
            transaction_status(layout, transaction, 'committed')
        except Exception:
            if not changed:
                abort_before_mutation(layout, maintenance, transaction)
                raise
            errors = []
            with layout.presentation_locked():
                had_helper = transaction['files'].get(HELPER) is not None
                if not had_helper and layout.path(HELPER).exists():
                    try:
                        helper_locked(layout, '--remove')
                    except Exception as error:
                        errors.append('presentation removal')
                        print(f'Presentation rollback needs review: {error}', file=sys.stderr)
                try:
                    restore_snapshot(layout, transaction)
                except Exception as error:
                    errors.append('canonical snapshot restoration')
                    print(f'Canonical rollback needs review: {error}', file=sys.stderr)
                if had_helper and not errors:
                    try:
                        helper_locked(layout)
                    except Exception as error:
                        errors.append('prior presentation reapply')
                        print(f'Prior presentation reapply needs review: {error}', file=sys.stderr)
            if layout.live and not errors:
                try:
                    restart_daemons(layout)
                    if watcher_exists():
                        run(['systemctl', 'start', 'sls-proxmox-branding.path'])
                except Exception as error:
                    errors.append('daemon recovery')
                    print(f'Daemon recovery requires a clear interruption window: {error}', file=sys.stderr)
            recover_event_producers(layout, maintenance, errors)
            transaction_status(layout, transaction, 'recovery-required' if errors else 'rolled-back')
            maintenance['safe_to_clear'] = not errors
            raise
    print(f'Proxmox Makeover {VERSION} installed. Configuration, audit history and backups are local to this node.')
    if layout.live and not health['supported']:
        print('Primary passkey enrollment is unavailable until native WebAuthn RP ID/origin settings are configured.')


def activate(layout):
    manifest = layout.json(MANIFEST, {})
    if manifest.get('status') == 'pending-uninstall':
        uninstall(layout, True)
        return
    staged = layout.json(PENDING)
    if staged:
        install(layout, layout.path(staged['release']), True)
        return
    if not manifest or manifest.get('status') == 'removed':
        raise RuntimeError('No staged or installed release. Run bash install.sh first.')
    preflight(layout)
    guard_sessions(layout)
    with layout.maintenance('activate') as maintenance:
        with layout.presentation_locked():
            maintenance['safe_to_clear'] = False
            print(helper_locked(layout), end='')
        restart_daemons(layout)
        health = loaded_api_health(layout)
        if layout.live:
            run(['systemctl', 'enable', '--now', 'sls-proxmox-branding.path'])
        manifest['status'] = 'active' if layout.live else 'fixture'
        manifest['features'] = ['primary_passkeys']
        manifest['health'] = health
        layout.save(MANIFEST, manifest)


def uninstall(layout, activate):
    manifest = layout.json(MANIFEST)
    if not manifest or manifest.get('status') == 'removed':
        raise RuntimeError('No installed release recorded. Retained backups were not changed.')
    if layout.live and not activate:
        manifest['status'] = 'pending-uninstall'
        layout.save(MANIFEST, manifest)
        print('Uninstall staged. Modules, wrappers, drop-ins and presentation remain installed until safe deactivation.')
        print('Close consoles/tasks, coordinate an interruption window, then run: proxmox-makeover activate')
        return
    preflight(layout, recovery=True)
    guard_sessions(layout)
    files = manifest['files']
    # A partly completed daemon reload can leave the legacy API resident even
    # after compensation has restored beta files. Capture the bridge before
    # the uninstall snapshot so the next recovery process also takes it.
    original_helper = files.get(HELPER, {}).get('original') or {}
    layout.legacy_lock_required = layout.legacy_lock_required or original_helper.get('sha256') == LEGACY_SCHEMA1_HELPER
    # An external drop-in may still reference our modules. Require deliberate
    # reconciliation before unloading/removing those modules.
    for name in DROPINS:
        path = layout.path(name)
        if name in files and path.exists() and digest(path.read_bytes()) != files[name]['installed']:
            raise RuntimeError(f'Daemon drop-in changed externally; reconcile it before uninstall: {name}')
    with layout.maintenance('uninstall', recover=True) as maintenance:
        with preparing_transaction(layout, maintenance):
            with layout.presentation_locked():
                transaction = snapshot(layout, [*files, '/etc/sls-proxmox-branding.disabled'], 'uninstall')
                preferences = current_preferences(layout)
        changed = False
        try:
            with layout.presentation_locked(), layout.legacy_overlay_locked():
                ensure_no_helper_processes(layout)
                maintenance['safe_to_clear'] = False
                changed = True
                if layout.live:
                    run(['systemctl', 'disable', EVENT_PATH])
                print(helper_locked(layout, '--remove'), end='')
                for name in DROPINS:
                    if name in files:
                        restore_original(layout, name, files[name])
                # Restore legacy files before their original drop-ins load,
                # retaining user settings and artwork independently of code.
                for name, entry in files.items():
                    if name not in (*DROPINS, CONFIG, *ARTWORK) and entry.get('original'):
                        restore_original(layout, name, entry)
                # Remove introduced non-code sources before legacy rendering:
                # the legacy content version hashes its entire source tree.
                for name, entry in files.items():
                    if name not in (*DROPINS, CONFIG, *ARTWORK) and not entry.get('original') and name not in RETAIN_UNTIL_UNLOAD:
                        restore_original(layout, name, entry)
                restore_preferences(layout, preferences, 'Legacy removal')
                if files.get(HELPER, {}).get('original'):
                    print(helper_locked(layout, '--enable'), end='')
            layout.release_legacy_overlay()
            restart_daemons(layout)
            with layout.presentation_locked():
                for name, entry in files.items():
                    if name not in RETAIN_UNTIL_UNLOAD or entry.get('original'):
                        continue
                    restore_original(layout, name, entry)
                manifest['status'] = 'removed'
                layout.save(MANIFEST, manifest)
                transaction_status(layout, transaction, 'committed')
            restore_event_producers(layout, layout.event_states, success=True, operation='uninstall')
        except Exception:
            if not changed:
                abort_before_mutation(layout, maintenance, transaction)
                raise
            errors = []
            with layout.presentation_locked():
                try:
                    restore_snapshot(layout, transaction)
                    helper_locked(layout, '--enable')
                except Exception as error:
                    errors.append('canonical/presentation recovery')
                    print(f'Uninstall presentation recovery needs review: {error}', file=sys.stderr)
            if not errors:
                try:
                    restart_daemons(layout)
                    if layout.live:
                        loaded_api_health(layout)
                        run(['systemctl', 'enable', '--now', 'sls-proxmox-branding.path'])
                except Exception as error:
                    errors.append('daemon recovery')
                    print(f'Uninstall daemon recovery needs review: {error}', file=sys.stderr)
            recover_event_producers(layout, maintenance, errors)
            transaction_status(layout, transaction, 'recovery-required' if errors else 'rolled-back')
            maintenance['safe_to_clear'] = not errors
            raise
    print('Makeover removed. Configuration, audit history, release copies and backups were retained.')


def restore_original(layout, name, entry):
    path = layout.path(name)
    if path.exists() and digest(path.read_bytes()) != entry['installed']:
        print(f'Preserved external change: {name}')
        return
    original = entry.get('original')
    if original:
        data = layout.path(original['blob']).read_bytes()
        if digest(data) != original['sha256']:
            raise RuntimeError(f'Original backup hash mismatch: {name}')
        layout.write(name, data, original['mode'])
    else:
        layout.unlink(name)


def rollback(layout, activate):
    latest = layout.json(STATE + '/latest-transaction.json')
    if not latest:
        raise RuntimeError('No installer transaction is available to roll back.')
    transaction = layout.json(latest['transaction'] + '/transaction.json')
    target_helper = transaction.get('files', {}).get(HELPER) or {}
    layout.legacy_lock_required = (layout.legacy_lock_required or bool(transaction.get('legacy_lock_required'))
                                   or target_helper.get('sha256') == LEGACY_SCHEMA1_HELPER)
    if transaction['status'] == 'rolled-back':
        raise RuntimeError('The latest installer transaction has already been rolled back.')
    if layout.live and not activate:
        raise RuntimeError('Rollback changes installed code and requires --activate in a clear interruption window. No files were changed.')
    preflight(layout, recovery=True)
    guard_sessions(layout)
    with layout.maintenance('rollback', recover=True) as maintenance:
        with preparing_transaction(layout, maintenance):
            with layout.presentation_locked():
                # Rollback is itself recoverable: capture the current payload
                # before applying an older snapshot, including interrupted cases.
                recovery = snapshot(layout, transaction['files'], 'rollback')
                recovery['rollback_target'] = transaction['transaction']
                transaction_status(layout, recovery, 'prepared')
        changed = False
        try:
            with layout.presentation_locked(), layout.legacy_overlay_locked():
                ensure_no_helper_processes(layout)
                maintenance['safe_to_clear'] = False
                changed = True
                preferences = current_preferences(layout)
                had_helper = transaction['files'].get(HELPER) is not None
                deferred = {name for name, entry in transaction['files'].items()
                            if entry is None and name in RETAIN_UNTIL_UNLOAD}
                if layout.path(HELPER).exists():
                    print(helper_locked(layout, '--remove'), end='')
                restore_snapshot(layout, transaction, skip=deferred)
                restore_preferences(layout, preferences, 'Installer rollback')
                prior = transaction.get('manifest') or {}
                if requires_passkey_backend(prior):
                    preflight(layout)
                if had_helper:
                    print(helper_locked(layout, '--enable'), end='')
            layout.release_legacy_overlay()
            restart_daemons(layout)
            if requires_passkey_backend(prior):
                loaded_api_health(layout)
            with layout.presentation_locked():
                for name in deferred:
                    layout.unlink(name)
                transaction_status(layout, transaction, 'rolled-back')
                transaction_status(layout, recovery, 'committed')
            if layout.live and layout.path('/etc/systemd/system/sls-proxmox-branding.path').exists():
                run(['systemctl', 'enable', '--now', 'sls-proxmox-branding.path'])
            restore_event_producers(layout, layout.event_states, success=True, operation='rollback')
        except Exception:
            if not changed:
                abort_before_mutation(layout, maintenance, recovery)
                raise
            errors = []
            with layout.presentation_locked():
                try:
                    restore_snapshot(layout, recovery)
                    if layout.path(HELPER).exists():
                        helper_locked(layout, '--enable')
                except Exception as error:
                    errors.append('canonical/presentation recovery')
                    print(f'Rollback recovery needs review: {error}', file=sys.stderr)
            if not errors:
                try:
                    restart_daemons(layout)
                    if requires_passkey_backend(recovery.get('manifest')):
                        loaded_api_health(layout)
                    if layout.live and layout.path('/etc/systemd/system/sls-proxmox-branding.path').exists():
                        run(['systemctl', 'enable', '--now', 'sls-proxmox-branding.path'])
                except Exception as error:
                    errors.append('daemon recovery')
                    print(f'Rollback daemon recovery needs review: {error}', file=sys.stderr)
            recover_event_producers(layout, maintenance, errors)
            transaction_status(layout, recovery, 'recovery-required' if errors else 'rolled-back')
            if not errors:
                layout.save(STATE + '/latest-transaction.json', {'transaction': transaction['transaction']})
            maintenance['safe_to_clear'] = not errors
            raise
    print('Latest installer transaction rolled back; retained recovery history remains available.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest='command', required=True)
    for name in ('install', 'activate', 'status', 'apply', 'uninstall', 'rollback', 'session-check'):
        command = subcommands.add_parser(name)
        command.add_argument('--root', default='/', help='Isolated fixture root; never invokes host services')
        if name == 'install':
            command.add_argument('--source', required=True)
        if name in ('install', 'uninstall', 'rollback'):
            group = command.add_mutually_exclusive_group()
            group.add_argument('--activate', action='store_true', help='Explicitly permit guarded daemon interruption')
            group.add_argument('--no-activate', action='store_true', help='Stage only on live hosts (default)')
    args = parser.parse_args(argv)
    layout = Layout(args.root)
    if args.command == 'status':
        print(json.dumps({'installed': layout.json(MANIFEST), 'staged': layout.json(PENDING)}, indent=2))
        if layout.path(HELPER).exists():
            print(helper(layout, '--check'), end='')
        return
    if args.command == 'session-check':
        guard_sessions(layout)
        print('No active Proxmox task or console session was found.' if layout.live else 'Fixture: host session inspection skipped.')
        return
    with layout.locked():
        if args.command == 'install':
            install(layout, Path(args.source), args.activate)
        elif args.command == 'activate':
            activate(layout)
        elif args.command == 'apply':
            print(helper(layout), end='')
        elif args.command == 'uninstall':
            uninstall(layout, args.activate)
        elif args.command == 'rollback':
            rollback(layout, args.activate)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'Proxmox Makeover: {error}', file=sys.stderr)
        sys.exit(1)
