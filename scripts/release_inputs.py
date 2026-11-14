"""Shared public-source allowlist for release archives and private staging."""
import os
from pathlib import Path

FILES = ('README.md', 'LICENSE', 'NOTICE', 'SECURITY.md', 'VERSION', '.gitignore',
         'config.json', 'login-passkeys.js', 'native-security.js', 'makeover.js',
         'makeover.css', 'southland.js', 'southland.css', 'sls-proxmox-branding',
         'sll-pveproxy', 'sll-pvedaemon', 'install.sh', 'bootstrap.sh')
DIRECTORIES = ('PVE', 'SLL', 'assets', 'scripts', 'systemd', 'hooks', 'tests',
               'docs', 'tools', '.github')
PRIVATE_DIRECTORIES = {'private', 'secrets', 'credentials', 'passkeys', 'backups',
                       'transactions', 'releases', 'evidence', 'dist', 'runtime',
                       'node_modules', '__pycache__'}
PRIVATE_FILES = {'state.json', 'credentials.json', 'lock', 'audit.jsonl',
                 'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519'}
PRIVATE_SUFFIXES = {'.key', '.pem', '.p12', '.pfx', '.jks', '.db', '.sqlite', '.sqlite3', '.pyc'}


def selected_inputs(root):
    root = Path(root)
    selected = []
    for name in FILES:
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f'Missing or unsafe release input: {path}')
        selected.append(path)
    for name in DIRECTORIES:
        base = root / name
        if base.is_symlink() or not base.is_dir():
            raise RuntimeError(f'Missing or unsafe release directory: {base}')
        for directory, children, filenames in os.walk(base, followlinks=False):
            directory = Path(directory)
            retained = []
            for child in children:
                if child.startswith('.') or child in PRIVATE_DIRECTORIES:
                    continue
                path = directory / child
                if path.is_symlink():
                    raise RuntimeError(f'Symlinked release directory: {path}')
                retained.append(child)
            children[:] = retained
            for filename in filenames:
                path = directory / filename
                if filename.startswith('.') or filename in PRIVATE_FILES or path.suffix.lower() in PRIVATE_SUFFIXES:
                    continue
                if path.is_symlink() or not path.is_file():
                    raise RuntimeError(f'Unsafe release input: {path}')
                selected.append(path)
    return sorted(set(selected))
