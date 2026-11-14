#!/usr/bin/env python3
"""Build an allowlisted source release; never include host state or dev evidence."""
import gzip
import hashlib
import io
import importlib.util
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('_makeover_release_inputs', ROOT / 'scripts/release_inputs.py')
release_inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_inputs)
selected = release_inputs.selected_inputs(ROOT)
version = (ROOT / 'VERSION').read_text().strip()
output = ROOT / 'dist' / f'proxmox-makeover-{version}.tar.gz'
output.parent.mkdir(exist_ok=True)
with output.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as gz:
    with tarfile.open(fileobj=gz, mode='w') as archive:
        for path in sorted(set(selected)):
            data = path.read_bytes()
            info = tarfile.TarInfo('proxmox-makeover/' + str(path.relative_to(ROOT)))
            info.size = len(data)
            info.mode = 0o755 if path.name in ('install.sh', 'bootstrap.sh', 'proxmox-makeover', 'sls-proxmox-branding', 'sll-pveproxy', 'sll-pvedaemon') or path == Path(__file__) else 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = 'root'
            archive.addfile(info, io.BytesIO(data))
checksum = hashlib.sha256(output.read_bytes()).hexdigest()
(output.parent / 'SHA256SUMS').write_text(f'{checksum}  {output.name}\n')
print(f'{output}\n{checksum} ({len(set(selected))} files)')
