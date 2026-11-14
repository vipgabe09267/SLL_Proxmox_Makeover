#!/usr/bin/python3
"""Private in-process verifier fixture for virtual-authenticator browser tests.

The production CLI has no state-path override. This test imports its classes
and uses an ephemeral repository-local store, never the installed state path.
"""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sll_passkeys_fixture', SOURCE / 'scripts/passkeys.py')
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
RP = {'id': 'pve.example.test', 'name': 'Example PVE', 'origin': 'https://pve.example.test'}

with tempfile.TemporaryDirectory(prefix='.passkeys-browser-', dir=SOURCE) as directory:
    app = core.Passkeys(core.Store(Path(directory) / 'state'))
    for line in sys.stdin:
        identifier = None
        try:
            if len(line) > core.MAX_INPUT:
                raise ValueError('oversized request')
            payload = core.decode_json(line)
            identifier = payload['id']
            request = payload['request']
            if request.get('rp', RP) != RP:
                raise ValueError('invalid test RP')
            request['rp'] = RP
            if request.get('op') in ('list', 'delete', 'register_begin', 'register_finish'):
                request.setdefault('binding', 'a' * 64)  # fictional server account generation
            result = {'id': identifier, 'data': app.dispatch(request)}
        except Exception:
            result = {'id': identifier, 'error': 'Passkey request failed.'}
        print(json.dumps(result, separators=(',', ':')), flush=True)
