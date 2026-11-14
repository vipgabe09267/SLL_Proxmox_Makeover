#!/usr/bin/python3
"""In-memory test authenticator for the native HTTP integration harness.

Signs real ES256 WebAuthn proofs. Fixture private keys never leave this process.
"""
import json
import sys
from test_passkeys import Authenticator

device = Authenticator()
for line in sys.stdin:
    identifier = None
    try:
        if len(line) > 65536:
            raise ValueError('oversized fixture input')
        request = json.loads(line)
        identifier = request.get('id')
        operation = request['op']
        if operation == 'register':
            response = device.register(request['begin'], **request.get('params', {}))
        elif operation == 'assert':
            response = device.assert_(request['begin'], **request.get('params', {}))
        else:
            raise ValueError('unsupported fixture operation')
        result = {'id': identifier, 'response': response}
    except Exception:
        result = {'id': identifier, 'error': 'Invalid authenticator fixture request.'}
    print(json.dumps(result, separators=(',', ':')), flush=True)
