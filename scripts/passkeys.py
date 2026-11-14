#!/usr/bin/python3
"""Root-only WebAuthn verifier. Native Perl code owns identity policy/tickets.

One bounded JSON request on stdin, one JSON result on stdout. No shell, network,
passwords, native tickets, private authenticator keys, or environment overrides.
Cryptographic WebAuthn verification is delegated to Debian's python3-fido2.
"""
import contextlib
import fcntl
import hashlib
import hmac
import importlib.metadata
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
import time
from urllib.parse import urlsplit

import fido2.features
from fido2.server import Fido2Server
from fido2.rpid import verify_rp_id
from fido2.utils import websafe_encode, websafe_decode
from fido2.webauthn import (AttestedCredentialData, AuthenticationResponse,
                            RegistrationResponse)

# Debian 1.2 explicitly opts into the same JSON API that became standard in 2.x.
if hasattr(fido2.features, 'webauthn_json_mapping'):
    fido2.features.webauthn_json_mapping.enabled = True

ROOT = Path('/var/lib/proxmox-makeover/passkeys')
MAX_INPUT = 65536
MAX_STATE = 8 * 1024 * 1024
TTL = 120
MAX_CEREMONIES = 256
MAX_KEYS = 10
USER_RE = re.compile(r'[^@!\s\x00-\x1f\x7f]{1,64}@(pam|pve)\Z')
ID_RE = re.compile(r'[0-9a-f]{32}\Z')
KEY_RE = re.compile(r'[0-9a-f]{64}\Z')


class Rejected(ValueError):
    """Fail closed without disclosing account/credential existence."""


def require(condition):
    if not condition:
        raise Rejected('Passkey request failed.')


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode_json(data):
    return json.loads(data, object_pairs_hook=unique_pairs,
                      parse_constant=lambda _value: (_ for _ in ()).throw(Rejected()))


def binary(value, maximum=4096):
    require(isinstance(value, str) and 1 <= len(value) <= maximum * 2)
    require(re.fullmatch(r'[A-Za-z0-9_-]+', value) is not None)
    result = websafe_decode(value)
    require(len(result) <= maximum and websafe_encode(result) == value)
    return result


def validate_rp(rp):
    require(isinstance(rp, dict) and set(rp) == {'id', 'name', 'origin'})
    require(all(isinstance(v, str) for v in rp.values()))
    host = rp['id']
    require(1 <= len(host) <= 253 and host == host.lower() and
            re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
                         r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', host) is not None)
    origin = urlsplit(rp['origin'])
    require(origin.scheme == 'https' and isinstance(origin.hostname, str) and
            not origin.username and not origin.password and
            not origin.path and not origin.query and not origin.fragment)
    require(verify_rp_id(host, rp['origin']))
    # Require an exact origin string, including a nondefault port if configured.
    require(origin.netloc == origin.hostname + (':' + str(origin.port) if origin.port else ''))
    require(1 <= len(rp['name']) <= 128 and not any(ord(c) < 32 for c in rp['name']))
    return dict(rp)


def validate_user(user):
    require(isinstance(user, str) and USER_RE.fullmatch(user) is not None)
    return user


def same_rp(left, right):
    # Renaming the display brand must not revoke an otherwise unchanged RP.
    return all(left[key] == right[key] for key in ('id', 'origin'))


def trusted_directory(path):
    """Reject symlinks/nonroot ownership through every existing parent."""
    for item in [*reversed(path.parents), path]:
        try:
            info = item.lstat()
        except FileNotFoundError:
            item.mkdir(mode=0o700)
            info = item.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid()))
        require(not info.st_mode & 0o022)
    require(not path.stat().st_mode & 0o077)


def trusted_open(path, flags, mode=0o600):
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1 and not info.st_mode & 0o077)
        return fd
    except BaseException:
        os.close(fd)
        raise


class Store:
    def __init__(self, root=ROOT):
        self.root = Path(root)

    @contextlib.contextmanager
    def locked(self):
        trusted_directory(self.root)
        fd = trusted_open(self.root / 'lock', os.O_RDWR | os.O_CREAT)
        with os.fdopen(fd, 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            path = self.root / 'state.json'
            try:
                datafd = trusted_open(path, os.O_RDONLY)
            except FileNotFoundError:
                state = {'schema': 1, 'users': {}, 'credentials': {},
                         'ceremonies': {}, 'rates': {}}
            else:
                with os.fdopen(datafd, 'rb') as stream:
                    raw = stream.read(MAX_STATE + 1)
                    require(len(raw) <= MAX_STATE)
                    state = decode_json(raw)
            require(isinstance(state, dict) and state.get('schema') == 1)
            require(all(isinstance(state.get(k), dict) for k in
                        ('users', 'credentials', 'ceremonies', 'rates')))
            before = json.dumps(state, separators=(',', ':'), allow_nan=False)
            try:
                yield state
            finally:
                # Consume failed proofs and rate budgets too. Failure to persist
                # raises before any successful authentication reaches Perl.
                encoded = json.dumps(state, separators=(',', ':'), allow_nan=False)
                # Invalid/made-up IDs and exhausted rate budgets must not
                # force an fsync/rename of an unchanged credential database.
                if encoded != before or not path.exists():
                    raw = (encoded + '\n').encode()
                    require(len(raw) <= MAX_STATE)
                    tempfd, temporary = tempfile.mkstemp(prefix='.state-', dir=self.root)
                    try:
                        with os.fdopen(tempfd, 'wb') as stream:
                            os.fchmod(stream.fileno(), 0o600)
                            stream.write(raw)
                            stream.flush()
                            os.fsync(stream.fileno())
                        os.replace(temporary, path)
                        dirfd = os.open(self.root, os.O_DIRECTORY | os.O_NOFOLLOW)
                        try:
                            os.fsync(dirfd)
                        finally:
                            os.close(dirfd)
                    finally:
                        if os.path.exists(temporary):
                            os.unlink(temporary)


def metadata(entry):
    return {key: entry[key] for key in ('id', 'description', 'created', 'last_used')}


def validate_public_key(key):
    # The library owns key decoding/signature verification; bound the accepted
    # algorithm parameters too (especially undersized RSA moduli).
    algorithm = key.get(3)
    require(algorithm in (-7, -8, -257))
    if algorithm == -7:
        require(key.get(1) == 2 and key.get(-1) == 1 and
                isinstance(key.get(-2), bytes) and len(key[-2]) == 32 and
                isinstance(key.get(-3), bytes) and len(key[-3]) == 32)
    elif algorithm == -8:
        require(key.get(1) == 1 and key.get(-1) == 6 and
                isinstance(key.get(-2), bytes) and len(key[-2]) == 32)
    else:
        modulus, exponent = key.get(-1), key.get(-2)
        require(key.get(1) == 3 and isinstance(modulus, bytes) and
                256 <= len(modulus) <= 512 and int.from_bytes(modulus).bit_length() >= 2048 and
                isinstance(exponent, bytes) and 1 <= len(exponent) <= 4 and
                int.from_bytes(exponent) >= 3 and int.from_bytes(exponent) % 2 == 1)


class Passkeys:
    def __init__(self, store=None, now=time.time):
        self.store = store or Store()
        self.now = now

    def dispatch(self, request):
        require(isinstance(request, dict))
        version = importlib.metadata.version('fido2').split('.')
        require((1, 2) <= tuple(int(v) for v in version[:2]) < (3, 0))
        op = request.get('op')
        require(op in ('status', 'list', 'register_begin', 'register_finish',
                       'login_begin', 'login_finish', 'delete'))
        rp = validate_rp(request.get('rp'))
        if op == 'status':
            return {'supported': True}
        user = validate_user(request.get('user')) if op not in ('login_begin', 'login_finish') else None
        binding = request.get('binding')
        if op in ('list', 'delete', 'register_begin', 'register_finish'):
            require(isinstance(binding, str) and KEY_RE.fullmatch(binding) is not None)
        now = int(self.now())
        server = Fido2Server({'id': rp['id'], 'name': rp['name']},
                             attestation='none', verify_origin=lambda value: value == rp['origin'])
        server.allowed_algorithms = [item for item in server.allowed_algorithms
                                     if item.alg in (-7, -8, -257)]
        server.timeout = TTL * 1000
        with self.store.locked() as state:
            # Short lifetimes and bounded state prevent unbounded anonymous disk use.
            state['ceremonies'] = {k: v for k, v in state['ceremonies'].items()
                                  if v['expires'] > now}
            state['rates'] = {k: v for k, v in state['rates'].items() if v['until'] > now}
            own = [v for v in state['credentials'].values()
                   if v['user'] == user and v.get('binding') == binding]
            if op == 'list':
                return {'credentials': [metadata(v) for v in own]}
            if op == 'delete':
                key = request.get('id')
                require(isinstance(key, str) and KEY_RE.fullmatch(key))
                entry = state['credentials'].get(key)
                require(entry is not None and entry['user'] == user and entry.get('binding') == binding)
                del state['credentials'][key]
                return {'removed': True}
            if op == 'login_finish':
                self.rate(state, request.get('client', ''), op, now)
            if op in ('login_begin', 'register_begin'):
                self.rate(state, request.get('client', ''), op, now)
                require(len(state['ceremonies']) < MAX_CEREMONIES)
                ceremony = secrets.token_hex(16)
                pending = {'op': op, 'rp': rp, 'expires': now + TTL}
                if op == 'register_begin':
                    # A fresh native-password proof establishes the current
                    # account generation. Rotate the opaque user handle and
                    # remove obsolete credentials after a password reset/reuse.
                    account = state['users'].get(user)
                    if not isinstance(account, dict) or account.get('binding') != binding:
                        for key in [k for k, v in state['credentials'].items() if v['user'] == user]:
                            del state['credentials'][key]
                        state['users'][user] = {'handle': websafe_encode(secrets.token_bytes(32)), 'binding': binding}
                        own = []
                    require(len(own) < MAX_KEYS)
                    description = request.get('description')
                    require(isinstance(description, str) and 1 <= len(description.strip()) <= 64
                            and not any(ord(c) < 32 or ord(c) == 127 for c in description))
                    handle = state['users'][user]['handle']
                    credentials = [AttestedCredentialData(binary(v['credential_data'])) for v in own
                                   if same_rp(v['rp'], rp)]
                    options, internal = server.register_begin(
                        {'id': handle, 'name': user, 'displayName': user}, credentials,
                        resident_key_requirement='required', user_verification='required')
                    pending.update(user=user, handle=handle, binding=binding, description=description.strip())
                else:
                    options, internal = server.authenticate_begin(user_verification='required')
                    pending['nonce'] = websafe_encode(secrets.token_bytes(32))
                pending['state'] = internal
                state['ceremonies'][ceremony] = pending
                result = {'ceremony': ceremony, 'publicKey': dict(options)['publicKey']}
                if op == 'login_begin':
                    result['nonce'] = pending['nonce']
                return result
            ceremony = request.get('ceremony')
            require(isinstance(ceremony, str) and ID_RE.fullmatch(ceremony))
            # Pop first: a bad assertion cannot be retried using the same state.
            pending = state['ceremonies'].pop(ceremony, None)
            require(pending is not None and same_rp(pending['rp'], rp) and
                    pending['op'] == op.replace('_finish', '_begin'))
            response = request.get('response')
            require(isinstance(response, dict) and response.get('type') == 'public-key')
            raw_id = binary(response.get('rawId'), 1024)
            require(response.get('id') == websafe_encode(raw_id))
            client_data = decode_json(binary(response.get('response', {}).get('clientDataJSON'), 8192))
            # The library verifies origin/type/challenge; additionally disallow
            # framed ceremonies and ambiguous/unknown crossOrigin values.
            require(isinstance(client_data, dict) and
                    (client_data.get('crossOrigin', False) is False) and 'topOrigin' not in client_data)
            key = hashlib.sha256(raw_id).hexdigest()
            if op == 'register_finish':
                require(pending['user'] == user and len(own) < MAX_KEYS and
                        hmac.compare_digest(pending['binding'], binding) and
                        state['users'][user]['binding'] == binding)
                require(key not in state['credentials'])
                registration = RegistrationResponse.from_dict(response)
                auth = server.register_complete(pending['state'], registration)
                require(auth.credential_data is not None and
                        auth.credential_data.credential_id == raw_id)
                validate_public_key(auth.credential_data.public_key)
                require(not auth.is_backed_up() or auth.is_backup_eligible())
                # discoverable registration is requested, and requireResidentKey
                # is true. An authenticator's unsigned credProps is advisory;
                # real userHandle is mandatory when proving primary login.
                entry = {'id': key, 'user': user, 'handle': pending['handle'], 'binding': binding, 'rp': rp,
                         'credential_data': websafe_encode(bytes(auth.credential_data)),
                         'backup_eligible': auth.is_backup_eligible(), 'counter': auth.counter,
                         'description': pending['description'], 'created': now, 'last_used': 0}
                state['credentials'][key] = entry
                return metadata(entry)
            nonce = request.get('nonce')
            require(isinstance(nonce, str) and hmac.compare_digest(nonce, pending['nonce']))
            entry = state['credentials'].get(key)
            require(entry is not None and same_rp(entry['rp'], rp))
            authentication = AuthenticationResponse.from_dict(response)
            handle = authentication.response.user_handle
            require(handle is not None and hmac.compare_digest(handle, binary(entry['handle'])))
            auth = authentication.response.authenticator_data
            require(auth.is_backup_eligible() == entry['backup_eligible'])
            require(not auth.is_backed_up() or auth.is_backup_eligible())
            server.authenticate_complete(pending['state'],
                [AttestedCredentialData(binary(entry['credential_data']))], authentication)
            # Zero counters are permitted for authenticators/synced passkeys
            # without counters. Once nonzero, a rollback or repeated value fails.
            require(not (entry['counter'] or auth.counter) or auth.counter > entry['counter'])
            entry['counter'] = auth.counter
            entry['last_used'] = now
            require(isinstance(entry.get('binding'), str) and KEY_RE.fullmatch(entry['binding']))
            return {'user': entry['user'], 'binding': entry['binding']}

    @staticmethod
    def rate(state, client, op, now):
        require(isinstance(client, str) and len(client) <= 255)
        budgets = []
        for tag, limit in [('global', 120), ('client:' + client, 20)]:
            key = hashlib.sha256((op + ':' + tag).encode()).hexdigest()
            budget = state['rates'].setdefault(key, {'until': now + 60, 'count': 0})
            require(budget['count'] < limit)
            budgets.append(budget)
        for budget in budgets:
            budget['count'] += 1


def main():
    try:
        require(os.geteuid() == 0)
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        require(0 < len(raw) <= MAX_INPUT)
        result = Passkeys().dispatch(decode_json(raw))
        sys.stdout.write(json.dumps(result, separators=(',', ':'), allow_nan=False) + '\n')
        return 0
    except Exception:
        # No attacker-controlled/native/credential values in logs or diagnostics.
        sys.stdout.write('{"error":"Passkey request failed."}\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
