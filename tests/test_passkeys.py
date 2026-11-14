"""Real WebAuthn signatures and filesystem/concurrency failure cases.

No PVE services, real users, production auth keys or physical device are used.
The fake authenticator here signs actual WebAuthn bytes with cryptography.
"""
import concurrent.futures
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import secrets
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding
from fido2 import cbor
from fido2.cose import ES256, EdDSA, RS256
from fido2.webauthn import AttestedCredentialData, AuthenticatorData, Aaguid

SOURCE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('sll_passkeys', SOURCE / 'scripts/passkeys.py')
keys = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(keys)
RP = {'id': 'pve.example.test', 'name': 'Example PVE', 'origin': 'https://pve.example.test'}
BINDING = 'a' * 64
LOGIN = {'user': 'alice@pve', 'binding': BINDING}


class Authenticator:
    def __init__(self, algorithm=-7):
        self.algorithm = algorithm
        self.private = (ec.generate_private_key(ec.SECP256R1()) if algorithm == -7 else
                        ed25519.Ed25519PrivateKey.generate() if algorithm == -8 else
                        rsa.generate_private_key(65537, 2048))
        self.credential_id = secrets.token_bytes(32)
        self.counter = 0

    def register(self, begin, uv=True, up=True, origin=None, rp_id=None, cross=False, flags=0):
        self.handle = begin['publicKey']['user']['id']
        data = {'type': 'webauthn.create', 'challenge': begin['publicKey']['challenge'],
                'origin': origin or RP['origin'], 'crossOrigin': cross}
        client = json.dumps(data, separators=(',', ':')).encode()
        key_class = {-7: ES256, -8: EdDSA, -257: RS256}[self.algorithm]
        credential = AttestedCredentialData.create(Aaguid.NONE, self.credential_id,
                                                   key_class.from_cryptography_key(self.private.public_key()))
        auth = AuthenticatorData.create(hashlib.sha256((rp_id or RP['id']).encode()).digest(),
                 0x40 | (1 if up else 0) | (4 if uv else 0) | flags, self.counter, credential)
        attestation = cbor.encode({'fmt': 'none', 'authData': bytes(auth), 'attStmt': {}})
        return {'id': keys.websafe_encode(self.credential_id), 'rawId': keys.websafe_encode(self.credential_id),
                'type': 'public-key', 'response': {'clientDataJSON': keys.websafe_encode(client),
                                                 'attestationObject': keys.websafe_encode(attestation)}}

    def assert_(self, begin, *, uv=True, up=True, origin=None, rp_id=None, cross=False,
                handle=None, counter=None, flags=0, challenge=None, top_origin=None):
        if counter is None:
            self.counter += 1
        else:
            self.counter = counter
        data = {'type': 'webauthn.get', 'challenge': challenge or begin['publicKey']['challenge'],
                'origin': origin or RP['origin'], 'crossOrigin': cross}
        if top_origin:
            data['topOrigin'] = top_origin
        client = json.dumps(data, separators=(',', ':')).encode()
        auth = AuthenticatorData.create(hashlib.sha256((rp_id or RP['id']).encode()).digest(),
                 (1 if up else 0) | (4 if uv else 0) | flags, self.counter)
        signed = bytes(auth) + hashlib.sha256(client).digest()
        signature = (self.private.sign(signed, ec.ECDSA(hashes.SHA256())) if self.algorithm == -7 else
                     self.private.sign(signed) if self.algorithm == -8 else
                     self.private.sign(signed, padding.PKCS1v15(), hashes.SHA256()))
        return {'id': keys.websafe_encode(self.credential_id), 'rawId': keys.websafe_encode(self.credential_id),
                'type': 'public-key', 'response': {'clientDataJSON': keys.websafe_encode(client),
                   'authenticatorData': keys.websafe_encode(bytes(auth)), 'signature': keys.websafe_encode(signature),
                   'userHandle': self.handle if handle is None else handle}}


class PasskeysTest(unittest.TestCase):
    def setUp(self):
        # Use this uid's private home: CI may run root tests from a checkout
        # owned by the runner, which the production trust policy rightly denies.
        fixture_parent = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        self.temp = tempfile.TemporaryDirectory(prefix='.passkeys-test-', dir=fixture_parent)
        self.path = Path(self.temp.name) / 'keys'
        self.clock = 1000000
        self.app = keys.Passkeys(keys.Store(self.path), now=lambda: self.clock)
        self.auth = Authenticator()

    def tearDown(self):
        self.temp.cleanup()

    def call(self, op, **kwargs):
        if op in ('list', 'delete', 'register_begin', 'register_finish'):
            kwargs.setdefault('binding', BINDING)
        return self.app.dispatch({'op': op, 'rp': RP, 'client': '127.0.0.1', **kwargs})

    def enroll(self, auth=None, **kwargs):
        auth = auth or self.auth
        begin = self.call('register_begin', user='alice@pve', description='My device')
        return self.call('register_finish', user='alice@pve', ceremony=begin['ceremony'],
                         response=auth.register(begin, **kwargs))

    def login(self, **kwargs):
        begin = self.call('login_begin')
        return self.call('login_finish', ceremony=begin['ceremony'], nonce=begin['nonce'],
                         response=self.auth.assert_(begin, **kwargs))

    def test_complete_signed_primary_login_and_metadata(self):
        entry = self.enroll()
        self.assertEqual(set(entry), {'id', 'description', 'created', 'last_used'})
        self.assertEqual(self.login(), LOGIN)
        listing = self.call('list', user='alice@pve')['credentials']
        self.assertEqual(listing[0]['last_used'], self.clock)
        self.assertEqual(self.call('list', user='bob@pve'), {'credentials': []})
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(self.path / 'state.json').st_mode & 0o777, 0o600)
        self.assertNotIn('PRIVATE', (self.path / 'state.json').read_text())

    def test_real_ed25519_and_rsa_registration_and_login(self):
        for algorithm in (-8, -257):
            with self.subTest(algorithm=algorithm):
                self.auth = Authenticator(algorithm)
                self.enroll()
                self.assertEqual(self.login(), LOGIN)

    def test_creation_requires_uv_up_and_exact_origin_rp(self):
        for mutation in ({'uv': False}, {'up': False}, {'origin': 'https://other.example.test'},
                         {'origin': 'https://sub.pve.example.test'}, {'rp_id': 'other.example.test'},
                         {'cross': True}, {'flags': 0x10}):
            with self.subTest(mutation=mutation), self.assertRaises((ValueError, KeyError)):
                self.enroll(**mutation)

    def test_assertion_rejects_uv_up_origin_rp_challenge_handle_and_frames(self):
        self.enroll()
        for mutation in ({'uv': False}, {'up': False}, {'origin': 'https://other.example.test'},
                         {'origin': 'https://sub.pve.example.test'}, {'rp_id': 'other.example.test'},
                         {'cross': True}, {'handle': keys.websafe_encode(b'wrong')},
                         {'challenge': keys.websafe_encode(b'not the issued challenge')},
                         {'top_origin': RP['origin']}, {'flags': 0x08}, {'flags': 0x10}):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.login(**mutation)

    def test_bad_signature_and_unknown_credential(self):
        self.enroll()
        for alteration in ('signature', 'credential'):
            begin = self.call('login_begin')
            response = self.auth.assert_(begin)
            if alteration == 'signature':
                response['response']['signature'] = keys.websafe_encode(b'fake signature')
            else:
                response['rawId'] = response['id'] = keys.websafe_encode(b'unknown credential')
            with self.assertRaises(ValueError):
                self.call('login_finish', ceremony=begin['ceremony'], nonce=begin['nonce'], response=response)

    def test_replay_nonce_and_failed_proof_consume_challenge(self):
        self.enroll()
        begin = self.call('login_begin')
        args = {'ceremony': begin['ceremony'], 'nonce': begin['nonce'], 'response': self.auth.assert_(begin)}
        self.assertEqual(self.call('login_finish', **args), LOGIN)
        with self.assertRaises(ValueError):
            self.call('login_finish', **args)
        begin = self.call('login_begin')
        args = {'ceremony': begin['ceremony'], 'nonce': begin['nonce'], 'response': self.auth.assert_(begin)}
        with self.assertRaises(ValueError):
            self.call('login_finish', **{**args, 'nonce': 'wrong'})
        with self.assertRaises(ValueError):
            self.call('login_finish', **args)

    def test_counter_regression_and_zero_counter_devices(self):
        self.enroll()
        self.assertEqual(self.login(counter=0), LOGIN)
        self.assertEqual(self.login(counter=0), LOGIN)
        self.assertEqual(self.login(counter=7), LOGIN)
        for counter in (7, 6, 0):
            with self.subTest(counter=counter), self.assertRaises(ValueError):
                self.login(counter=counter)

    def test_synchronized_passkey_backup_flags(self):
        self.enroll(flags=0x08)
        self.assertEqual(self.login(flags=0x18, counter=0), LOGIN)
        self.assertEqual(self.login(flags=0x08, counter=0), LOGIN)
        with self.assertRaises(ValueError):
            self.login(flags=0, counter=0)

    def test_expiry_rp_config_change_and_registration_account_binding(self):
        begin = self.call('register_begin', user='alice@pve', description='My device')
        response = self.auth.register(begin)
        with self.assertRaises(ValueError):
            self.call('register_finish', user='bob@pve', ceremony=begin['ceremony'], response=response)
        self.enroll()
        begin = self.call('login_begin')
        response = self.auth.assert_(begin)
        self.clock += keys.TTL
        with self.assertRaises(ValueError):
            self.call('login_finish', ceremony=begin['ceremony'], nonce=begin['nonce'], response=response)
        begin = self.call('login_begin')
        response = self.auth.assert_(begin)
        with self.assertRaises(ValueError):
            self.app.dispatch({'op': 'login_finish', 'rp': {**RP, 'origin': RP['origin'] + ':8006'},
                'ceremony': begin['ceremony'], 'nonce': begin['nonce'], 'response': response})

    def test_rp_display_name_can_follow_branding_without_revoking_key(self):
        self.enroll()
        begin = self.call('login_begin')
        response = self.auth.assert_(begin)
        result = self.app.dispatch({'op': 'login_finish', 'rp': {**RP, 'name': 'New brand'},
            'ceremony': begin['ceremony'], 'nonce': begin['nonce'], 'response': response})
        self.assertEqual(result, LOGIN)

    def test_account_generation_is_bound_and_reenrollment_rotates_handle_and_revokes_old_keys(self):
        entry = self.enroll()
        self.assertEqual(self.login()['binding'], BINDING)
        old = self.auth
        old_handle = old.handle
        generation = 'b' * 64
        self.assertEqual(self.call('list', user='alice@pve', binding=generation), {'credentials': []})
        with self.assertRaises(ValueError):
            self.call('delete', user='alice@pve', id=entry['id'], binding=generation)
        begin = self.call('register_begin', user='alice@pve', description='New account device', binding=generation)
        replacement = Authenticator()
        response = replacement.register(begin)
        self.assertNotEqual(replacement.handle, old_handle)
        with self.assertRaises(ValueError):
            self.login()
        self.call('register_finish', user='alice@pve', ceremony=begin['ceremony'], response=response, binding=generation)
        self.auth = replacement
        self.assertEqual(self.login(), {'user': 'alice@pve', 'binding': generation})

    def test_password_record_change_during_registration_cannot_finish(self):
        begin = self.call('register_begin', user='alice@pve', description='Device')
        response = self.auth.register(begin)
        with self.assertRaises(ValueError):
            self.call('register_finish', user='alice@pve', ceremony=begin['ceremony'],
                      response=response, binding='b' * 64)
        self.assertEqual(self.call('list', user='alice@pve'), {'credentials': []})

    def test_parent_rp_matches_native_configuration_but_not_public_suffix(self):
        keys.validate_rp({**RP, 'id': 'example.test'})
        with self.assertRaises(ValueError):
            keys.validate_rp({'id': 'co.uk', 'name': 'Example', 'origin': 'https://pve.co.uk'})

    def test_delete_is_current_user_only_and_revokes_login(self):
        entry = self.enroll()
        with self.assertRaises(ValueError):
            self.call('delete', user='bob@pve', id=entry['id'])
        self.call('delete', user='alice@pve', id=entry['id'])
        self.assertEqual(self.call('list', user='alice@pve'), {'credentials': []})
        with self.assertRaises(ValueError):
            self.login()

    def test_limits_and_unsupported_realms(self):
        for user in ('alice@ldap', 'alice@openid', 'alice@pam!token', 'alice\n@pve'):
            with self.subTest(user=user), self.assertRaises(ValueError):
                self.call('register_begin', user=user, description='Key')
        for _ in range(20):
            self.call('login_begin')
        with self.assertRaises(ValueError):
            self.call('login_begin')
        self.clock += 60
        self.call('login_begin')

    def test_fabricated_finish_requests_are_rate_bounded_without_rewriting_unchanged_state(self):
        for _ in range(20):
            with self.assertRaises(ValueError):
                self.call('login_finish', ceremony='0'*32, nonce='x'*43, response={})
        with patch.object(keys.os, 'replace', side_effect=AssertionError('unchanged state was rewritten')):
            with self.assertRaises(ValueError):
                self.call('login_finish', ceremony='0'*32, nonce='x'*43, response={})
        # A rejected client cannot consume somebody else's remaining budget.
        begin = self.app.dispatch({'op': 'login_begin', 'rp': RP, 'client': 'other-client'})
        self.assertIn('ceremony', begin)
        with patch.object(keys.os, 'replace', side_effect=AssertionError('read-only list rewrote state')):
            self.call('list', user='alice@pve')

    def test_ten_keys_and_duplicate_credential_rejected(self):
        self.enroll()
        with self.assertRaises(ValueError):
            self.enroll()
        for _ in range(9):
            self.enroll(Authenticator())
        with self.assertRaises(ValueError):
            self.call('register_begin', user='alice@pve', description='Too many')

    def test_concurrent_replay_has_exactly_one_success(self):
        self.enroll()
        begin = self.call('login_begin')
        args = {'ceremony': begin['ceremony'], 'nonce': begin['nonce'], 'response': self.auth.assert_(begin)}
        def attempt(_number):
            try:
                return self.call('login_finish', **args) == LOGIN
            except ValueError:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            self.assertEqual(sum(executor.map(attempt, range(2))), 1)

    def test_symlink_permissive_state_and_corrupt_state_fail_closed(self):
        self.call('list', user='alice@pve')
        state = self.path / 'state.json'
        state.chmod(0o644)
        with self.assertRaises(ValueError):
            self.call('login_begin')
        state.chmod(0o600)
        state.write_text('{}')
        with self.assertRaises(ValueError):
            self.call('login_begin')
        state.unlink()
        state.symlink_to(self.path / 'other')
        with self.assertRaises(OSError):
            self.call('login_begin')

    def test_strict_json_and_origin_configuration(self):
        for value in ('{"op":1,"op":2}', '{"x":NaN}'):
            with self.assertRaises(ValueError):
                keys.decode_json(value)
        for rp in ({**RP, 'origin': 'http://pve.example.test'}, {**RP, 'origin': RP['origin'] + '/'},
                   {**RP, 'origin': 'https://user@pve.example.test'}, {**RP, 'id': 'com'},
                   {**RP, 'origin': 'https://other.example.test'}):
            with self.subTest(rp=rp), self.assertRaises(ValueError):
                self.app.dispatch({'op': 'status', 'rp': rp})

    def test_public_key_algorithm_and_strength_policy(self):
        keys.validate_public_key(ES256.from_cryptography_key(self.auth.private.public_key()))
        keys.validate_public_key(EdDSA.from_cryptography_key(ed25519.Ed25519PrivateKey.generate().public_key()))
        keys.validate_public_key(RS256.from_cryptography_key(rsa.generate_private_key(65537, 2048).public_key()))
        with self.assertRaises(ValueError):
            keys.validate_public_key(RS256.from_cryptography_key(rsa.generate_private_key(65537, 1024).public_key()))
        with self.assertRaises(ValueError):
            keys.validate_public_key({1: 2, 3: -7, -1: 2, -2: b'x'*32, -3: b'y'*32})


if __name__ == '__main__':
    unittest.main()
