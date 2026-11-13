# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""SSO-1: the single sign-on commands oidc-set, oidc-start, oidc-finish and tenant-oidc-set as a whole, against a test
provider in memory. The provider has a real RSA key of 2048 bits and signs real RS256 ID tokens; it answers the discovery
document, the token request and the key set the way Keycloak and Entra ID do, and it checks PKCE like they do. Only the HTTPS
transport (_oidc_json) and the database are replaced. A live test against a real Keycloak is in docs (portal, freshtest2)."""

import base64
import hashlib
import json
import os
import sys
import time
import unittest
import urllib.parse
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_write_commands as writes  # noqa: E402  the same loader and the same temporary root

efactl, EfaError = writes.efactl, writes.EfaError

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ImportError:  # pragma: no cover
    rsa = None

ISSUER = 'https://idp.example.org/realms/efa'
UNSIGNED_HEAD = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b'=').decode()


class Base(unittest.TestCase):
    """The harness of the write tests, without their tests."""


for _name in ('setUp', 'tearDown', 'query', 'run_cmd', 'refused', 'read'):
    setattr(Base, _name, writes.WriteCommandTests.__dict__[_name])


def _tenant_id(name):
    if name != 'acme':
        raise EfaError('No such tenant.')
    return 7


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


class TestProvider:
    """An OIDC provider: discovery, token endpoint with PKCE, key set."""

    def __init__(self, issuer=ISSUER):
        self.issuer, self.key = issuer, rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.codes, self.requests, self.claims, self.discovery_issuer = {}, [], {}, issuer

    def authorize(self, url, **claims):
        """What the browser does: the provider logs the user in and sends a code back to the redirect address."""
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
        code = 'code-' + str(len(self.codes))
        self.codes[code] = {'query': query, 'claims': {'iss': self.issuer, 'aud': query['client_id'], 'exp': int(time.time()) + 300,
                                                       'iat': int(time.time()), 'nonce': query['nonce'], 'sub': 'sub-anna', **claims}}
        return code, query

    def token(self, claims, header=None):
        head = _b64(json.dumps(header or {'alg': 'RS256', 'kid': 'k1', 'typ': 'JWT'}).encode())
        body = _b64(json.dumps(claims).encode())
        signature = self.key.sign(f'{head}.{body}'.encode(), padding.PKCS1v15(), hashes.SHA256())
        return f'{head}.{body}.{_b64(signature)}'

    def __call__(self, url, data=None):
        self.requests.append((url, data))
        assert url.startswith('https://')
        if url == self.issuer + '/.well-known/openid-configuration':
            return {'issuer': self.discovery_issuer, 'authorization_endpoint': self.issuer + '/auth',
                    'token_endpoint': self.issuer + '/token', 'jwks_uri': self.issuer + '/certs'}
        if url == self.issuer + '/certs':
            numbers = self.key.public_key().public_numbers()
            return {'keys': [{'kty': 'RSA', 'kid': 'k1', 'alg': 'RS256', 'use': 'sig', 'n': _b64(numbers.n.to_bytes(256, 'big')),
                              'e': _b64(numbers.e.to_bytes(3, 'big'))}]}
        if url == self.issuer + '/token':
            found = self.codes.pop(data['code'], None)
            if not found or data['grant_type'] != 'authorization_code' or data['redirect_uri'] != found['query']['redirect_uri']:
                raise EfaError('OIDC: the provider answered 400.')
            challenge = _b64(hashlib.sha256(data['code_verifier'].encode()).digest())
            if challenge != found['query']['code_challenge'] or found['query']['code_challenge_method'] != 'S256':
                raise EfaError('OIDC: the provider answered 400.')
            if data['client_secret'] != 'top-secret':
                raise EfaError('OIDC: the provider answered 401.')
            return {'access_token': 'x', 'token_type': 'Bearer', 'id_token': self.token(found['claims'])}
        raise EfaError('OIDC: the provider answered 404.')


@unittest.skipIf(rsa is None, 'python3-cryptography is missing')
class OidcFlowTests(Base):
    def setUp(self):
        super().setUp()
        self.idp = TestProvider()
        self.logins = []
        self.tenant_domains = {'tenant.example': 7}
        self.secret = ['top-secret']
        extra = [mock.patch.object(efactl, '_oidc_json', self.idp),
                 mock.patch.object(efactl, '_secrets', lambda count, prompt: list(self.secret)),
                 mock.patch.object(efactl, '_tenant_id', _tenant_id),
                 mock.patch.object(efactl, '_tenant_of_domain', lambda domain: self.tenant_domains.get(domain.lower())),
                 mock.patch.object(efactl, '_own_domains', lambda: {'example.org', 'tenant.example'}),
                 mock.patch.object(efactl, '_external_login', self.external_login)]
        for patch in extra:
            patch.start()
        self.patches += extra

    def external_login(self, username, groups, source, tenant=None, external=None):
        self.logins.append((username, groups, source, tenant, external))
        return {'username': username, 'role': 'admin'}

    def switch_on(self, *extra, command=('oidc-set',)):
        return self.run_cmd(*command, '--mode', 'on', '--issuer', ISSUER, '--client_id', 'efa-web',
                            '--redirect_uri', 'https://mx.example.org/login/oidc/callback', *extra)

    def login(self, start_words=(), finish_words=(), **claims):
        started = self.run_cmd('oidc-start', *start_words)
        code, query = self.idp.authorize(started['url'], **claims)
        # As efa-web passes them (--name=value): a random value may start with a hyphen.
        finish = [f'--code={code}', f"--nonce={started['nonce']}", f"--verifier={started['verifier']}"]
        if started['tenant']:
            finish += [f"--tenant={started['tenant']}"]
        return started, query, self.run_cmd('oidc-finish', *finish, *finish_words)

    def test_admin_login_with_pkce(self):
        status = self.switch_on('--group_claim', 'roles')
        self.assertTrue(status['oidc'])
        self.assertNotIn('client_secret', status)
        self.assertEqual(os.stat(efactl.OIDC_FILE).st_mode & 0o777, 0o600)
        started, query, result = self.login(preferred_username='anna', roles=['efa-admins'], email='anna@example.org', email_verified=True)
        self.assertEqual(result, {'username': 'anna', 'role': 'admin'})
        self.assertEqual(self.logins, [('anna', ['efa-admins'], 'oidc', None, ISSUER + '|sub-anna')])
        self.assertTrue(started['url'].startswith(ISSUER + '/auth?'))
        self.assertEqual((query['response_type'], query['scope'], query['code_challenge_method']), ('code', 'openid profile email', 'S256'))
        self.assertEqual(query['redirect_uri'], 'https://mx.example.org/login/oidc/callback')
        self.assertNotIn(started['verifier'], started['url'])
        token_request = [data for url, data in self.idp.requests if url.endswith('/token')][0]
        self.assertEqual(token_request['code_verifier'], started['verifier'])
        # Each login has its own state, nonce and verifier.
        again = self.run_cmd('oidc-start')
        self.assertNotEqual((again['state'], again['nonce'], again['verifier']), (started['state'], started['nonce'], started['verifier']))

    def test_a_group_claim_as_text_counts_as_one_group(self):
        self.switch_on()
        self.login(preferred_username='anna', groups='efa-admins')
        self.assertEqual(self.logins[0][1], ['efa-admins'])

    def test_unchecked_address_is_not_the_name(self):
        self.switch_on()
        self.login(email='chef@example.org', email_verified=False)
        self.assertEqual(self.logins[0][0], 'sub-anna')

    def test_refused_settings(self):
        good = {'--issuer': ISSUER, '--client_id': 'efa-web', '--redirect_uri': 'https://mx.example.org/login/oidc/callback'}
        for key, bad in (('--issuer', 'http://idp.example.org'), ('--issuer', ' '), ('--redirect_uri', 'https://mx.example.org/other'),
                         ('--client_id', ' '), ('--portal_redirect_uri', 'https://mx.example.org/portal/x')):
            with self.subTest(key=key, bad=bad):
                words = {**good, key: bad}
                self.refused('oidc-set', '--mode', 'on', *[item for pair in words.items() for item in pair])
        flat = [item for pair in good.items() for item in pair]
        self.secret[:] = ['']
        self.refused('oidc-set', '--mode', 'on', *flat)
        self.secret[:] = ['top-secret']
        self.idp.discovery_issuer = 'https://evil.example.org'
        self.refused('oidc-set', '--mode', 'on', *flat)
        self.assertFalse(os.path.exists(efactl.OIDC_FILE))

    def test_secret_is_kept_when_left_empty_and_off_forgets_it(self):
        self.switch_on()
        self.secret[:] = ['']
        self.switch_on()
        self.assertEqual(json.loads(self.read('OIDC_FILE'))['client_secret'], 'top-secret')
        self.assertEqual(self.run_cmd('oidc-set', '--mode', 'off'), {'oidc': False})
        self.assertEqual(json.loads(self.read('OIDC_FILE')), {'oidc': False})
        self.refused('oidc-start')

    def test_refused_tokens(self):
        self.switch_on()
        now = int(time.time())
        for claims in ({'aud': 'other-app'}, {'iss': 'https://evil.example.org'}, {'exp': now - 120}, {'nbf': now + 600},
                       {'nonce': 'from-another-browser'}, {'sub': ''}):
            with self.subTest(claims=claims):
                self.assertRaises(EfaError, self.login, **claims)
        self.assertEqual(self.logins, [])

    def test_refused_code_exchange(self):
        self.switch_on()
        started = self.run_cmd('oidc-start')
        code, _query = self.idp.authorize(started['url'])
        # A verifier of another login: the provider refuses (PKCE), the code is used up.
        self.refused('oidc-finish', f'--code={code}', f"--nonce={started['nonce']}", '--verifier=' + 'x' * 64)
        self.refused('oidc-finish', f'--code={code}', f"--nonce={started['nonce']}", f"--verifier={started['verifier']}")

    def test_forged_and_unsigned_tokens(self):
        self.switch_on()
        started = self.run_cmd('oidc-start')
        code, query = self.idp.authorize(started['url'])
        claims = self.idp.codes[code]['claims']
        other = TestProvider()
        head, body, _signature = self.idp.token(claims).split('.')
        for token in (other.token(claims), f'{UNSIGNED_HEAD}.{body}.', self.idp.token(claims, {'alg': 'HS256', 'kid': 'k1'}),
                      f'{head}.{_b64(json.dumps({**claims, "preferred_username": "root"}).encode())}.{_signature}'):
            with self.subTest(token=token[:40]):
                self.idp.codes['forged'] = {'query': query, 'claims': claims}
                with mock.patch.object(self.idp, 'token', lambda _claims, header=None, token=token: token):
                    self.refused('oidc-finish', '--code=forged', f"--nonce={started['nonce']}", f"--verifier={started['verifier']}")
        self.assertEqual(self.logins, [])

    def test_tenant_login(self):
        self.switch_on(command=('tenant-oidc-set', '--tenant', 'acme'))
        with open(efactl.IDP_DIR + '/oidc-7.json') as f:
            self.assertTrue(json.load(f)['oidc'])
        self.assertFalse(os.path.exists(efactl.OIDC_FILE))
        started, _query, _result = self.login(('--domain', 'tenant.example'), email='Bea@tenant.example', email_verified=True, groups=['g'])
        self.assertEqual(started['tenant'], '7')
        self.assertEqual(self.logins, [('bea@tenant.example', ['g'], 'oidc:7', 7, ISSUER + '|sub-anna')])
        # The directory of a tenant speaks only for checked addresses of its own domains.
        for claims in ({'email': 'mallory@example.org', 'email_verified': True}, {'email': 'bea@tenant.example', 'email_verified': False},
                       {'preferred_username': 'admin'}):
            with self.subTest(claims=claims):
                self.assertRaises(EfaError, self.login, ('--domain', 'tenant.example'), **claims)
        self.assertEqual(len(self.logins), 1)
        # A domain without a directory of its own uses the global one, which is off here.
        self.refused('oidc-start', '--domain', 'example.org')
        self.refused('tenant-oidc-set', '--tenant', 'nobody', '--mode', 'off')

    def test_portal_login(self):
        self.refused('oidc-set', '--mode', 'on', '--issuer', ISSUER, '--client_id', 'efa-web', '--redirect_uri',
                     'https://mx.example.org/login/oidc/callback', '--portal_redirect_uri', 'https://mx.example.org/portal/login/oidc/callback/x')
        self.switch_on()
        self.refused('oidc-start', '--portal', 'yes')
        self.assertTrue(self.switch_on('--portal_redirect_uri', 'https://mx.example.org/portal/login/oidc/callback')['portal'])
        portal = []
        with mock.patch.object(efactl, '_portal_oidc_login', lambda email, external, tenant=None: portal.append((email, external, tenant)) or {'role': 'user'}):
            _started, query, result = self.login(('--portal', 'yes'), ('--portal', 'yes'), email='Carl@example.org', email_verified=True)
        self.assertEqual(query['redirect_uri'], 'https://mx.example.org/portal/login/oidc/callback')
        self.assertEqual(result, {'role': 'user'})
        self.assertEqual(portal, [('Carl@example.org', ISSUER + '|sub-anna', None)])
        self.assertEqual(self.logins, [])
        # The admin redirect address is not taken for a portal code, and back.
        started = self.run_cmd('oidc-start', '--portal', 'yes')
        code, _query = self.idp.authorize(started['url'])
        self.refused('oidc-finish', f'--code={code}', f"--nonce={started['nonce']}", f"--verifier={started['verifier']}")
        # '-' takes the portal off again.
        self.assertFalse(self.switch_on('--portal_redirect_uri', '-')['portal'])

    def test_portal_refuses_admin_addresses_and_foreign_domains(self):
        with mock.patch.object(efactl, '_admin_has_address', lambda address: address == 'boss@example.org'):
            self.assertRaises(EfaError, efactl._portal_oidc_login, 'boss@example.org', ISSUER + '|s1')
        for email in ('', 'x@other.example', 'bea@tenant.example'):
            with self.subTest(email=email), mock.patch.object(efactl, '_admin_has_address', lambda address: False):
                self.assertRaises(EfaError, efactl._portal_oidc_login, email, ISSUER + '|s1', 3)


if __name__ == '__main__':
    unittest.main()
