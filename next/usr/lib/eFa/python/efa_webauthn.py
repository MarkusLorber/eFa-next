# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""5s: passkeys and security keys (WebAuthn Level 2) for the logins of eFa-next: a small CBOR decoder with limits, the
authenticator data, COSE keys (ES256, EdDSA, RS256) and the checks of a registration and of a login. Attestation "none":
the AAGUID is only shown. The keys are checked with python-cryptography."""
import base64
import hashlib
import json
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

MAX_ITEMS = 64
MAX_DEPTH = 8
MAX_BYTES = 4096
ALGORITHMS = {-7: 'ES256', -8: 'EdDSA', -257: 'RS256'}


class Invalid(ValueError):
    pass


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def unb64url(text):
    if not isinstance(text, str) or len(text) > 16384:
        raise Invalid('bad base64url')
    try:
        return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
    except (ValueError, TypeError):
        raise Invalid('bad base64url')


def cbor_decode(data, start=0, depth=0):
    """(value, end) of the CBOR item at start. Only what WebAuthn uses: integers, byte and text strings, arrays, maps, simple values."""
    if depth > MAX_DEPTH:
        raise Invalid('CBOR nested too deep')
    if start >= len(data):
        raise Invalid('CBOR cut off')
    first = data[start]
    major, info, pos = first >> 5, first & 31, start + 1
    if info < 24:
        value = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if pos + size > len(data):
            raise Invalid('CBOR cut off')
        value = int.from_bytes(data[pos:pos + size], 'big')
        pos += size
    else:
        raise Invalid('CBOR length not supported')
    if major == 0:
        return value, pos
    if major == 1:
        return -1 - value, pos
    if major in (2, 3):
        if value > MAX_BYTES or pos + value > len(data):
            raise Invalid('CBOR string too long')
        raw = data[pos:pos + value]
        if major == 3:
            try:
                return raw.decode('utf-8'), pos + value
            except UnicodeDecodeError:
                raise Invalid('CBOR text not UTF-8')
        return raw, pos + value
    if major == 4:
        if value > MAX_ITEMS:
            raise Invalid('CBOR array too long')
        items = []
        for _ in range(value):
            item, pos = cbor_decode(data, pos, depth + 1)
            items.append(item)
        return items, pos
    if major == 5:
        if value > MAX_ITEMS:
            raise Invalid('CBOR map too long')
        found = {}
        for _ in range(value):
            key, pos = cbor_decode(data, pos, depth + 1)
            if isinstance(key, (list, dict)):
                raise Invalid('CBOR key not allowed')
            found[key], pos = cbor_decode(data, pos, depth + 1)
        return found, pos
    if major == 7 and info in (20, 21, 22):
        return {20: False, 21: True, 22: None}[info], pos
    raise Invalid('CBOR type not supported')


def auth_data(data):
    """The authenticator data: rpIdHash, flags, signCount and, with the AT flag, the credential (aaguid, id, COSE key)."""
    if len(data) < 37:
        raise Invalid('authenticator data too short')
    found = {'rp_id_hash': data[:32], 'flags': data[32], 'sign_count': struct.unpack('>I', data[33:37])[0],
             'up': bool(data[32] & 1), 'uv': bool(data[32] & 4), 'at': bool(data[32] & 64)}
    if found['at']:
        if len(data) < 55:
            raise Invalid('credential data too short')
        length = struct.unpack('>H', data[53:55])[0]
        if length > 1023 or len(data) < 55 + length:
            raise Invalid('credential id length')
        found['aaguid'] = data[37:53].hex()
        found['credential_id'] = data[55:55 + length]
        found['cose'], _end = cbor_decode(data, 55 + length)
    return found


def cose_key(cose):
    """The public key of a COSE key map, as (algorithm name, PEM)."""
    if not isinstance(cose, dict):
        raise Invalid('COSE key is no map')
    alg = cose.get(3)
    if alg == -7 and cose.get(1) == 2 and cose.get(-1) == 1:
        x, y = cose.get(-2), cose.get(-3)
        if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == len(y) == 32):
            raise Invalid('EC key')
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b'\x04' + x + y)
    elif alg == -8 and cose.get(1) == 1 and cose.get(-1) == 6:
        if not isinstance(cose.get(-2), bytes) or len(cose[-2]) != 32:
            raise Invalid('Ed25519 key')
        key = ed25519.Ed25519PublicKey.from_public_bytes(cose[-2])
    elif alg == -257 and cose.get(1) == 3:
        n, e = cose.get(-1), cose.get(-2)
        if not (isinstance(n, bytes) and isinstance(e, bytes) and 256 <= len(n) <= 512):
            raise Invalid('RSA key: 2048 bits or more')
        key = rsa.RSAPublicNumbers(int.from_bytes(e, 'big'), int.from_bytes(n, 'big')).public_key()
    else:
        raise Invalid('key type not allowed: ES256, EdDSA or RS256 only')
    return ALGORITHMS[alg], key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def client_data(raw, kind, challenge, origin):
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise Invalid('client data is no JSON')
    if not isinstance(data, dict) or data.get('type') != kind:
        raise Invalid('wrong kind of ceremony')
    if data.get('challenge') != b64url(challenge):
        raise Invalid('wrong or old challenge')
    if data.get('origin') != origin:
        raise Invalid('wrong origin')
    if data.get('crossOrigin'):
        raise Invalid('cross-origin not allowed')
    return data


def verify_registration(attestation_b64, client_b64, challenge, rp_id, origin, need_uv=False):
    """A new credential: (credential id, algorithm, PEM, sign count, aaguid). Attestation statements are not trusted, only read."""
    client_raw = unb64url(client_b64)
    client_data(client_raw, 'webauthn.create', challenge, origin)
    attestation, _end = cbor_decode(unb64url(attestation_b64))
    if not isinstance(attestation, dict) or not isinstance(attestation.get('authData'), bytes):
        raise Invalid('attestation object')
    data = auth_data(attestation['authData'])
    if data['rp_id_hash'] != hashlib.sha256(rp_id.encode()).digest():
        raise Invalid('credential for another site')
    if not data['up'] or not data['at'] or (need_uv and not data['uv']):
        raise Invalid('user presence or verification missing')
    alg, pem = cose_key(data['cose'])
    return data['credential_id'], alg, pem, data['sign_count'], data['aaguid']


def verify_assertion(client_b64, auth_b64, signature_b64, pem, alg, old_count, challenge, rp_id, origin, need_uv=False):
    """A login with a stored credential: the new sign count, or Invalid."""
    client_raw, data_raw, signature = unb64url(client_b64), unb64url(auth_b64), unb64url(signature_b64)
    client_data(client_raw, 'webauthn.get', challenge, origin)
    data = auth_data(data_raw)
    if data['rp_id_hash'] != hashlib.sha256(rp_id.encode()).digest():
        raise Invalid('credential for another site')
    if not data['up'] or (need_uv and not data['uv']):
        raise Invalid('user presence or verification missing')
    signed = data_raw + hashlib.sha256(client_raw).digest()
    key = serialization.load_pem_public_key(pem.encode())
    try:
        if alg == 'ES256':
            key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif alg == 'EdDSA':
            key.verify(signature, signed)
        elif alg == 'RS256':
            key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise Invalid('algorithm')
    except InvalidSignature:
        raise Invalid('signature does not match')
    # A counter that goes back means a copied key; 0 on both sides means the authenticator keeps none.
    if (data['sign_count'] or old_count) and data['sign_count'] <= old_count:
        raise Invalid('sign counter went back: the key may be copied')
    return data['sign_count']


def _cbor(value):
    """A small CBOR encoder, for the software authenticator of the self-test."""
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, 'big')
    if isinstance(value, bool):
        return bytes([0xf5 if value else 0xf4])
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        return head(3, len(value.encode())) + value.encode()
    if isinstance(value, list):
        return head(4, len(value)) + b''.join(_cbor(item) for item in value)
    if isinstance(value, dict):
        return head(5, len(value)) + b''.join(_cbor(k) + _cbor(v) for k, v in value.items())
    raise TypeError(value)


def self_test():
    rp_id, origin, challenge = 'mx.example.org', 'https://mx.example.org', b'c' * 32
    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    cose = {1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, 'big'), -3: numbers.y.to_bytes(32, 'big')}
    cred = b'credential-1'
    rp_hash = hashlib.sha256(rp_id.encode()).digest()
    reg_auth = rp_hash + bytes([0x45]) + struct.pack('>I', 0) + b'\x00' * 16 + struct.pack('>H', len(cred)) + cred + _cbor(cose)
    attestation = b64url(_cbor({'fmt': 'none', 'attStmt': {}, 'authData': reg_auth}))
    reg_client = b64url(json.dumps({'type': 'webauthn.create', 'challenge': b64url(challenge), 'origin': origin}).encode())
    found_id, alg, pem, count, aaguid = verify_registration(attestation, reg_client, challenge, rp_id, origin, need_uv=True)
    assert found_id == cred and alg == 'ES256' and count == 0 and aaguid == '00' * 16
    for bad in ((attestation, reg_client, b'd' * 32, rp_id, origin), (attestation, reg_client, challenge, 'evil.example', origin),
                (attestation, reg_client, challenge, rp_id, 'https://evil.example')):
        try:
            verify_registration(*bad)
            raise AssertionError(bad)
        except Invalid:
            pass

    def assertion(counter, flags=0x05, client_challenge=challenge, kind='webauthn.get'):
        auth = rp_hash + bytes([flags]) + struct.pack('>I', counter)
        client = json.dumps({'type': kind, 'challenge': b64url(client_challenge), 'origin': origin}).encode()
        signature = private.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return b64url(client), b64url(auth), b64url(signature)
    assert verify_assertion(*assertion(5), pem, alg, 0, challenge, rp_id, origin, need_uv=True) == 5
    for args, old in ((assertion(5), 5), (assertion(6, flags=0x01), 0), (assertion(6, client_challenge=b'x' * 32), 0), (assertion(6, kind='webauthn.create'), 0)):
        try:
            verify_assertion(*args, pem, alg, old, challenge, rp_id, origin, need_uv=True)
            raise AssertionError(args)
        except Invalid:
            pass
    client_b64, auth_b64, signature_b64 = assertion(7)
    try:
        verify_assertion(client_b64, auth_b64, b64url(b'0' * 70), pem, alg, 0, challenge, rp_id, origin)
        raise AssertionError('bad signature')
    except Invalid:
        pass
    ed = ed25519.Ed25519PrivateKey.generate()
    assert cose_key({1: 1, 3: -8, -1: 6, -2: ed.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)})[0] == 'EdDSA'
    for bad in (b'\x9f', b'\x5b' + b'\xff' * 8, b'\x81' * 20 + b'\x00', b'\xa1\x80\x00', b'\x61\xff', b'\xb8\xff' + b'\x00' * 10):
        try:
            cbor_decode(bad)
            raise AssertionError(bad)
        except Invalid:
            pass
    try:
        cose_key({1: 3, 3: -257, -1: b'\x01' * 128, -2: b'\x01\x00\x01'})
        raise AssertionError('short RSA key')
    except Invalid:
        pass
    print('self-test ok')


if __name__ == '__main__':
    self_test()
