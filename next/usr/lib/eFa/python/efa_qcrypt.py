# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""D3: held mail encrypted at rest, with a key pair per tenant. The writer (efa-maillog) knows only the public keys; the private
keys are for root, so only efactl reads a held mail. One AES-256-GCM key per mail, wrapped for each tenant of its recipients
with X25519 and HKDF-SHA256. A file without the mark is an older plain one and is read as it is."""
import base64
import json
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b'EFAQ1\n'
INFO = b'eFa-next quarantine 1'


def new_key_pair():
    """(private PEM, public raw as base64)."""
    key = x25519.X25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, base64.b64encode(public).decode()


def _wrap_key(shared, salt):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=INFO).derive(shared)


def encrypt(data, publics):
    """data for the tenants in publics {tenant: public base64}."""
    if not publics:
        raise ValueError('no key to encrypt for')
    content_key, nonce = AESGCM.generate_key(256), os.urandom(12)
    wrapped = {}
    for tenant, public in sorted(publics.items()):
        ephemeral = x25519.X25519PrivateKey.generate()
        epk = ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        shared = ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(base64.b64decode(public)))
        key_nonce = os.urandom(12)
        sealed = AESGCM(_wrap_key(shared, epk)).encrypt(key_nonce, content_key, tenant.encode())
        wrapped[tenant] = {'epk': base64.b64encode(epk).decode(), 'nonce': base64.b64encode(key_nonce).decode(), 'key': base64.b64encode(sealed).decode()}
    head = json.dumps({'wrapped': wrapped, 'nonce': base64.b64encode(nonce).decode()}, sort_keys=True).encode()
    return MAGIC + struct.pack('>I', len(head)) + head + AESGCM(content_key).encrypt(nonce, data, head)


def is_sealed(blob):
    return blob[:len(MAGIC)] == MAGIC


def decrypt(blob, privates):
    """The mail, with one of the private keys {tenant: private PEM}; a plain file as it is. ValueError without a fitting key."""
    if not is_sealed(blob):
        return blob
    size = struct.unpack('>I', blob[len(MAGIC):len(MAGIC) + 4])[0]
    start = len(MAGIC) + 4
    head = blob[start:start + size]
    meta = json.loads(head)
    for tenant, item in meta['wrapped'].items():
        pem = privates.get(tenant)
        if not pem:
            continue
        private = serialization.load_pem_private_key(pem, None)
        epk = base64.b64decode(item['epk'])
        shared = private.exchange(x25519.X25519PublicKey.from_public_bytes(epk))
        content_key = AESGCM(_wrap_key(shared, epk)).decrypt(base64.b64decode(item['nonce']), base64.b64decode(item['key']), tenant.encode())
        return AESGCM(content_key).decrypt(base64.b64decode(meta['nonce']), blob[start + size:], head)
    raise ValueError('no key of this host fits this held mail')


def self_test():
    a_private, a_public = new_key_pair()
    b_private, b_public = new_key_pair()
    blob = encrypt(b'Subject: x\r\n\r\nbody', {'3': a_public, 'global': b_public})
    assert is_sealed(blob) and b'body' not in blob
    assert decrypt(blob, {'3': a_private}) == b'Subject: x\r\n\r\nbody' == decrypt(blob, {'global': b_private})
    assert decrypt(b'plain mail', {}) == b'plain mail'
    for keys in ({}, {'4': a_private}):
        try:
            decrypt(blob, keys)
            raise AssertionError('decrypted without the key')
        except ValueError:
            pass
    broken = blob[:-1] + bytes([blob[-1] ^ 1])
    try:
        decrypt(broken, {'3': a_private})
        raise AssertionError('a changed file was read')
    except Exception as err:  # cryptography raises InvalidTag
        assert type(err).__name__ == 'InvalidTag', err
    print('self-test ok')


if __name__ == '__main__':
    self_test()
