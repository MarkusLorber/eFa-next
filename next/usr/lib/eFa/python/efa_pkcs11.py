# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""G7-17: DKIM (and ARC) keys in a hardware module through PKCS#11, for eFa-next on own hardware.

The private key never leaves the module: OpenSSL 3 with its pkcs11 provider (package pkcs11-provider) signs, with the module
the admin chose (OpenSC for Nitrokey or SmartCard-HSM, the YubiHSM 2 module, SoftHSM, or another PKCS#11 library). Tested
with SoftHSM only; no real device was tested yet. Standard library; openssl as a program."""
import base64
import glob
import hashlib
import os
import re
import subprocess
import tempfile
import urllib.parse

MODULE_DIRS = ('/usr/lib64/pkcs11/', '/usr/lib64/', '/usr/lib/pkcs11/', '/usr/lib/', '/opt/')
# Modules known to speak PKCS#11 for signing keys (in principle; only SoftHSM is tested): name in the dropdown -> file name.
KNOWN = {'OpenSC (Nitrokey HSM, SmartCard-HSM, other smart cards)': 'opensc-pkcs11.so', 'YubiHSM 2': 'yubihsm_pkcs11.so',
         'SoftHSM 2 (software, for tests)': 'libsofthsm2.so', 'p11-kit proxy (all modules of the system)': 'p11-kit-proxy.so'}
PROVIDER = '/usr/lib64/ossl-modules/pkcs11.so'
LABEL_RE = re.compile(r'^[\w .:@+-]{1,64}$')
TIMEOUT = 10


def modules():
    """{label: path} of the known modules installed here."""
    found = {}
    for label, name in KNOWN.items():
        for folder in MODULE_DIRS:
            hits = glob.glob(os.path.join(folder, '**', name), recursive=True) if folder == '/opt/' else glob.glob(os.path.join(folder, name))
            if hits:
                found[label] = sorted(hits)[0]
                break
    return found


def module_ok(path):
    return (isinstance(path, str) and path.startswith(MODULE_DIRS) and '..' not in path and path.endswith('.so') and os.path.isfile(path))


def uri(token, key):
    """The PKCS#11 URI of a private key by the label of the token and of the key, without its PIN (key_uri adds where it is)."""
    if not LABEL_RE.match(token or '') or not LABEL_RE.match(key or ''):
        raise ValueError('token and key: their labels, letters, digits and . : @ + - _ space')
    quote = lambda value: urllib.parse.quote(value, safe='')
    return f'pkcs11:token={quote(token)};object={quote(key)};type=private'


PIN_FILE_RE = re.compile(r'^/[\w./-]{1,200}$')


def key_uri(spec):
    """Security review F2: the URI openssl gets names the file of the PIN (pin-source=file:, read only by root or the service);
    the PIN itself never stands on a command line, where every user of the host could read it (ps, /proc/<pid>/cmdline)."""
    base = spec['uri']
    if 'pin-value' in base.lower() or 'pin-source' in base.lower() or '?' in base:
        raise ValueError('the key address holds a PIN: set the key up again (dkim-hsm-set)')
    pin_file = spec.get('pin_file') or ''
    if not pin_file:
        return base
    if not PIN_FILE_RE.match(pin_file) or '..' in pin_file:
        raise ValueError('the PIN file has no valid path')
    return f'{base}?pin-source=file:{pin_file}'


def write_pin(path, pin):
    """The PIN in a file of its own: mode 0400, created anew (no other content, no link followed)."""
    if os.path.lexists(path):
        os.remove(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o400)
    with os.fdopen(fd, 'w') as f:
        f.write(pin)


def _run(spec, args, data=None):
    env = {**os.environ, 'PKCS11_PROVIDER_MODULE': spec['module']}
    if data is None:
        return subprocess.run(['openssl', *args, '-provider', 'pkcs11', '-provider', 'default'], capture_output=True, env=env, timeout=TIMEOUT)
    with tempfile.NamedTemporaryFile(delete=False) as source:
        source.write(data)
    try:
        return subprocess.run(['openssl', *args, '-provider', 'pkcs11', '-provider', 'default', '-in', source.name], capture_output=True, env=env,
                              timeout=TIMEOUT)
    finally:
        os.remove(source.name)


def public(spec):
    """(algorithm, DER of the public key) of the key behind the URI: rsa-sha256 or ed25519-sha256. OSError when it does not answer."""
    done = _run(spec, ['pkey', '-in', key_uri(spec), '-pubout', '-outform', 'DER'])
    if done.returncode != 0 or not done.stdout:
        raise OSError('the module gives no public key: ' + done.stderr.decode('utf-8', 'replace').strip()[-200:])
    return ('ed25519-sha256' if len(done.stdout) == 44 else 'rsa-sha256'), done.stdout


def dns_value(algorithm, der):
    """The DKIM record of the public key: v=DKIM1; k=rsa|ed25519; p=..."""
    if algorithm == 'ed25519-sha256':
        return 'v=DKIM1; k=ed25519; p=' + base64.b64encode(der[-32:]).decode()
    return 'v=DKIM1; k=rsa; p=' + base64.b64encode(der).decode()


def signer(spec):
    """A function data -> signature for efa_dkim.sign: RSA PKCS#1 v1.5 over SHA-256, or Ed25519 over the SHA-256 (RFC 8463)."""
    def sign(data):
        if spec['algorithm'] == 'ed25519-sha256':
            done = _run(spec, ['pkeyutl', '-sign', '-rawin', '-inkey', key_uri(spec)], hashlib.sha256(data).digest())
        else:
            done = _run(spec, ['pkeyutl', '-sign', '-rawin', '-digest', 'sha256', '-inkey', key_uri(spec)], data)
        if done.returncode != 0 or not done.stdout:
            raise OSError('the module did not sign: ' + done.stderr.decode('utf-8', 'replace').strip()[-200:])
        return done.stdout
    return sign


def verify(algorithm, der, data, signature):
    """True when the signature fits the public key (the check of the test signing)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    key = serialization.load_der_public_key(der)
    try:
        if algorithm == 'ed25519-sha256':
            key.verify(signature, hashlib.sha256(data).digest())
        else:
            key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False


def self_test():
    assert uri('mail token', 'dkim own.example') == 'pkcs11:token=mail%20token;object=dkim%20own.example;type=private'
    for bad in (('t;x', 'k'), ('t', ''), ('t', 'k' * 65)):
        try:
            uri(*bad)
            raise AssertionError(bad)
        except ValueError:
            pass
    # F2 (security review 2026-11-24): the PIN never in argv; only the path of its file (mode 0400).
    spec = {'module': '/usr/lib64/pkcs11/libsofthsm2.so', 'uri': uri('t', 'k'), 'pin_file': '/run/credentials/efa-cdr.service/dkim-hsm_pin_own.example',
            'algorithm': 'rsa-sha256'}
    assert key_uri(spec) == 'pkcs11:token=t;object=k;type=private?pin-source=file:/run/credentials/efa-cdr.service/dkim-hsm_pin_own.example'
    for bad in ({'uri': 'pkcs11:token=t;object=k;type=private;pin-value=1234'}, {'uri': uri('t', 'k'), 'pin_file': '../x'},
                {'uri': uri('t', 'k') + '?pin-source=file:/x'}):
        try:
            key_uri(bad)
            raise AssertionError(bad)
        except ValueError:
            pass
    calls = []

    class Done:
        returncode, stdout, stderr = 0, b'signature', b''
    kept = subprocess.run
    subprocess.run = lambda args, **kw: calls.append(args) or Done()
    try:
        assert signer(spec)(b'data') == b'signature'
    finally:
        subprocess.run = kept
    assert calls and all('1234' not in word and 'pin-value' not in word for word in calls[0]) and any('pin-source=file:' in word for word in calls[0])
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, 'pin')
        write_pin(path, '12 34')
        write_pin(path, '5678')
        assert open(path).read() == '5678' and (os.name == 'nt' or os.stat(path).st_mode & 0o777 == 0o400)
    assert not module_ok('/tmp/x.so') and not module_ok('/usr/lib64/../tmp/x.so') and not module_ok('/usr/lib64/pkcs11/none.so')
    assert dns_value('ed25519-sha256', b'\0' * 12 + b'\1' * 32).endswith(base64.b64encode(b'\1' * 32).decode())
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert verify('rsa-sha256', der, b'data', key.sign(b'data', padding.PKCS1v15(), hashes.SHA256())) and not verify('rsa-sha256', der, b'other', b'x' * 256)
    ed = ed25519.Ed25519PrivateKey.generate()
    ed_der = ed.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert len(ed_der) == 44 and verify('ed25519-sha256', ed_der, b'data', ed.sign(hashlib.sha256(b'data').digest()))
    print('efa_pkcs11 self-test ok')


if __name__ == '__main__':
    self_test()
