# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""15: S/MIME and PGP at the gateway. Signs and encrypts outgoing mail, decrypts incoming mail, with keys of addresses or whole
domains (domain certificates between gateways). OpenSSL (cms) and GnuPG do the cryptography; this module cuts the mail into its
header and its MIME entity (the part that is signed or encrypted) and puts it together again, byte for byte, with CRLF.
Keys: files named smime-own-<id>.pem (certificate, key, chain), smime-peer-<id>.pem, pgp-own-<id>.asc (secret key),
pgp-peer-<id>.asc; <id> is an address or @domain."""
import os
import re
import secrets
import shutil
import subprocess
import tempfile

CONTENT = re.compile(rb'^(content-[\w-]+|mime-version)\s*:', re.I)
TIMEOUT = 60


class CryptoError(ValueError):
    pass


def crlf(raw):
    # Any number of CR before a LF: openssl on some systems writes CR CR LF with -crlfeol.
    return re.sub(rb'\r*\n', b'\r\n', raw)


def split(raw):
    """(the header fields as a list of their lines, the body) of a mail in CRLF."""
    raw = crlf(raw)
    head, sep, body = raw.partition(b'\r\n\r\n')
    fields = []
    for line in head.split(b'\r\n'):
        if line[:1] in (b' ', b'\t') and fields:
            fields[-1] += b'\r\n' + line
        elif line:
            fields.append(line)
    return fields, body if sep else b''


def entity(raw):
    """(the header fields that stay outside, the MIME entity: Content-* fields and the body)."""
    fields, body = split(raw)
    inner = [field for field in fields if CONTENT.match(field) and not field.lower().startswith(b'mime-version')]
    outer = [field for field in fields if not CONTENT.match(field)]
    if not inner:
        inner = [b'Content-Type: text/plain; charset=us-ascii']
    return outer, b'\r\n'.join(inner) + b'\r\n\r\n' + body


def join(outer, new_entity):
    """The mail again: the outer fields, MIME-Version once, and the new entity with its own Content-* fields."""
    fields, body = split(new_entity)
    inner = [field for field in fields if not field.lower().startswith(b'mime-version')]
    return b'\r\n'.join(outer + [b'MIME-Version: 1.0'] + inner) + b'\r\n\r\n' + body


def content_type(raw):
    fields, _body = split(raw)
    found = next((field for field in fields if field.lower().startswith(b'content-type')), b'')
    return re.sub(rb'\s+', b' ', found.split(b':', 1)[1] if b':' in found else b'').strip().lower().decode('ascii', 'replace')


def is_encrypted(raw):
    kind = content_type(raw)
    return kind.startswith('multipart/encrypted') or (kind.startswith(('application/pkcs7-mime', 'application/x-pkcs7-mime'))
                                                      and 'signed-data' not in kind)


def is_signed(raw):
    kind = content_type(raw)
    return kind.startswith('multipart/signed') or 'signed-data' in kind


def _run(argv, data=b'', env=None):
    done = subprocess.run(argv, input=data, capture_output=True, timeout=TIMEOUT, env=env)
    if done.returncode != 0:
        raise CryptoError(f'{os.path.basename(argv[0])}: {done.stderr.decode("utf-8", "replace").strip()[-200:]}')
    return done.stdout


def key_for(keys, kind, address):
    """The key file of an address, else of its domain (domain certificate), else None. kind: smime-own, smime-peer, pgp-own, pgp-peer."""
    address = address.lower()
    for name in (address, '@' + address.rpartition('@')[2]):
        path = keys.get(f'{kind}-{name}')
        if path:
            return path
    return None


def key_files(folder, prefix=''):
    """{kind-id: path} of a folder of keys; prefix: the one of systemd credentials (crypto_)."""
    found = {}
    if not folder or not os.path.isdir(folder):
        return found
    for name in os.listdir(folder):
        if name.startswith(prefix):
            stem = name[len(prefix):].rsplit('.', 1)[0]
            if re.fullmatch(r'(smime|pgp)-(own|peer)-(@?[a-z0-9._%+@-]+)', stem):
                found[stem] = os.path.join(folder, name)
    return found


def _own(pem):
    """(the options for an own key, environment, temporary file or None). P3: a .json names a key in an HSM (PKCS#11 provider)
    with its certificate; else the PEM holds certificate and key."""
    if not pem.endswith('.json'):
        return ['-inkey', pem], None, None
    import json
    with open(pem) as f:
        spec = json.load(f)
    handle = tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False)
    handle.write(spec['cert'])
    handle.close()
    return ['-inkey', spec['uri'], '-provider', 'pkcs11', '-provider', 'default'], {**os.environ, 'PKCS11_PROVIDER_MODULE': spec['module']}, handle.name


# S/MIME with openssl cms. The entity is signed as binary: it is in CRLF already, so it stays byte for byte.
def smime_sign(raw, pem, openssl='openssl'):
    outer, inner = entity(raw)
    key, env, cert = _own(pem)
    try:
        signed = _run([openssl, 'cms', '-sign', '-binary', '-md', 'sha256', '-signer', cert or pem, *key, '-outform', 'SMIME', '-crlfeol'], inner, env)
    finally:
        if cert:
            os.remove(cert)
    return join(outer, signed)


def smime_encrypt(raw, pems, openssl='openssl'):
    outer, inner = entity(raw)
    argv = [openssl, 'cms', '-encrypt', '-binary', '-aes-256-cbc', '-outform', 'SMIME', '-crlfeol']
    for pem in pems:
        argv += ['-recip', pem, '-keyopt', 'rsa_padding_mode:oaep']
    return join(outer, _run(argv, inner))


def smime_decrypt(raw, pem, openssl='openssl'):
    outer, inner = entity(raw)
    key, env, cert = _own(pem)
    try:
        return join(outer, crlf(_run([openssl, 'cms', '-decrypt', '-recip', cert or pem, *key], inner, env)))
    finally:
        if cert:
            os.remove(cert)


def smime_signer_cert(raw, openssl='openssl'):
    """The certificate of the signer of a signed mail (PEM), to encrypt to the sender later; None without one."""
    _outer, inner = entity(raw)
    with tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as out:
        path = out.name
    try:
        subprocess.run([openssl, 'cms', '-verify', '-noverify', '-signer', path, '-out', os.devnull], input=inner, capture_output=True, timeout=TIMEOUT)
        with open(path, 'rb') as f:
            data = f.read()
        return data if b'BEGIN CERTIFICATE' in data else None
    finally:
        os.remove(path)


# PGP/MIME (RFC 3156) with gpg in a home folder of its own; peers by --recipient-file, so no keyring of peers is needed.
def gpg_home(own_keys, gpg='gpg'):
    """A home folder for gpg with the own secret keys imported, and {key file: fingerprint}; the caller removes the folder."""
    home = tempfile.mkdtemp(prefix='efa-gpg-')
    os.chmod(home, 0o700)
    fingerprints = {}
    for path in own_keys:
        with open(path, 'rb') as f:
            data = f.read()
        shown = _run([gpg, '--homedir', home, '--batch', '--with-colons', '--import-options', 'show-only', '--import'], data)
        found = re.search(rb'^fpr:+([0-9A-F]{40}):', shown, re.M)
        _run([gpg, '--homedir', home, '--batch', '--import'], data)
        if found:
            fingerprints[path] = found.group(1).decode()
    return home, fingerprints


def _gpg(home, gpg='gpg'):
    return [gpg, '--homedir', home, '--batch', '--yes', '--no-tty', '--trust-model', 'always', '--pinentry-mode', 'loopback', '--passphrase', '']


def _boundary():
    return '=_efa_' + secrets.token_hex(12)


def pgp_sign(raw, home, signer, gpg='gpg'):
    outer, inner = entity(raw)
    signature = _run(_gpg(home, gpg) + ['--local-user', signer, '--digest-algo', 'SHA256', '--armor', '--detach-sign'], inner)
    boundary = _boundary()
    body = (f'--{boundary}\r\n').encode() + inner + (f'\r\n--{boundary}\r\nContent-Type: application/pgp-signature; name="signature.asc"\r\n'
                                                     f'Content-Description: OpenPGP digital signature\r\n\r\n').encode() + crlf(signature) + \
        f'\r\n--{boundary}--\r\n'.encode()
    head = f'Content-Type: multipart/signed; micalg=pgp-sha256; protocol="application/pgp-signature"; boundary="{boundary}"\r\n\r\n'.encode()
    return join(outer, head + body)


def pgp_encrypt(raw, home, peers, gpg='gpg', signer=None):
    outer, inner = entity(raw)
    argv = _gpg(home, gpg) + ['--armor', '--encrypt'] + [item for path in peers for item in ('--recipient-file', path)]
    if signer:
        argv += ['--sign', '--local-user', signer]
    data = _run(argv, inner)
    boundary = _boundary()
    body = (f'--{boundary}\r\nContent-Type: application/pgp-encrypted\r\nContent-Description: PGP/MIME version identification\r\n\r\nVersion: 1\r\n\r\n'
            f'--{boundary}\r\nContent-Type: application/octet-stream; name="encrypted.asc"\r\nContent-Description: OpenPGP encrypted message\r\n'
            f'Content-Disposition: inline; filename="encrypted.asc"\r\n\r\n').encode() + crlf(data) + f'\r\n--{boundary}--\r\n'.encode()
    head = f'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="{boundary}"\r\n\r\n'.encode()
    return join(outer, head + body)


def pgp_decrypt(raw, home, gpg='gpg'):
    _outer, inner = entity(raw)
    found = re.search(rb'-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----', inner, re.S)
    if not found:
        raise CryptoError('no PGP message in the mail')
    outer, _ = entity(raw)
    return join(outer, crlf(_run(_gpg(home, gpg) + ['--decrypt'], found.group(0))))


def outbound_plan(policy, sender, rcpts, keys):
    """What to do with an outgoing mail: {'sign': kind or None, 'encrypt': kind or None, 'missing': [recipients]}.
    policy: {'sign': {own domain: 'smime' | 'pgp'}, 'encrypt': {address or domain: {'mode': 'always' | 'if-possible', 'kind': 'smime' |
    'pgp' | 'auto'}}}. Encryption needs a key of each recipient; 'always' without one names the recipient in missing."""
    domain = sender.rpartition('@')[2].lower()
    plan = {'sign': None, 'encrypt': None, 'missing': []}
    wanted = (policy.get('sign') or {}).get(sender.lower()) or (policy.get('sign') or {}).get(domain)
    if wanted and key_for(keys, f'{wanted}-own', sender):
        plan['sign'] = wanted
    rules = [(policy.get('encrypt') or {}).get(rcpt.lower()) or (policy.get('encrypt') or {}).get(rcpt.rpartition('@')[2].lower()) for rcpt in rcpts]
    if not any(rules):
        return plan
    for kind in ('smime', 'pgp'):
        if all(not rule or rule['kind'] in (kind, 'auto') for rule in rules) and all(key_for(keys, f'{kind}-peer', rcpt) for rcpt in rcpts):
            plan['encrypt'] = kind
            break
    if plan['encrypt'] is None:
        plan['missing'] = [rcpt for rcpt, rule in zip(rcpts, rules) if rule and rule['mode'] == 'always']
    if plan['encrypt'] == 'pgp' and plan['sign'] == 'smime' or plan['encrypt'] == 'smime' and plan['sign'] == 'pgp':
        plan['sign'] = plan['encrypt'] if key_for(keys, f"{plan['encrypt']}-own", sender) else None
    return plan


def self_test():
    raw = b'From: a@own.example\nTo: b@far.example\nSubject: Hi\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nHello\nworld\n'
    outer, inner = entity(raw)
    assert outer == [b'From: a@own.example', b'To: b@far.example', b'Subject: Hi'] and inner.startswith(b'Content-Type: text/plain')
    assert join(outer, inner) == b'From: a@own.example\r\nTo: b@far.example\r\nSubject: Hi\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello\r\nworld\r\n'
    keys = {'smime-peer-@far.example': '/k1', 'pgp-peer-c@other.example': '/k2', 'smime-own-@own.example': '/k3'}
    assert key_for(keys, 'smime-peer', 'B@far.example') == '/k1' and key_for(keys, 'smime-peer', 'c@other.example') is None
    policy = {'sign': {'own.example': 'smime'}, 'encrypt': {'far.example': {'mode': 'always', 'kind': 'auto'}, 'other.example': {'mode': 'always', 'kind': 'pgp'}}}
    assert outbound_plan(policy, 'a@own.example', ['b@far.example'], keys) == {'sign': 'smime', 'encrypt': 'smime', 'missing': []}
    assert outbound_plan(policy, 'a@own.example', ['b@far.example', 'c@other.example'], keys)['missing'] == ['b@far.example', 'c@other.example']
    assert outbound_plan(policy, 'a@own.example', ['x@free.example'], keys) == {'sign': 'smime', 'encrypt': None, 'missing': []}
    assert is_encrypted(b'Content-Type: application/pkcs7-mime; smime-type=enveloped-data\r\n\r\nx')
    assert is_signed(b'Content-Type: multipart/signed; protocol="application/pkcs7-signature"\r\n\r\nx') and not is_encrypted(raw)
    openssl, gpg = shutil.which('openssl'), shutil.which('gpg')
    if openssl:
        folder = tempfile.mkdtemp()
        try:
            pem = os.path.join(folder, 'own.pem')
            _run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=a@own.example', '-keyout', pem + '.key', '-out', pem + '.crt',
                  '-addext', 'subjectAltName=email:a@own.example'])
            with open(pem, 'wb') as f:
                f.write(open(pem + '.crt', 'rb').read() + open(pem + '.key', 'rb').read())
            signed = smime_sign(raw, pem, openssl)
            assert b'Subject: Hi' in signed and is_signed(signed) and b'Hello\r\nworld' in signed
            assert b'BEGIN CERTIFICATE' in smime_signer_cert(signed, openssl)
            sealed = smime_encrypt(signed, [pem], openssl)
            assert is_encrypted(sealed) and b'Hello' not in sealed and b'Subject: Hi' in sealed
            opened = smime_decrypt(sealed, pem, openssl)
            assert opened.count(b'Subject: Hi') == 1 and is_signed(opened) and b'Hello\r\nworld' in opened
        finally:
            shutil.rmtree(folder, ignore_errors=True)
    # The gpg of Git for Windows cannot start its agent for a Windows Python: the PGP part runs on Linux (CI).
    if gpg and os.name != 'nt':
        source = tempfile.mkdtemp()
        try:
            _run([gpg, '--homedir', source, '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key', 'a@own.example', 'ed25519', 'sign', '2d'])
            fpr = re.search(rb'fpr:+([0-9A-F]{40})', _run([gpg, '--homedir', source, '--with-colons', '--list-keys'])).group(1).decode()
            _run([gpg, '--homedir', source, '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-add-key', fpr, 'cv25519', 'encr', '2d'])
            secret = os.path.join(source, 'own.asc')
            with open(secret, 'wb') as f:
                f.write(_run([gpg, '--homedir', source, '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--armor', '--export-secret-keys', fpr]))
            public = os.path.join(source, 'peer.asc')
            with open(public, 'wb') as f:
                f.write(_run([gpg, '--homedir', source, '--armor', '--export', fpr]))
            home, fingerprints = gpg_home([secret], gpg)
            assert fingerprints[secret] == fpr
            try:
                signed = pgp_sign(raw, home, 'a@own.example', gpg)
                assert is_signed(signed) and b'application/pgp-signature' in signed and b'Hello\r\nworld' in signed
                sealed = pgp_encrypt(raw, home, [public], gpg, signer='a@own.example')
                assert is_encrypted(sealed) and b'Hello' not in sealed and b'BEGIN PGP MESSAGE' in sealed
                opened = pgp_decrypt(sealed, home, gpg)
                assert b'Subject: Hi' in opened and b'Hello\r\nworld' in opened and not is_encrypted(opened)
            finally:
                shutil.rmtree(home, ignore_errors=True)
        finally:
            subprocess.run([gpg, '--homedir', source, '--kill', 'gpg-agent'], capture_output=True)
            shutil.rmtree(source, ignore_errors=True)
    print('self-test ok')


if __name__ == '__main__':
    self_test()
