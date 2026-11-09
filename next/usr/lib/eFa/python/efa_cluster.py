# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The cluster of eFa-next nodes (9): a master and its clients, connected only by TLS with certificates on both sides from the own
certificate authority of the master. What efactl and the efa-cluster service share: the files, the keys, signing, requests."""
import ast
import base64
import fcntl
import hashlib
import http.client
import io
import ipaddress
import json
import os
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

PORT = 8460
CERT_DAYS = 825
NAME_CHARS = set('abcdefghijklmnopqrstuvwxyz0123456789-')


def folder(etc='/etc'):
    return os.path.join(etc, 'eFa', 'cluster')


def state_file(etc='/etc'):
    return os.path.join(folder(etc), 'cluster.json')


def read_state(etc='/etc'):
    try:
        with open(state_file(etc)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def write_state(state, etc='/etc'):
    path = state_file(etc)
    fd = os.open(path + '.new', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(state, f, indent=1, sort_keys=True)
    os.replace(path + '.new', path)


def valid_name(name):
    return 0 < len(name) <= 40 and set(name) <= NAME_CHARS and not name.startswith('-')


def _openssl(args, data=None):
    done = subprocess.run(['openssl'] + args, input=data, capture_output=True, timeout=60)
    if done.returncode != 0:
        raise RuntimeError('openssl failed: ' + done.stderr.decode('utf-8', 'replace').strip()[-200:])
    return done.stdout


def make_ca(base, name):
    """The certificate authority of a master: an EC key that never leaves it, valid 10 years."""
    key, cert = os.path.join(base, 'ca.key'), os.path.join(base, 'ca.crt')
    _openssl(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', key, '-out', cert,
              '-days', '3650', '-subj', f'/O=eFa-next cluster/CN={name} CA', '-addext', 'basicConstraints=critical,CA:TRUE',
              '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
    os.chmod(key, 0o600)
    return cert


def make_request(base, name):
    """The key of a node and its certificate request; the key stays on the node."""
    key = os.path.join(base, 'node.key')
    csr = _openssl(['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', key,
                    '-subj', f'/O=eFa-next cluster/CN={name}'])
    os.chmod(key, 0o600)
    return csr.decode()


def sign(base, csr, name):
    """A node certificate from the CA of the master, for client and server use, named after the node."""
    with tempfile.TemporaryDirectory() as temp:
        request, extensions = os.path.join(temp, 'node.csr'), os.path.join(temp, 'ext')
        with open(request, 'w') as f:
            f.write(csr)
        with open(extensions, 'w') as f:
            f.write(f'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                    f'extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:{name}\n')
        subject = _openssl(['req', '-in', request, '-noout', '-subject', '-nameopt', 'multiline']).decode()
        if f'commonName                = {name}' not in subject:
            raise ValueError('the request names another node')
        return _openssl(['x509', '-req', '-in', request, '-CA', os.path.join(base, 'ca.crt'), '-CAkey', os.path.join(base, 'ca.key'),
                         '-CAcreateserial', '-days', str(CERT_DAYS), '-sha256', '-extfile', extensions]).decode()


def fingerprint_pem(pem):
    """SHA-256 of a certificate, as hex with colons, the way openssl shows it."""
    der = ssl.PEM_cert_to_DER_cert(pem)
    digest = hashlib.sha256(der).hexdigest().upper()
    return ':'.join(digest[i:i + 2] for i in range(0, len(digest), 2))


def fingerprint_der(der):
    digest = hashlib.sha256(der).hexdigest().upper()
    return ':'.join(digest[i:i + 2] for i in range(0, len(digest), 2))


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def context(base, server=False):
    """TLS 1.3 only, the own node certificate, and only the cluster CA as trusted authority."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(os.path.join(base, 'node.crt'), os.path.join(base, 'node.key'))
    ctx.load_verify_locations(os.path.join(base, 'ca.crt'))
    if server:
        # The join itself comes without a certificate; every other request needs one, the handler checks it.
        ctx.verify_mode = ssl.CERT_OPTIONAL
    else:
        ctx.check_hostname = False  # nodes are known by their certificate, not by DNS
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def peer_fingerprint(base, host, port):
    """The certificate a member of this cluster must show: the master for a node, each node for the master."""
    state = read_state(os.path.dirname(os.path.dirname(base)))
    for item in list(state.get('nodes', {}).values()) + ([state['master']] if state.get('master') else []):
        if item.get('host') == host and int(item.get('port', PORT)) == int(port):
            return item.get('fingerprint')
    return None


def call(base, host, port, path, body=None, timeout=10, expected=None):
    """A request to another member with the own certificate; the answer as JSON. The CA alone is not enough: the peer must show
    the very certificate this member knows of it, so a removed or another node cannot stand in for the master."""
    expected = expected or peer_fingerprint(base, host, port)
    if not expected:
        raise OSError(f'{host}:{port} is no known member of this cluster')
    connection = http.client.HTTPSConnection(host, int(port), timeout=timeout, context=context(base))
    try:
        connection.connect()
        if fingerprint_der(connection.sock.getpeercert(binary_form=True)) != expected:
            raise OSError(f'{host}:{port} answered with another certificate than the one of that member')
        data = json.dumps(body).encode() if body is not None else None
        connection.request('POST' if data else 'GET', path, body=data, headers={'Content-Type': 'application/json'})
        answer = connection.getresponse()
        raw = answer.read()
        if answer.status >= 400:
            raise urllib.error.HTTPError(f'https://{host}:{port}{path}', answer.status, answer.reason, answer.headers, io.BytesIO(raw))
        return json.loads(raw)
    finally:
        connection.close()


def fetch_ca(host, port, timeout=10):
    """The CA of a master, read without trust; the caller compares its fingerprint with the one the master showed."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with urllib.request.urlopen(f'https://{host}:{port}/v1/ca', timeout=timeout, context=ctx) as answer:
        return json.load(answer)['ca']


def join_request(host, port, ca_pem, body, timeout=20):
    """The join, already over TLS that trusts only the CA whose fingerprint was checked."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.load_verify_locations(cadata=ca_pem)
    request = urllib.request.Request(f'https://{host}:{port}/v1/join', data=json.dumps(body).encode(), method='POST',
                                     headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=timeout, context=ctx) as answer:
        return json.load(answer)


def cert_end(pem):
    """The end of a certificate as a Unix time."""
    out = _openssl(['x509', '-noout', '-enddate'], pem.encode()).decode().strip().split('=', 1)[1]
    return int(time.mktime(time.strptime(out, '%b %d %H:%M:%S %Y %Z')))


# The journal of the master (9b): one line per entry, AES-256-GCM with a key of the master alone (root only, never sent to a
# node: the nodes get the entries over mutual TLS). Lines of the Fernet journal of before stay readable and are written anew.
# Once every node has confirmed an entry, its secrets and file contents go: only a note and their checksum stay.
JOURNAL_KEEP = 20000


def _journal_key(base):
    path = os.path.join(base, 'journal-gcm.key')
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(os.urandom(32))
    with open(path, 'rb') as f:
        return f.read()


def _seal(key, data):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    return b'g1:' + base64.b64encode(nonce + AESGCM(key).encrypt(nonce, data, b'efa-cluster-journal'))


def _open_line(base, key, line):
    if line.startswith(b'g1:'):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        raw = base64.b64decode(line[3:])
        return AESGCM(key).decrypt(raw[:12], raw[12:], b'efa-cluster-journal')
    return _fernet(base).decrypt(line)


def _fernet(base):
    from cryptography.fernet import Fernet
    path = os.path.join(base, 'journal.key')
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(Fernet.generate_key())
    with open(path, 'rb') as f:
        return Fernet(f.read().strip())


class _locked:
    """efactl appends, the service removes secrets: one at a time."""

    def __init__(self, base):
        self.path = os.path.join(base, 'journal.lock')

    def __enter__(self):
        self.handle = open(self.path, 'a')
        fcntl.flock(self.handle, fcntl.LOCK_EX)
        return self

    def __exit__(self, *_exc):
        fcntl.flock(self.handle, fcntl.LOCK_UN)
        self.handle.close()


def journal_read(base):
    path = os.path.join(base, 'journal.enc')
    if not os.path.exists(path):
        return []
    key = _journal_key(base)
    with open(path, 'rb') as f:
        return [json.loads(_open_line(base, key, line.strip())) for line in f if line.strip()]


def _journal_write(base, entries):
    key = _journal_key(base)
    path = os.path.join(base, 'journal.enc')
    fd = os.open(path + '.new', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        for entry in entries[-JOURNAL_KEEP:]:
            f.write(_seal(key, json.dumps(entry, sort_keys=True).encode()) + b'\n')
    os.replace(path + '.new', path)
    # The old key goes once no Fernet line is left.
    if os.path.exists(os.path.join(base, 'journal.key')):
        os.remove(os.path.join(base, 'journal.key'))


def journal_append(base, entries, now=None):
    """Numbers the new entries on and writes them; returns the last number."""
    with _locked(base):
        old = journal_read(base)
        seq = old[-1]['seq'] if old else 0
        for entry in entries:
            seq += 1
            old.append({'seq': seq, 'time': int(now or time.time()), **entry})
        _journal_write(base, old)
        return seq


def scrubbed(entry):
    """The entry without secrets and file contents, with their checksums."""
    entry = dict(entry)
    if entry.get('secrets'):
        entry['secrets_sha256'] = hashlib.sha256('\n'.join(entry['secrets']).encode()).hexdigest()
        entry['secrets'] = []
        entry['secrets_note'] = 'distributed'
    if entry.get('files'):
        files = []
        for item in entry['files']:
            item = dict(item)
            if item.get('data'):
                item['data_sha256'] = hashlib.sha256(item['data'].encode()).hexdigest()
                item['data'] = ''
            files.append(item)
        entry['files'] = files
        entry['files_note'] = 'distributed'
    return entry


def journal_scrub(base, confirmed):
    """Removes secrets and file contents from every entry up to the number all nodes confirmed."""
    with _locked(base):
        entries = journal_read(base)
        changed = [scrubbed(entry) if entry['seq'] <= confirmed and not entry.get('secrets_note') and not entry.get('files_note') else entry
                   for entry in entries]
        if changed != entries:
            _journal_write(base, changed)


# 9d: the bans of Fail2Ban hold on every node. Each node reports its bans, the master keeps them an hour and hands them back.
BAN_SECONDS = 3600


def f2b_banned(run=subprocess.run):
    """The banned addresses per jail: {(jail, address)}. Empty when Fail2Ban does not answer."""
    done = run(['fail2ban-client', 'banned'], capture_output=True, text=True, timeout=30)
    if done.returncode != 0:
        return set()
    try:
        jails = ast.literal_eval(done.stdout.strip() or '[]')
    except (ValueError, SyntaxError):
        return set()
    return {(jail, address) for item in jails for jail, addresses in item.items() for address in addresses}


def f2b_ban(jail, address, run=subprocess.run):
    run(['fail2ban-client', 'set', jail, 'banip', address], capture_output=True, text=True, timeout=30)


def f2b_unban(address, run=subprocess.run):
    run(['fail2ban-client', 'unban', address], capture_output=True, text=True, timeout=30)


def protected(address, networks):
    """Never banned through the cluster: loopback, the networks given (relay networks, allowlist, the nodes themselves)."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    if ip.is_loopback or ip.is_unspecified:
        return True
    for network in networks:
        try:
            if ip in ipaddress.ip_network(network, strict=False):
                return True
        except ValueError:
            continue
    return False


def merge_bans(table, reported, source, now=None, unbanned=None):
    """The ban table of the master with the reported bans of one node: each kept an hour from its last report. An address an
    admin unbanned through the cluster stays out for that hour."""
    now = time.time() if now is None else now
    lifted = {address for address, until in (unbanned or {}).items() if until > now}
    table = {key: item for key, item in table.items() if item['until'] > now and item['address'] not in lifted}
    for jail, address in reported:
        if address not in lifted:
            table[f'{jail} {address}'] = {'jail': jail, 'address': address, 'until': now + BAN_SECONDS, 'from': source}
    return table


def self_test():
    assert valid_name('mx-2') and not valid_name('MX') and not valid_name('-x') and not valid_name('a b')
    with tempfile.TemporaryDirectory() as etc:
        base = folder(etc)
        os.makedirs(base)
        # A journal of before (Fernet) is read, then written anew with AES-256-GCM, and the old key goes.
        old = _fernet(base).encrypt(json.dumps({'seq': 1, 'command': 'x'}).encode())
        with open(os.path.join(base, 'journal.enc'), 'wb') as f:
            f.write(old + b'\n')
        assert journal_append(base, [{'command': 'y'}]) == 2 and [e['command'] for e in journal_read(base)] == ['x', 'y']
        with open(os.path.join(base, 'journal.enc'), 'rb') as f:
            lines = f.read().split()
        assert all(line.startswith(b'g1:') for line in lines) and not os.path.exists(os.path.join(base, 'journal.key'))
        assert b'"command"' not in b''.join(lines), 'nothing readable at rest'
        with open(os.path.join(base, 'journal-gcm.key'), 'wb') as f:
            f.write(os.urandom(32))
        try:
            journal_read(base)
            raise AssertionError('another key read the journal')
        except Exception as err:  # InvalidTag of cryptography
            assert 'InvalidTag' in type(err).__name__ or isinstance(err, ValueError), err
        write_state({'role': 'client', 'master': {'host': '192.0.2.1', 'port': 8460, 'fingerprint': 'AA:BB'}}, etc)
        assert peer_fingerprint(base, '192.0.2.1', 8460) == 'AA:BB' and peer_fingerprint(base, '192.0.2.9', 8460) is None
        try:
            call(base, '192.0.2.9', 8460, '/v1/status')
            raise AssertionError('an unknown member was called')
        except OSError as err:
            assert 'no known member' in str(err)

    class Out:
        returncode, stdout = 0, "[{'sshd': ['203.0.113.7']}, {'postfix-sasl': ['198.51.100.9', '203.0.113.7']}, {'efa-web': []}]"
    assert f2b_banned(lambda *a, **k: Out()) == {('sshd', '203.0.113.7'), ('postfix-sasl', '198.51.100.9'), ('postfix-sasl', '203.0.113.7')}
    assert protected('127.0.0.1', []) and protected('10.0.0.5', ['10.0.0.0/8']) and not protected('203.0.113.7', ['10.0.0.0/8']) and protected('x', [])
    table = merge_bans({'sshd 192.0.2.1': {'jail': 'sshd', 'address': '192.0.2.1', 'until': 50, 'from': 'a'}}, {('sshd', '203.0.113.7')}, 'mx-2', now=100)
    assert list(table) == ['sshd 203.0.113.7'] and table['sshd 203.0.113.7']['until'] == 100 + BAN_SECONDS
    assert merge_bans(table, {('sshd', '203.0.113.7')}, 'mx-2', now=200, unbanned={'203.0.113.7': 3000}) == {}, 'an unban holds'
    assert token_hash('abc') == hashlib.sha256(b'abc').hexdigest()
    with tempfile.TemporaryDirectory() as base:
        try:
            ca = make_ca(base, 'master')
        except (OSError, RuntimeError):
            print('self-test ok')  # no openssl here: the part below runs where it is
            return
        csr = make_request(base, 'mx-2')
        cert = sign(base, csr, 'mx-2')
        with open(ca) as f:
            ca_pem = f.read()
        assert fingerprint_pem(cert) != fingerprint_pem(ca_pem) and len(fingerprint_pem(cert)) == 95
        assert cert_end(cert) > time.time() + 800 * 86400
        try:
            sign(base, csr, 'mx-3')
            raise AssertionError('a request for another name must not be signed')
        except ValueError:
            pass
        with open(os.path.join(base, 'node.crt'), 'w') as f:
            f.write(cert)
        context(base, server=True)
        context(base)
        try:
            import cryptography  # noqa: F401
        except ImportError:
            print('self-test ok')
            return
        last = journal_append(base, [{'type': 'command', 'command': 'pdf-password-set', 'args': {}, 'secrets': ['Geheim-Passwort-1']},
                                     {'type': 'files', 'files': [{'path': 'rspamd/dkim/x.key', 'mode': 0o640, 'data': 'UFJJVkFURSBLRVk='}],
                                      'mirror': [], 'then': 'cluster-dkim-apply'}])
        assert last == 2 and [entry['seq'] for entry in journal_read(base)] == [1, 2]
        with open(os.path.join(base, 'journal.enc'), 'rb') as f:
            raw = f.read()
        assert b'Geheim-Passwort-1' not in raw and b'UFJJVkFURSBLRVk=' not in raw, 'encrypted on the disk'
        assert oct(os.stat(os.path.join(base, 'journal-gcm.key')).st_mode & 0o777) == '0o600'
        journal_scrub(base, 1)
        first, second = journal_read(base)
        assert first['secrets'] == [] and first['secrets_note'] == 'distributed' and len(first['secrets_sha256']) == 64
        assert second['files'][0]['data'] == 'UFJJVkFURSBLRVk=', 'not confirmed yet'
        journal_scrub(base, 2)
        text = json.dumps(journal_read(base))
        assert 'Geheim-Passwort-1' not in text and 'UFJJVkFURSBLRVk=' not in text, 'no secret left after all nodes confirmed'
    print('self-test ok')


if __name__ == '__main__':
    self_test()
