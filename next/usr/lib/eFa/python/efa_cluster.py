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
import re
import secrets
import ssl
import stat
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
    try:
        write_view(state, etc)
    except OSError:  # the line of the web interface only; the state is written
        pass


def public_dir(etc='/etc'):
    """The two files of the cluster for the web interface: state, not configuration, so not under /etc (no noise in config
    backups, rpm -V, the tamper guard and the export). /var/lib/eFa is root only (0750): a folder of their own, 0755. A second
    node on one host (EFA_ETC) has its own."""
    return '/var/lib/efa-cluster' if os.path.abspath(etc) == '/etc' else os.path.join(etc, 'var-lib-efa-cluster')


def health_file(etc='/etc'):
    return os.path.join(public_dir(etc), 'health.json')


def drop_old_files(etc='/etc'):
    """Builds of 2026-11-18 kept both files under /etc/eFa for a few hours: they go."""
    for name in ('cluster-view.json', 'cluster-health.json'):
        try:
            os.remove(os.path.join(etc, 'eFa', name))
        except OSError:
            pass


def write_public(path, data):
    """A file for the web interface: readable, written whole (a temp file renamed), no secrets in it."""
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    fd = os.open(path + '.new', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, 'w') as f:
        json.dump(data, f, sort_keys=True)
    os.chmod(path + '.new', 0o644)
    os.replace(path + '.new', path)


# 2026-11-19: a node whose follow loop stopped took no journal entry for a day and nothing said so. The master's health
# names it: behind the journal for more than LAG_ALARM_SECONDS, or no finished round of its follow loop for more than
# ROUND_ALARM_SECONDS (the heartbeat of /v1/status, a node of 6.0.0.6.6.2 on).
LAG_ALARM_SECONDS = 300
ROUND_ALARM_SECONDS = 120


def health_alarm(row, old, answer, now):
    """(lag_since, alarm text) of one node from its answer now and its row of the last poll."""
    behind = row.get('behind')
    lag_since = (old.get('lag_since') or int(now)) if behind else None
    alarms = []
    if behind and now - lag_since > LAG_ALARM_SECONDS:
        alarms.append(f'{behind} journal entries behind for {int(now - lag_since) // 60} min')
    round_at = answer.get('round') if isinstance(answer.get('round'), int) else 0
    if round_at and now - round_at > ROUND_ALARM_SECONDS:
        alarms.append(f'its follow loop finished no round for {int(now - round_at)} s')
    return lag_since, '; '.join(alarms)


def health_rows(state, answers, before, seq, now):
    """The nodes of a master for its dashboard (2026-11-18): from the last poll, one row each; the last contact stays from
    before when a node does not answer now. answers: name -> the /v1/status answer, or an Exception."""
    last = {row.get('name'): row for row in before.get('nodes', [])} if isinstance(before.get('nodes'), list) else {}
    rows = []
    for name, node in sorted(state.get('nodes', {}).items()):
        row = {'name': name, 'role': 'node', 'joined': node.get('joined', '')}
        answer = answers.get(name)
        if node.get('pending'):
            rows.append({**row, 'sync': 'pending'})
            continue
        if isinstance(answer, dict):
            failed = answer.get('failed') if isinstance(answer.get('failed'), list) else []
            behind = max(0, int(seq) - int(answer.get('applied', 0) or 0)) if str(answer.get('applied', 0)).isdigit() else None
            row = {**row, 'version': str(answer.get('version', ''))[:40], 'platform': str(answer.get('platform', ''))[:8],
                   'status': str(answer.get('status', ''))[:20], 'contact': int(now), 'behind': behind,
                   'sync': 'error' if failed else 'ok', 'failed': len(failed),
                   # 6.0.0.6.7: whether the node has its own break-glass admin; None from a node of before (it does not say)
                   'breakglass': answer['breakglass'] if isinstance(answer.get('breakglass'), bool) else None}
            row['lag_since'], row['alarm'] = health_alarm(row, last.get(name, {}), answer, now)
            rows.append(row)
        else:
            old = last.get(name, {})
            rows.append({**row, 'version': old.get('version', ''), 'platform': old.get('platform', ''), 'contact': old.get('contact'),
                         'behind': old.get('behind'), 'sync': 'error', 'error': str(answer or 'no answer')[:160], 'breakglass': old.get('breakglass')})
    return rows


def view_file(etc='/etc'):
    return os.path.join(public_dir(etc), 'view.json')


def read_view(etc='/etc'):
    try:
        with open(view_file(etc)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def write_view(state, etc='/etc', contact=None):
    """What every page of the web interface shows of the cluster (2026-11-18): the role, the mode and, on a client, the name
    and address of its master and when it last answered. No secrets: readable by efa-web, which makes no call for it."""
    view = {'role': state.get('role'), 'name': state.get('name', ''), 'mode': state.get('mode', 'master-client'), 'written': int(time.time())}
    if state.get('role') == 'client':
        master = state.get('master', {})
        view.update(master={'name': master.get('name', ''), 'host': master.get('host', '')},
                    contact=int(contact) if contact else read_view(etc).get('contact'), down_since=state.get('master_down_since'))
    write_public(view_file(etc), view)


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


# 6.0.0.6: download-only data in a cluster. Only the master downloads; its manifest lists the files of each kind with size and
# SHA-256. A node fetches a file it lacks over the mutual TLS of the cluster and checks it before it swaps it in.
SYNC_DIRS = {'clamav': '/var/lib/clamav', 'rspamd': '/etc/rspamd', 'maps': '/etc/rspamd/maps.d', 'state': '/var/lib/eFa',
             'blocklists': '/var/lib/eFa/blocklists'}
SYNC_MANIFEST = '/var/lib/eFa/cluster-manifest.json'
SYNC_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,120}')
SYNC_MAX = 300 * 1024 * 1024


def served_file(manifest, kind, name, folder, limit=SYNC_MAX):
    """The open file the master hands a node, and its size: only a plain name of its current manifest, no link, a regular file
    within the limit. Anything else is a PermissionError."""
    items = manifest.get('kinds', {}).get(kind) if isinstance(manifest, dict) else None
    if not isinstance(items, dict) or not isinstance(name, str) or name not in items or not SYNC_NAME.fullmatch(name) or '..' in name or not folder:
        raise PermissionError('not a file of the manifest')
    try:
        fd = os.open(os.path.join(folder, name), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise PermissionError('not a file of the manifest')
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        os.close(fd)
        raise PermissionError('not a regular file within the limit')
    return fd, info.st_size


def fetch_file(base, host, port, path, target, limit, expected=None, timeout=120):
    """A file of the master into target, read in blocks: (size, SHA-256). As call(): the master must show its known certificate."""
    expected = expected or peer_fingerprint(base, host, port)
    if not expected:
        raise OSError(f'{host}:{port} is no known member of this cluster')
    connection = http.client.HTTPSConnection(host, int(port), timeout=timeout, context=context(base))
    try:
        connection.connect()
        if fingerprint_der(connection.sock.getpeercert(binary_form=True)) != expected:
            raise OSError(f'{host}:{port} answered with another certificate than the one of that member')
        connection.request('GET', path)
        answer = connection.getresponse()
        if answer.status != 200:
            raise OSError(f'HTTP {answer.status}')
        length = answer.headers.get('Content-Length', '')
        if not length.isdigit() or int(length) > limit:
            raise OSError('larger than the manifest says')
        digest, size = hashlib.sha256(), 0
        with open(target, 'wb') as f:
            while True:
                block = answer.read(65536)
                if not block:
                    break
                size += len(block)
                if size > limit:
                    raise OSError('larger than the manifest says')
                digest.update(block)
                f.write(block)
        return size, digest.hexdigest()
    finally:
        connection.close()


def fetch_ca(host, port, timeout=10):
    """The CA of a master, read without trust; the caller compares its fingerprint with the one the master showed."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with urllib.request.urlopen(f'https://{host}:{port}/v1/ca', timeout=timeout, context=ctx) as answer:
        return json.load(answer)['ca']


# What a node that joined and waits (pending) never receives, whatever it asks: until /v1/activate it gets only the preview
# manifest of preview_manifest(), names, paths, hashes and sizes. The one list of these classes (2026-11-18).
PREVIEW_NEVER = ('file contents (DKIM and ARC private keys, TLS and Let\'s Encrypt keys, passwords and their hashes, API and join '
                 'tokens, TOTP and HMAC keys, the keys of threat feeds and backups)', 'the SQL rows of users, groups, tenants and '
                 'scoped settings', 'the values of the mail settings (a relay password map or a key in a value)')
PREVIEW_KEYS = ('seq', 'files', 'postconf', 'units', 'tables')
# No hash of a value either (a short password or token in a plain hash can be guessed offline): the master sends names and
# paths, the node sends the hashes of its own values back, the master answers changed or not.
COMPARE_KEYS = ('files', 'unchanged_files', 'postconf', 'units', 'tables')
JOB_SECONDS = 900  # a job of a master or a step of a node is valid this long (15 minutes)


def preview_manifest(snapshot):
    """The snapshot of a master reduced to what a pending node may see before its admin confirmed: the paths of the files,
    the names of the mail settings, the units, whether tables come. No value, no content, no hash of either."""
    return {'seq': int(snapshot.get('seq', 0)), 'files': [str(item.get('path', '')) for item in snapshot.get('files', [])],
            'postconf': sorted(str(name) for name in snapshot.get('postconf', {})),
            'units': {str(unit): bool(on) for unit, on in snapshot.get('units', {}).items()},
            'tables': ['the shared tables'] if snapshot.get('sql') else []}


def preview_compare(snapshot, local):
    """The master: the hashes the node sent of its own files and settings against the snapshot; back only changed or not."""
    mine = local.get('files') if isinstance(local.get('files'), dict) else {}
    theirs = local.get('postconf') if isinstance(local.get('postconf'), dict) else {}
    files, same = [], 0
    for item in snapshot.get('files', []):
        path = str(item.get('path', ''))
        digest = hashlib.sha256(base64.b64decode(item.get('data', ''))).hexdigest()
        if path not in mine:
            files.append({'path': path, 'change': 'new'})
        elif mine[path] != digest:
            files.append({'path': path, 'change': 'replaced'})
        else:
            same += 1
    postconf = [{'name': str(name)} for name, value in sorted(snapshot.get('postconf', {}).items())
                if theirs.get(name) != hashlib.sha256(str(value).encode()).hexdigest()]
    return {'files': files, 'unchanged_files': same, 'postconf': postconf,
            'units': {str(unit): bool(on) for unit, on in snapshot.get('units', {}).items()},
            'tables': ['the shared tables'] if snapshot.get('sql') else []}


def job_envelope(kind, now=None, seconds=JOB_SECONDS, **values):
    """A step of the cluster that changes something: its kind, an id never used before, when it was made and until when it
    counts. The receiver refuses another kind, an old or future one, and one whose id it saw already (a replay)."""
    now = int(time.time() if now is None else now)
    return {'job': kind, 'id': secrets.token_hex(16), 'issued': now, 'expires': now + seconds, **values}


def job_problem(body, kind, seen, now=None):
    """Why a job is refused, or None; a job taken is noted in seen (id -> expiry, the expired ones dropped)."""
    now = time.time() if now is None else now
    for key in [key for key, until in seen.items() if until < now]:
        del seen[key]
    job_id = str(body.get('id', ''))
    if body.get('job') != kind or not re.fullmatch(r'[0-9a-f]{32}', job_id):
        return 'not a job of this kind'
    issued, expires = body.get('issued'), body.get('expires')
    if not isinstance(issued, int) or not isinstance(expires, int) or expires - issued > JOB_SECONDS or issued > now + 60:
        return 'times of the job not valid'
    if expires < now:
        return 'job expired'
    if job_id in seen:
        return 'job seen already (a replay)'
    seen[job_id] = expires
    return None


def seen_jobs_file(etc='/etc'):
    return os.path.join(folder(etc), 'seen-jobs.json')


def active_nodes(state):
    """The nodes of a master that take part. A node that joined is pending until its admin saw what it takes over and
    confirmed (cluster wizard, 2026-11-18): no traffic, no view over all nodes and no rollout goes to it before."""
    return {name: node for name, node in state.get('nodes', {}).items() if not node.get('pending')}


def release_of(path='/etc/os-release'):
    """el9 or el10 of this host, '' when it cannot be read."""
    try:
        with open(path) as f:
            found = re.search(r'^VERSION_ID="?(\d+)', f.read(), re.M)
    except OSError:
        return ''
    return f'el{found.group(1)}' if found else ''


def efa_version(paths=('/etc/eFa-next-Version', '/etc/eFa-Version')):
    """The eFa-next version of this host (the old file name: hosts of 6.0.0.5.x)."""
    for path in paths:
        try:
            with open(path) as f:
                return f.readline().strip().replace('eFa-', '', 1)
        except OSError:
            continue
    return ''


def join_request(host, port, ca_pem, body, timeout=20, path='/v1/join'):
    """The join (or its check before, /v1/precheck), already over TLS that trusts only the CA whose fingerprint was checked."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.load_verify_locations(cadata=ca_pem)
    request = urllib.request.Request(f'https://{host}:{port}{path}', data=json.dumps(body).encode(), method='POST',
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


def journal_redact(base, commands):
    """Takes the secrets out of every entry of these commands, whether the nodes have it or not; returns how many changed."""
    with _locked(base):
        entries = journal_read(base)
        changed = [{**entry, 'secrets': [], 'secrets_note': 'redacted'} if entry.get('command') in commands and entry.get('secrets') else entry
                   for entry in entries]
        count = sum(1 for old, new in zip(entries, changed) if old is not new)
        if count:
            _journal_write(base, changed)
        return count


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
# CL-RECIDIVE: the bans of other nodes go into this jail (jail.d/efa-cluster.local), which recidive does not count and no node
# reports again as its own.
SHARED_JAIL = 'efa-cluster'


def f2b_banned(run=subprocess.run):
    """The banned addresses per jail: {(jail, address)}. Empty when Fail2Ban does not answer."""
    try:
        done = run(['fail2ban-client', 'banned'], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        # 2026-11-19: a Fail2Ban busy for more than 30 s ended the follow loop of efa-cluster; no answer = no bans now.
        return set()
    if done.returncode != 0:
        return set()
    try:
        jails = ast.literal_eval(done.stdout.strip() or '[]')
    except (ValueError, SyntaxError):
        return set()
    return {(jail, address) for item in jails for jail, addresses in item.items() for address in addresses}


def f2b_ban(jail, address, run=subprocess.run):
    run(['fail2ban-client', 'set', jail, 'banip', address], capture_output=True, text=True, timeout=30)


def f2b_unban(address, run=subprocess.run, jail=None):
    """Lifts the bans of an address: in every jail, or with jail only in that one."""
    command = ['fail2ban-client', 'set', jail, 'unbanip', address] if jail else ['fail2ban-client', 'unban', address]
    run(command, capture_output=True, text=True, timeout=30)


# Hans 2026-11-18: the admin networks of the web allowlist are never banned. Only networks an admin entered while the list is
# on: with the list off ("all") or empty nothing is exempt, and an entry as wide as the internet is not exempt either
# (IPv4 wider than /8, IPv6 wider than /32).
ADMIN_EXEMPT_MIN_PREFIX = {4: 8, 6: 32}
# The jails that guard an admin way in (web, SSH) and those that ban on every port (recidive, the bans of the cluster).
# Never the mail jails (postfix-sasl, efa-harvest): a password guessed on port 587 from an admin network is still banned there.
ADMIN_EXEMPT_JAILS = ('sshd', 'efa-web', 'recidive', SHARED_JAIL)


def admin_exempt_networks(allow):
    """The networks of the web allowlist (web-allowlist.json) that Fail2Ban never bans in ADMIN_EXEMPT_JAILS."""
    if not isinstance(allow, dict) or allow.get('mode') != 'allowed':
        return []
    found = set()
    for item in allow.get('entries') or []:
        try:
            network = ipaddress.ip_network(item.get('network', ''), strict=False)
        except (AttributeError, TypeError, ValueError):
            continue
        if network.prefixlen >= ADMIN_EXEMPT_MIN_PREFIX[network.version]:
            found.add(str(network))
    return sorted(found)


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
        if address not in lifted and jail != SHARED_JAIL:
            table[f'{jail} {address}'] = {'jail': jail, 'address': address, 'until': now + BAN_SECONDS, 'from': source}
    return table


# 8g: the send limits of efa-outbound for the whole cluster. Each node reports its counts of the running hour every half minute
# (absolute values, so a lost report heals itself); the master answers with the sums of all other nodes, which the node writes
# into its Redis next to its own counts (see RedisCounts in efa-outbound). Target domains are sent as names, at most RATE_DOMAINS
# per sender, so a domain reached from two nodes counts once; a report older than RATE_SECONDS no longer counts.
RATE_KEYS = 3000
RATE_DOMAINS = 150
RATE_DOMAINS_TOTAL = 30000
RATE_SECONDS = 120
RATE_KINDS = ('who:', 'domain:', 'tenant:')
RATE_TTL = 7200


def rate_clean(report, most=RATE_DOMAINS):
    """A report or an answer as it came over the network: {key: [recipients, [domains]]}, everything else dropped."""
    clean = {}
    if not isinstance(report, dict):
        return clean
    for key, value in list(report.items())[:RATE_KEYS]:
        if not (isinstance(key, str) and key.startswith(RATE_KINDS) and len(key) <= 400 and key.isprintable()):
            continue
        if not (isinstance(value, list) and len(value) == 2 and isinstance(value[0], int) and 0 <= value[0] < 10 ** 9 and isinstance(value[1], list)):
            continue
        clean[key] = [value[0], sorted({item.lower() for item in value[1] if isinstance(item, str) and 0 < len(item) <= 253 and item.isprintable()})[:most]]
    return clean


def rate_report(call, hour):
    """The counts of this node in the hour, from the local Redis: the senders with the most recipients first."""
    own = call([('HGETALL', f'efa:rate:own:{hour}')])[0] or []
    counts = {key: int(value) for key, value in zip(own[::2], own[1::2]) if key.startswith(RATE_KINDS)}
    keys = sorted(counts, key=lambda key: (-counts[key], key))[:RATE_KEYS]
    who = [key for key in keys if key.startswith('who:')]
    members = dict(zip(who, call([('SMEMBERS', f'efa:rate:{key}:{hour}:d') for key in who]))) if who else {}
    report, budget = {}, RATE_DOMAINS_TOTAL
    for key in keys:
        domains = sorted(members.get(key) or [])[:min(RATE_DOMAINS, budget)]
        budget -= len(domains)
        report[key] = [counts[key], domains]
    return report


def merge_rates(table, node, hour, report, now=None):
    """The table of the master with the report of one node; reports of another hour or older than RATE_SECONDS are gone."""
    now = time.time() if now is None else now
    table = {name: item for name, item in table.items() if item['at'] > now - RATE_SECONDS and item['hour'] >= hour - 1}
    table[node] = {'hour': hour, 'at': now, 'keys': rate_clean(report)}
    return table


def peer_rates(table, node, hour, now=None):
    """What all other nodes counted in the hour: {key: [recipients, [domains]]}."""
    now = time.time() if now is None else now
    total = {}
    for name, item in table.items():
        if name == node or item['hour'] != hour or item['at'] <= now - RATE_SECONDS:
            continue
        for key, (recipients, domains) in item['keys'].items():
            found = total.setdefault(key, [0, set()])
            found[0] += recipients
            found[1].update(domains)
    return {key: [recipients, sorted(domains)[:RATE_DOMAINS * 4]] for key, (recipients, domains) in total.items()}


def rate_apply(call, hour, peers):
    """The counts of the other nodes into the local Redis, next to the own ones (:pr recipients, :pd target domains)."""
    commands = []
    for key, (recipients, domains) in rate_clean(peers, RATE_DOMAINS * 4).items():
        base = f'efa:rate:{key}:{hour}'
        commands += [('SET', base + ':pr', recipients, 'EX', RATE_TTL), ('DEL', base + ':pd')]
        if domains:
            commands += [('SADD', base + ':pd', *domains), ('EXPIRE', base + ':pd', RATE_TTL)]
    if commands:
        call(commands)
    return len(commands)


# 6.0.0.6.6: mixed platforms in one cluster (EL9 and EL10 while the nodes are upgraded one at a time, as the release upgrade
# says). Nodes of one release series only; what a node takes from the master as raw Postfix values is made fit for its Postfix.
VERSION_FILES = ('/etc/eFa-next-Version', '/etc/eFa-Version')  # the old name: nodes of 6.0.0.5.x


def own_version(files=None):
    """The installed eFa-next version (6.0.0.6.6), '' when none is recorded."""
    for path in files or VERSION_FILES:
        try:
            with open(path) as f:
                found = re.search(r'\d+(?:\.\d+)+', f.read())
            return found.group(0) if found else ''
        except OSError:
            continue
    return ''


def own_platform(os_release='/etc/os-release'):
    """el9, el10, ...: the major version of the operating system, '' when unknown."""
    try:
        with open(os_release) as f:
            found = re.search(r'^VERSION_ID="?(\d+)', f.read(), flags=re.M)
    except OSError:
        return ''
    return f'el{found.group(1)}' if found else ''


def version_series(version):
    """The release series: the first four numbers (6.0.0.6 of 6.0.0.6.6), '' for none."""
    parts = re.findall(r'\d+', str(version or ''))
    return '.'.join(parts[:4]) if len(parts) >= 4 else ''


def version_problem(own, other, who='the master', strict=False):
    """'' when both are of one release series, else why not (for join and every sync). A peer that names no version is a
    build from before this check (6.0.0.6.5 and older): for a rolling update of a cluster one node at a time it is taken,
    except with strict (a new node joining: it has to name its version)."""
    if not str(other or '').strip() and not strict:
        return ''
    if not version_series(other):
        return f'{who} names no eFa-next version: update it to the release series {version_series(own)} first'
    if version_series(own) != version_series(other):
        return (f'{who} runs eFa-next {other}, this node {own}: nodes of a cluster need one release series '
                f'({version_series(own)} here); update the older one first')
    return ''


# Indexed lookup tables of Postfix: written as the table type of the receiving node. Everything else a node lacks is refused.
INDEXED_MAP_TYPES = ('hash', 'btree', 'lmdb', 'cdb', 'dbm', 'sdbm')
MAP_REF = re.compile(r'\b([a-z][a-z0-9_]*):(?=[/$.{]|[a-z0-9_]+:)')


def snapshot_value_local(value, local_type, supported):
    """A Postfix value of the master for this node: (value, '') with the tables of an indexed type as local_type (a btree
    cache as btree beside hash, else local_type), or (None, why) when it names a table type this Postfix does not have
    (supported: the types of postconf -m). Never the value of the master raw where it would break the mail here."""
    missing = []

    def local(found):
        kind = found.group(1)
        if kind in INDEXED_MAP_TYPES:
            # The node compiles every table of the snapshot as its own type (postmap): its references name that type. A
            # cache (postscreen, TLS sessions, verify) is btree beside hash, as efactl _cache_map writes it.
            cache = 'cache' in value[found.end():].split(',')[0].split()[0] if value[found.end():].strip() else False
            kind = 'btree' if cache and local_type == 'hash' else local_type
        if kind not in supported:
            missing.append(found.group(1))
        return kind + ':'
    changed = MAP_REF.sub(local, value or '')
    if missing:
        return None, f"table type {', '.join(sorted(set(missing)))} is not in this Postfix (postconf -m)"
    return changed, ''


def self_test():
    # 8g: the counts of the other nodes, cleaned, of the same hour and fresh only.
    table = merge_rates({}, 'mx-2', 5, {'who:a': [3, ['x.example']], 'evil': [1, []]}, now=1000)
    table = merge_rates(table, 'mx-3', 5, {'who:a': [2, ['x.example', 'y.example']]}, now=1010)
    assert peer_rates(table, 'mx-1', 5, now=1010) == {'who:a': [5, ['x.example', 'y.example']]}
    assert peer_rates(table, 'mx-2', 5, now=1010) == {'who:a': [2, ['x.example', 'y.example']]} and peer_rates(table, 'mx-1', 6, now=1010) == {}
    assert peer_rates(table, 'mx-1', 5, now=1000 + RATE_SECONDS + 1) == {'who:a': [2, ['x.example', 'y.example']]}
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
        # 6.0.0.6: the secrets of named commands go at once, confirmed or not; order, numbers and other secrets stay.
        journal_append(base, [{'type': 'command', 'command': 'clam-source-set', 'args': {'source': 'securiteinfo'}, 'secrets': ['EXAMPLEKEY' * 2]},
                              {'type': 'command', 'command': 'pdf-password-set', 'args': {}, 'secrets': ['Other-Secret-2']},
                              {'type': 'command', 'command': 'clam-securiteinfo-set', 'args': {'tier': 'basic'}, 'secrets': ['RGF0YWJhc2VDdXN0b21VUkwgRVhBTVBMRUtFWQ==']}])
        assert journal_redact(base, {'clam-source-set', 'clam-securiteinfo-set'}) == 2 and journal_redact(base, {'clam-source-set'}) == 0
        entries = journal_read(base)
        assert [entry['seq'] for entry in entries] == [1, 2, 3, 4, 5] and entries[3]['secrets'] == ['Other-Secret-2']
        assert entries[2]['secrets'] == [] and entries[4]['secrets_note'] == 'redacted' and entries[4]['args'] == {'tier': 'basic'}
        text = json.dumps(entries)
        assert 'EXAMPLEKEY' not in text and 'RGF0YWJhc2VDdXN0b21VUkwgRVhBTVBMRUtFWQ==' not in text
        for name in os.listdir(base):
            with open(os.path.join(base, name), 'rb') as f:
                assert b'EXAMPLEKEY' not in f.read(), name
    print('self-test ok')


if __name__ == '__main__':
    self_test()
