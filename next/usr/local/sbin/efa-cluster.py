#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""eFa-next cluster service (9): HTTPS on the cluster port, only TLS 1.2+ with certificates on both sides from the CA of the master.
Without a certificate only two requests are open: the CA (public anyway) and, on the master, the join with a one-time token.
Every other request needs the certificate of a known member: the master of a client, a node of the master.

    efa-cluster.py [--port N]     EFA_ETC moves the folder of the cluster files (a second node on one host)
"""
import base64
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import syslog
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

for _folder in ('/usr/lib/eFa/python', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'lib', 'eFa', 'python')):
    if os.path.isdir(_folder) and _folder not in sys.path:
        sys.path.insert(0, _folder)
import efa_cluster  # noqa: E402
import efa_redis  # noqa: E402

ETC = os.environ.get('EFA_ETC', '/etc')
BASE = efa_cluster.folder(ETC)
MAX_BODY = 64 * 1024
RATES_BODY = 4 * 1024 * 1024
JOIN_TRIES = 10  # per address and minute
FETCH_SECONDS = 30
# Handshake and request of one connection: snapshots and journals of the master are larger.
CONNECTION_SECONDS = 120
# What the master may run on a node, for the view over all nodes (9c): mail log, quarantine, queue, and their actions.
MASTER_RUNS = {'maillog-search', 'quarantine-list', 'quarantine-show', 'quarantine-release', 'quarantine-delete',
               'queue-list', 'queue-show', 'queue-action', 'status', 'cve-watch-status', 'update-install', 'update-staged-set'}
ARG_CHARS = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._-:+ ')
JOURNAL_PAGE = 200
EFACTL = os.environ.get('EFA_EFACTL', '/usr/sbin/efactl')


class Throttle:
    def __init__(self):
        self.lock, self.seen = threading.Lock(), {}

    def allow(self, who, now=None):
        now = time.time() if now is None else now
        with self.lock:
            recent = [moment for moment in self.seen.get(who, []) if now - moment < 60]
            recent.append(now)
            self.seen[who] = recent
            return len(recent) <= JOIN_TRIES


def member(state, fingerprint):
    """Whose certificate it is: the master for a client, a node for the master; None for anyone else."""
    if state.get('role') == 'master':
        return next((name for name, node in state.get('nodes', {}).items() if node.get('fingerprint') == fingerprint), None)
    master = state.get('master', {})
    return 'master' if master.get('fingerprint') == fingerprint else None


def join(state, body, now=None):
    """A node joins with a one-time token: its request is signed and it is listed. Returns the answer and the changed state."""
    now = time.time() if now is None else now
    tokens = {key: until for key, until in state.get('tokens', {}).items() if until > now}
    key = efa_cluster.token_hash(str(body.get('token', '')))
    name = str(body.get('name', ''))
    if key not in tokens:
        raise PermissionError('unknown or expired token')
    if not efa_cluster.valid_name(name) or name in state.get('nodes', {}) or name == state.get('name'):
        raise ValueError('name: small letters, digits and dashes, not taken yet')
    cert = efa_cluster.sign(BASE, str(body.get('csr', '')), name)
    del tokens[key]
    nodes = dict(state.get('nodes', {}))
    nodes[name] = {'host': str(body.get('host', ''))[:255], 'port': int(body.get('port', efa_cluster.PORT)),
                   'fingerprint': efa_cluster.fingerprint_pem(cert), 'joined': time.strftime('%Y-%m-%d %H:%M:%S')}
    with open(os.path.join(BASE, 'ca.crt')) as f:
        ca = f.read()
    with open(os.path.join(BASE, 'node.crt')) as f:
        master_fingerprint = efa_cluster.fingerprint_pem(f.read())
    return {'cert': cert, 'ca': ca, 'master': state.get('name'), 'master_fingerprint': master_fingerprint}, {**state, 'tokens': tokens, 'nodes': nodes}


def journal_after(seq, entries=None):
    """The entries of the master after a number, at most a page."""
    entries = efa_cluster.journal_read(BASE) if entries is None else entries
    return [entry for entry in entries if entry['seq'] > seq][:JOURNAL_PAGE]


def confirm(state, name, seq):
    """A node confirms what it applied; returns the changed state and the number all nodes have, for the scrub."""
    nodes = dict(state.get('nodes', {}))
    nodes[name] = {**nodes[name], 'applied': max(int(nodes[name].get('applied', 0)), int(seq))}
    return {**state, 'nodes': nodes}, min(int(node.get('applied', 0)) for node in nodes.values())


def below(relative, etc=None):
    """A path of the journal below the /etc of this node; nothing outside it, whatever the entry says."""
    etc = os.path.realpath(etc or ETC)
    path = os.path.realpath(os.path.join(etc, relative))
    if not path.startswith(etc + os.sep):
        raise ValueError(f'a path outside {etc}: {relative}')
    return path


def command_line(entry):
    line = [EFACTL, entry['command']]
    for name, value in sorted(entry.get('args', {}).items()):
        line += [f'--{name}', str(value)]
    return line


def apply(entry, run=subprocess.run):
    """One entry on a client: the command with its secrets on stdin, or the files (a mirrored folder loses what the master no
    longer has) and the command after them. Returns an error text, or None."""
    env = {**os.environ, 'EFA_ETC': ETC, 'EFA_CLUSTER_REPLAY': '1'}
    if entry['type'] == 'command' and entry['command'] == 'cluster-sync-apply':
        # 6.0.0.6: large signature files must not hold up the poll of the journal: the transfer runs on its own.
        subprocess.Popen(command_line(entry), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, start_new_session=True)
        return None
    if entry['type'] == 'command':
        done = run(command_line(entry), input=''.join(secret + '\n' for secret in entry.get('secrets', [])), capture_output=True,
                   text=True, timeout=600, env=env)
        return None if done.returncode == 0 else (done.stdout or done.stderr)[-300:]
    keep = set()
    for item in entry['files']:
        path = below(item['path'])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path + '.new', 'wb') as f:
            f.write(base64.b64decode(item['data']))
        os.chmod(path + '.new', item['mode'])
        os.replace(path + '.new', path)
        keep.add(path)
    for top in entry.get('mirror', []):
        for root, _dirs, names in os.walk(below(top)):
            for name in names:
                if os.path.join(root, name) not in keep:
                    os.remove(os.path.join(root, name))
    if entry.get('then'):
        done = run([EFACTL, entry['then']], capture_output=True, text=True, timeout=300, env=env)
        return None if done.returncode == 0 else (done.stdout or done.stderr)[-300:]
    return None


def protected_networks(state):
    """Relay networks, the allowlist and the nodes of the cluster: never banned through it."""
    networks = []
    for path, key in ((os.path.join(ETC, 'eFa', 'outbound.json'), 'networks'), (os.path.join(ETC, 'eFa', 'firewall.json'), 'allowlist')):
        try:
            with open(path) as f:
                networks += json.load(f).get(key, [])
        except (OSError, ValueError):
            pass
    networks += [node.get('host', '') for node in state.get('nodes', {}).values()] + [state.get('master', {}).get('host', '')]
    return [item for item in networks if item]


def apply_bans(bans, state, banned=None, unbanned=()):
    """The bans of the cluster that this node lacks, banned here, and the addresses an admin unbanned, unbanned here.
    Returns how many were banned."""
    have = efa_cluster.f2b_banned() if banned is None else banned
    held = {address for _jail, address in have}
    for address in sorted(set(unbanned) & held):
        efa_cluster.f2b_unban(address)
    networks, count = protected_networks(state), 0
    for address in sorted({item['address'] for item in bans} - held):
        # CL-RECIDIVE: in the jail of the cluster (every port, not counted by recidive); an address banned here already stays as it is.
        if not efa_cluster.protected(address, networks):
            efa_cluster.f2b_ban(efa_cluster.SHARED_JAIL, address)
            count += 1
    return count


def share_bans(state):
    """Every half minute: the master takes its own bans into the table; a client reports its bans and takes those of the others."""
    own = {(jail, address) for jail, address in efa_cluster.f2b_banned()
           if jail != efa_cluster.SHARED_JAIL and not efa_cluster.protected(address, protected_networks(state))}
    if state.get('role') == 'master':
        with Handler.lock:
            state = efa_cluster.read_state(ETC)
            state['bans'] = efa_cluster.merge_bans(state.get('bans', {}), own, state['name'], unbanned=state.get('unbans', {}))
            efa_cluster.write_state(state, ETC)
        apply_bans(list(state['bans'].values()), state, unbanned=live_unbans(state))
    elif state.get('role') == 'client':
        master = state['master']
        answer = efa_cluster.call(BASE, master['host'], master['port'], '/v1/bans', {'bans': sorted(own)}, timeout=30)
        apply_bans(answer.get('bans', []), state, unbanned=answer.get('unbans', []))


def share_rates(state, call=None, now=None):
    """8g, every half minute: the own send counts of the hour to the master, the counts of the other nodes into the own Redis.
    The master keeps the reports in memory only: they are absolute and come again within half a minute."""
    call, now = call or efa_redis.call, time.time() if now is None else now
    hour = int(now // 3600)
    own = efa_cluster.rate_report(call, hour)
    if state.get('role') == 'master':
        with Handler.lock:
            Handler.rates = efa_cluster.merge_rates(Handler.rates, state['name'], hour, own, now)
            peers = efa_cluster.peer_rates(Handler.rates, state['name'], hour, now)
    elif state.get('role') == 'client':
        master = state['master']
        peers = efa_cluster.call(BASE, master['host'], master['port'], '/v1/rates', {'hour': hour, 'rates': own}, timeout=30).get('rates', {})
    else:
        return 0
    return efa_cluster.rate_apply(call, hour, peers)


def live_unbans(state):
    return [address for address, until in state.get('unbans', {}).items() if until > time.time()]


def sync_pull(popen=subprocess.Popen):
    """6.0.0.6, a client after its start, after the master is back, and again while a transfer failed: the download-only files
    of the master it lacks. Started on its own, so the poll of the journal goes on."""
    popen([EFACTL, 'cluster-sync-pull'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
          env={**os.environ, 'EFA_ETC': ETC}, start_new_session=True)


SYNC_RETRY_SECONDS = 600
SYNC_RECEIVED = '/var/lib/eFa/cluster-received.json'


def sync_failed():
    """True if the last transfer of a kind failed: then the node asks again every ten minutes."""
    try:
        with open(SYNC_RECEIVED) as f:
            received = json.load(f)
    except (OSError, ValueError):
        return False
    return any(isinstance(item, dict) and item.get('errors') and item.get('files') for name, item in received.items() if name != 'fallback')


def sync_signature(dirs=None):
    """On the master: name, size and time of the files in the folders of the kinds, to notice a change (freshclam) cheaply."""
    found = []
    for kind, folder in sorted((dirs or efa_cluster.SYNC_DIRS).items()):
        try:
            for name in sorted(os.listdir(folder)):
                info = os.stat(os.path.join(folder, name))
                found.append((kind, name, info.st_size, info.st_mtime_ns))
        except OSError:
            continue
    return found


def follow():
    """Every half minute: the bans of the cluster; on a client the new entries of the master, applied in order. A failed one is
    noted and skipped."""
    pulled, retry_at, seen = False, 0, None
    while True:
        time.sleep(FETCH_SECONDS)
        state = efa_cluster.read_state(ETC)
        if state.get('role') == 'master':
            # A change in a folder of the kinds (freshclam, a job): the manifest anew and, if it changed, a journal entry.
            now_seen = sync_signature()
            if seen is not None and now_seen != seen:
                subprocess.run([EFACTL, 'cluster-sync-publish'], capture_output=True, text=True, timeout=600, env={**os.environ, 'EFA_ETC': ETC})
            seen = now_seen
        try:
            share_bans(state)
        except (OSError, ValueError, KeyError) as err:
            syslog.syslog(syslog.LOG_WARNING, f'efa-cluster bans not shared: {err}')
        try:
            share_rates(state)
        except (OSError, ValueError, KeyError, TypeError) as err:
            # Each node then counts its own mail only, as without a cluster.
            syslog.syslog(syslog.LOG_WARNING, f'efa-cluster send counts not shared: {err}')
        if state.get('role') != 'client':
            continue
        master = state['master']
        try:
            reply = efa_cluster.call(BASE, master['host'], master['port'], f"/v1/journal?after={state.get('applied', 0)}", timeout=30)
            entries = reply['entries']
        except (OSError, ValueError, KeyError) as err:
            syslog.syslog(syslog.LOG_WARNING, f'efa-cluster master not reached: {err}')
            # 9g-b: since when, for the dashboard; a node never takes over by itself (two nodes would both become master).
            if not state.get('master_down_since'):
                state['master_down_since'] = int(time.time())
                efa_cluster.write_state(state, ETC)
            continue
        if state.get('master_down_since'):
            state.pop('master_down_since')
            efa_cluster.write_state(state, ETC)
            pulled = False  # 6.0.0.6: the master is back: its files replace what the node fetched itself meanwhile
        if not pulled or (time.time() > retry_at and sync_failed()):
            pulled, retry_at = True, time.time() + SYNC_RETRY_SECONDS
            sync_pull()
        # 9g: a new mode of the master: all settings anew, then the journal from there.
        if reply.get('mode') in ('master-client', 'ha') and reply['mode'] != state.get('mode', 'master-client'):
            state['mode'] = reply['mode']
            efa_cluster.write_state(state, ETC)
            done = subprocess.run([EFACTL, 'cluster-resync'], capture_output=True, text=True, timeout=600, env={**os.environ, 'EFA_ETC': ETC})
            syslog.syslog(syslog.LOG_NOTICE, f"efa-cluster mode {reply['mode']}: resync {'done' if done.returncode == 0 else 'failed'}")
            continue
        for entry in entries:
            error = apply(entry)
            state = efa_cluster.read_state(ETC)
            state['applied'] = entry['seq']
            if error:
                state.setdefault('failed', []).append({'seq': entry['seq'], 'command': entry.get('command') or entry.get('then'), 'error': error})
                state['failed'] = state['failed'][-20:]
                syslog.syslog(syslog.LOG_ERR, f"efa-cluster entry {entry['seq']} failed: {error}")
            efa_cluster.write_state(state, ETC)
        if entries:
            try:
                efa_cluster.call(BASE, master['host'], master['port'], '/v1/ack', {'seq': entries[-1]['seq']}, timeout=30)
            except (OSError, ValueError) as err:
                syslog.syslog(syslog.LOG_WARNING, f'efa-cluster confirm failed: {err}')


def read_manifest():
    try:
        with open(efa_cluster.SYNC_MANIFEST) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def sync_file(role, who, path):
    """(None, manifest) for /v1/manifest, (open file, size) for /v1/file?kind=..&name=..: only on the master, only for its nodes."""
    if role != 'master' or who in (None, 'master'):
        raise PermissionError('only a node of this master fetches its files')
    if path == '/v1/manifest':
        # The names of the nodes too: after a day without the master the first of them alone sends the lookalike alerts.
        return None, {'kinds': read_manifest().get('kinds', {}), 'nodes': sorted(efa_cluster.read_state(ETC).get('nodes', {}))}
    query = urllib.parse.parse_qs(path.split('?', 1)[1], keep_blank_values=True)
    kind, name = query.get('kind', [''])[0], query.get('name', [''])[0]
    if len(query.get('kind', [])) != 1 or len(query.get('name', [])) != 1 or kind not in efa_cluster.SYNC_DIRS:
        raise PermissionError('not a file of the manifest')
    return efa_cluster.served_file(read_manifest(), kind, name, efa_cluster.SYNC_DIRS[kind])


def run_for_master(body, run=subprocess.run):
    """One command of the master's list on this node, as the master: the answer of efactl as JSON."""
    command, args = str(body.get('command', '')), body.get('args', {})
    if command not in MASTER_RUNS or not isinstance(args, dict):
        raise PermissionError('not a command the master may run here')
    line = [EFACTL, '--client', 'cluster-master', command]
    for name, value in sorted(args.items()):
        value = str(value)
        if not name.isidentifier() or len(value) > 200 or not set(value) <= ARG_CHARS:
            raise ValueError(f'argument {name} not allowed')
        line += [f'--{name}', value]
    done = run(line, capture_output=True, text=True, timeout=120, env={**os.environ, 'EFA_ETC': ETC})
    try:
        return json.loads(done.stdout)
    except ValueError:
        return {'error': (done.stderr or done.stdout)[-300:]}


def forwarded_line(body, who):
    """The efactl call for a change a node hands on in HA mode. efactl itself refuses commands that are not shared."""
    command, args = str(body.get('command', '')), body.get('args', {})
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{1,40}', command) or not isinstance(args, dict) or not isinstance(body.get('stdin', ''), str):
        raise ValueError('not a command')
    line = [EFACTL, '--client', f'cluster-node {who} ({str(body.get("user", ""))[:60]})', command]
    for name, value in sorted(args.items()):
        value = str(value)
        if not name.isidentifier() or len(value) > 4000 or '\x00' in value:
            raise ValueError(f'argument {name} not allowed')
        line += [f'--{name}', value]
    return line


def run_forwarded(body, who, run=subprocess.run):
    done = run(forwarded_line(body, who), input=body.get('stdin', ''), capture_output=True, text=True, timeout=170,
               env={**os.environ, 'EFA_ETC': ETC, 'EFA_CLUSTER_FORWARDED': who})
    try:
        return json.loads(done.stdout)
    except ValueError:
        return {'error': (done.stderr or done.stdout).strip()[-300:] or 'no answer'}


def node_status():
    done = subprocess.run([EFACTL, 'status'], capture_output=True, text=True, timeout=30, env={**os.environ, 'EFA_ETC': ETC})
    try:
        status = json.loads(done.stdout)
    except ValueError:
        status = {'status': 'unknown', 'error': (done.stderr or done.stdout)[-200:]}
    version = ''
    for path in ('/etc/eFa-next-Version', '/etc/eFa-Version'):  # the old name: nodes of 6.0.0.5.x
        try:
            with open(path) as f:
                version = f.read().strip()
            break
        except OSError:
            continue
    state = efa_cluster.read_state(ETC)
    return {'status': status.get('status'), 'down': status.get('down', []), 'version': version, 'time': int(time.time()),
            'applied': state.get('applied', 0), 'failed': state.get('failed', [])[-5:]}


class Handler(BaseHTTPRequestHandler):
    throttle = Throttle()
    lock = threading.Lock()
    rates = {}
    server_version = 'efa-cluster'

    def log_message(self, fmt, *args):
        syslog.syslog(syslog.LOG_INFO, 'efa-cluster ' + (fmt % args)[:300])

    def answer(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def peer(self):
        der = self.connection.getpeercert(binary_form=True)
        return member(efa_cluster.read_state(ETC), efa_cluster.fingerprint_der(der)) if der else None

    def do_GET(self):
        if self.path == '/v1/ca':
            with open(os.path.join(BASE, 'ca.crt')) as f:
                return self.answer(200, {'ca': f.read()})
        who = self.peer()
        if who is None:
            return self.answer(403, {'error': 'a certificate of a cluster member is needed'})
        if self.path == '/v1/status':
            return self.answer(200, {**node_status(), 'name': efa_cluster.read_state(ETC).get('name')})
        if self.path == '/v1/snapshot' and efa_cluster.read_state(ETC).get('role') == 'master':
            done = subprocess.run([EFACTL, '--client', 'cluster-node', 'cluster-snapshot'], capture_output=True, text=True, timeout=300,
                                  env={**os.environ, 'EFA_ETC': ETC})
            try:
                return self.answer(200, json.loads(done.stdout))
            except ValueError:
                return self.answer(500, {'error': (done.stderr or done.stdout)[-200:]})
        if self.path == '/v1/manifest' or self.path.startswith('/v1/file?'):
            return self.sync_answer(who)
        if self.path.startswith('/v1/journal?after=') and efa_cluster.read_state(ETC).get('role') == 'master':
            after = self.path.split('=', 1)[1]
            return self.answer(200, {'entries': journal_after(int(after) if after.isdigit() else 0),
                                     'mode': efa_cluster.read_state(ETC).get('mode', 'master-client')})
        return self.answer(404, {'error': 'unknown'})

    def sync_answer(self, who):
        """6.0.0.6: the manifest, or one file of it, for a node of this master; the file streamed as it is on the disk."""
        try:
            fd, size = sync_file(efa_cluster.read_state(ETC).get('role'), who, self.path)
        except PermissionError as err:
            return self.answer(403 if 'node' in str(err) else 404, {'error': str(err)})
        if fd is None:
            return self.answer(200, size)
        with os.fdopen(fd, 'rb') as f:
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(size))
            self.end_headers()
            shutil.copyfileobj(f, self.wfile, 65536)
        return None

    def do_POST(self):
        value = (self.headers.get('Content-Length') or '0').strip()
        # -1 would read to the end: the join is open without a certificate.
        if not (value.isascii() and value.isdigit()):
            return self.answer(400, {'error': 'bad Content-Length'})
        length = int(value)
        # 8g: the send counts of a node are larger than the other requests; only a member may send that much.
        if length > (RATES_BODY if self.path == '/v1/rates' and self.peer() not in (None, 'master') else MAX_BODY):
            return self.answer(413, {'error': 'too large'})
        try:
            body = json.loads(self.rfile.read(length) or b'{}')
        except ValueError:
            return self.answer(400, {'error': 'no JSON'})
        if self.path == '/v1/run':
            if self.peer() != 'master':
                return self.answer(403, {'error': 'only the master runs commands here'})
            try:
                return self.answer(200, run_for_master(body))
            except PermissionError as err:
                return self.answer(403, {'error': str(err)})
            except ValueError as err:
                return self.answer(400, {'error': str(err)})
        if self.path == '/v1/forward':
            who, state = self.peer(), efa_cluster.read_state(ETC)
            if state.get('role') != 'master' or who in (None, 'master') or state.get('mode') != 'ha':
                return self.answer(403, {'error': 'changes from the nodes only in HA mode, on the master'})
            try:
                return self.answer(200, run_forwarded(body, who))
            except ValueError as err:
                return self.answer(400, {'error': str(err)})
        if self.path == '/v1/bans':
            who = self.peer()
            if efa_cluster.read_state(ETC).get('role') != 'master' or who is None or not isinstance(body.get('bans'), list):
                return self.answer(403, {'error': 'only nodes report bans to their master'})
            reported = {(str(item[0]), str(item[1])) for item in body['bans'] if isinstance(item, list) and len(item) == 2}
            with self.lock:
                state = efa_cluster.read_state(ETC)
                state['bans'] = efa_cluster.merge_bans(state.get('bans', {}), reported, who, unbanned=state.get('unbans', {}))
                efa_cluster.write_state(state, ETC)
            return self.answer(200, {'bans': list(state['bans'].values()), 'unbans': live_unbans(state)})
        if self.path == '/v1/lookalike':
            # 6.0.0.6: what a node found alone while the master was away; the master alerts once per domain.
            who, state = self.peer(), efa_cluster.read_state(ETC)
            if state.get('role') != 'master' or who in (None, 'master') or not isinstance(body.get('hits'), list):
                return self.answer(403, {'error': 'only nodes report lookalikes to their master'})
            done = subprocess.run([EFACTL, '--client', 'cluster-node', 'lookalike-report'], input=json.dumps({'hits': body['hits'][:50]}),
                                  capture_output=True, text=True, timeout=120, env={**os.environ, 'EFA_ETC': ETC})
            try:
                return self.answer(200, json.loads(done.stdout))
            except ValueError:
                return self.answer(500, {'error': (done.stderr or done.stdout)[-200:]})
        if self.path == '/v1/rates':
            who, state = self.peer(), efa_cluster.read_state(ETC)
            if state.get('role') != 'master' or who in (None, 'master') or not isinstance(body.get('hour'), int):
                return self.answer(403, {'error': 'only nodes report send counts to their master'})
            with self.lock:
                Handler.rates = efa_cluster.merge_rates(Handler.rates, who, body['hour'], body.get('rates'))
                peers = efa_cluster.peer_rates(Handler.rates, who, body['hour'])
            return self.answer(200, {'rates': peers})
        if self.path == '/v1/ack':
            who = self.peer()
            state = efa_cluster.read_state(ETC)
            if state.get('role') != 'master' or who is None or not str(body.get('seq', '')).isdigit():
                return self.answer(403, {'error': 'only nodes confirm to their master'})
            with self.lock:
                state, everyone = confirm(efa_cluster.read_state(ETC), who, body['seq'])
                efa_cluster.write_state(state, ETC)
                efa_cluster.journal_scrub(BASE, everyone)
            return self.answer(200, {'confirmed': int(body['seq'])})
        if self.path == '/v1/join':
            if not self.throttle.allow(self.client_address[0]):
                return self.answer(429, {'error': 'too many tries'})
            with self.lock:
                state = efa_cluster.read_state(ETC)
                if state.get('role') != 'master':
                    return self.answer(404, {'error': 'not a master'})
                try:
                    result, changed = join(state, body)
                except PermissionError as err:
                    syslog.syslog(syslog.LOG_WARNING, f'efa-cluster join refused from {self.client_address[0]}: {err}')
                    return self.answer(403, {'error': str(err)})
                except (ValueError, RuntimeError) as err:
                    return self.answer(400, {'error': str(err)[:200]})
                efa_cluster.write_state(changed, ETC)
            syslog.syslog(syslog.LOG_INFO, f'efa-cluster node {body.get("name")} joined from {self.client_address[0]}')
            return self.answer(200, result)
        return self.answer(404, {'error': 'unknown'})


class TLSServer(ThreadingHTTPServer):
    """The TLS handshake of each connection in its own thread and with a time limit, which stays for the request: a client
    that connects and says nothing cannot stop the accept loop, nor keep a thread."""
    ssl_context = None

    def finish_request(self, request, client_address):
        request.settimeout(CONNECTION_SECONDS)
        try:
            connection = self.ssl_context.wrap_socket(request, server_side=True)
        except OSError:  # no TLS, a failed handshake or the time limit
            return
        try:
            self.RequestHandlerClass(connection, client_address, self)
        finally:
            connection.close()


def main(port):
    syslog.openlog('efa-cluster', 0, syslog.LOG_DAEMON)
    server = TLSServer(('0.0.0.0', port), Handler)
    server.ssl_context = efa_cluster.context(BASE, server=True)
    threading.Thread(target=follow, daemon=True).start()
    server.serve_forever()


def self_test():
    throttle = Throttle()
    assert all(throttle.allow('a', 100) for _ in range(JOIN_TRIES)) and not throttle.allow('a', 100) and throttle.allow('a', 200)
    state = {'role': 'master', 'name': 'm1', 'nodes': {'mx-2': {'fingerprint': 'AA'}}, 'tokens': {efa_cluster.token_hash('t1'): 1000}}
    assert member(state, 'AA') == 'mx-2' and member(state, 'BB') is None
    assert member({'role': 'client', 'master': {'fingerprint': 'CC'}}, 'CC') == 'master'
    for body, error in (({'token': 'nope', 'name': 'mx-3'}, PermissionError), ({'token': 't1', 'name': 'mx-2'}, ValueError),
                        ({'token': 't1', 'name': 'BAD NAME'}, ValueError)):
        try:
            join(state, body, now=10)
            raise AssertionError(body)
        except error:
            pass
    try:
        join(state, {'token': 't1', 'name': 'mx-3'}, now=2000)
        raise AssertionError('expired token')
    except PermissionError:
        pass
    with tempfile.TemporaryDirectory() as temp:
        journal = [{'seq': n, 'type': 'command', 'command': 'rbl-set', 'args': {'list': 'x'}} for n in range(1, 6)]
        assert [entry['seq'] for entry in journal_after(3, journal)] == [4, 5] and journal_after(9, journal) == []
        class Out:
            stdout, stderr = '{"quarantine": []}', ''
        seen = []
        assert run_for_master({'command': 'quarantine-list', 'args': {}}, lambda line, **kw: seen.append(line) or Out()) == {'quarantine': []}
        assert seen[-1][1:4] == ['--client', 'cluster-master', 'quarantine-list']
        for bad, error in (({'command': 'cluster-leave', 'args': {}}, PermissionError), ({'command': 'queue-action', 'args': {'id': 'x;rm -rf'}}, ValueError),
                           ({'command': 'queue-action', 'args': {'bad name': 'x'}}, ValueError)):
            try:
                run_for_master(bad, lambda line, **kw: Out())
                raise AssertionError(bad)
            except error:
                pass
        banned = []
        efa_cluster.f2b_ban, kept_ban = (lambda jail, address: banned.append((jail, address))), efa_cluster.f2b_ban
        count = apply_bans([{'jail': 'sshd', 'address': '203.0.113.7'}, {'jail': 'sshd', 'address': '192.0.2.10'}, {'jail': 'sshd', 'address': '127.0.0.1'},
                            {'jail': 'sshd', 'address': '198.51.100.4'}],
                           {'nodes': {'mx-2': {'host': '192.0.2.10'}}}, banned={('sshd', '198.51.100.4')})
        assert count == 1 and banned == [('efa-cluster', '203.0.113.7')], banned
        # CL-RECIDIVE: banned here in any jail (own or shared before): no second ban, so no second Ban line for recidive.
        banned.clear()
        assert apply_bans([{'jail': 'postfix-sasl', 'address': '203.0.113.7'}], {}, banned={('efa-cluster', '203.0.113.7')}) == 0 and not banned
        assert efa_cluster.merge_bans({}, {('efa-cluster', '203.0.113.8'), ('sshd', '203.0.113.9')}, 'mx-2', now=1) == {
            'sshd 203.0.113.9': {'jail': 'sshd', 'address': '203.0.113.9', 'until': 1 + efa_cluster.BAN_SECONDS, 'from': 'mx-2'}}, 'shared bans are never reported again'
        lifted = []
        efa_cluster.f2b_unban, kept_unban = lifted.append, efa_cluster.f2b_unban
        apply_bans([], {}, banned={('sshd', '198.51.100.4')}, unbanned=['198.51.100.4', '203.0.113.99'])
        efa_cluster.f2b_ban, efa_cluster.f2b_unban = kept_ban, kept_unban
        assert lifted == ['198.51.100.4'], lifted
        line = forwarded_line({'command': 'subject-set', 'args': {'text': '[A B]; rm -rf /'}, 'user': 'admin'}, 'mx-2')
        assert line[-3:] == ['subject-set', '--text', '[A B]; rm -rf /'] and 'mx-2' in line[2], 'values are arguments, never a shell'
        for bad in ({'command': '--self-test'}, {'command': 'x y'}, {'command': 'subject-set', 'args': {'te xt': '1'}}, {'command': 'subject-set', 'args': []}):
            try:
                forwarded_line(bad, 'mx-2')
                raise AssertionError(bad)
            except ValueError:
                pass
        seen = {}
        def fake_run(line, **kw):
            seen.update(kw)
            return subprocess.CompletedProcess(line, 0, '{"ok": 1}', '')
        assert run_forwarded({'command': 'subject-set', 'args': {}, 'stdin': 'pw\n'}, 'mx-2', fake_run) == {'ok': 1}
        assert seen['input'] == 'pw\n' and seen['env']['EFA_CLUSTER_FORWARDED'] == 'mx-2'
        two = {'nodes': {'a': {'applied': 4}, 'b': {'applied': 2}}}
        changed, everyone = confirm(two, 'b', 5)
        assert changed['nodes']['b']['applied'] == 5 and everyone == 4 and confirm(changed, 'b', 3)[0]['nodes']['b']['applied'] == 5
        assert command_line({'command': 'rbl-set', 'args': {'mode': 'on', 'list': 'x'}})[1:] == ['rbl-set', '--list', 'x', '--mode', 'on']
        calls = []

        class Done:
            returncode, stdout, stderr = 0, '', ''

        def fake(line, **kw):
            calls.append((line, kw.get('input')))
            return Done()
        keyfolder = os.path.join(temp, 'dkim')
        os.makedirs(keyfolder)
        with open(os.path.join(keyfolder, 'old.key'), 'w') as f:
            f.write('old')
        global ETC
        kept, ETC = ETC, temp
        files = {'type': 'files', 'files': [{'path': 'dkim/new.key', 'mode': 0o640, 'data': base64.b64encode(b'new').decode()}],
                 'mirror': ['dkim'], 'then': 'cluster-dkim-apply'}
        assert apply(files, fake) is None and os.listdir(keyfolder) == ['new.key'] and calls[-1][0][1] == 'cluster-dkim-apply'
        for bad in ('../etc/passwd', '/etc/passwd'):
            try:
                below(bad, temp)
                raise AssertionError(bad)
            except ValueError:
                pass
        ETC = kept
        assert apply({'type': 'command', 'command': 'user-set', 'args': {}, 'secrets': ['pw', 'pw']}, fake) is None and calls[-1][1] == 'pw\npw\n'
    tls_self_test()
    sync_self_test()
    started = []
    kept_popen, subprocess.Popen = subprocess.Popen, lambda line, **kw: started.append((line, kw.get('start_new_session')))
    try:
        def waited(*_args, **_kw):
            raise AssertionError('the poll waited for the transfer')
        assert apply({'type': 'command', 'command': 'cluster-sync-apply', 'args': {'kind': 'clamav'}}, waited) is None
    finally:
        subprocess.Popen = kept_popen
    sync_pull(lambda line, **kw: started.append((line, kw.get('start_new_session'))))
    assert started == [([EFACTL, 'cluster-sync-apply', '--kind', 'clamav'], True), ([EFACTL, 'cluster-sync-pull'], True)], started
    with tempfile.TemporaryDirectory() as temp:
        global SYNC_RECEIVED
        kept_received, SYNC_RECEIVED = SYNC_RECEIVED, os.path.join(temp, 'r.json')
        assert not sync_failed()
        with open(SYNC_RECEIVED, 'w') as f:
            json.dump({'clamav': {'errors': ['x'], 'files': 3}, 'fallback': {'since': 1}}, f)
        assert sync_failed()
        SYNC_RECEIVED = kept_received
        os.makedirs(os.path.join(temp, 'c'))
        before = sync_signature({'clamav': os.path.join(temp, 'c')})
        with open(os.path.join(temp, 'c', 'daily.cld'), 'w') as f:
            f.write('x')
        assert sync_signature({'clamav': os.path.join(temp, 'c')}) != before and sync_signature({'gone': os.path.join(temp, 'none')}) == []
    print('self-test ok')


def sync_self_test():
    """6.0.0.6: what the master serves (only names of its manifest, no link, nothing outside), and a real transfer over mutual
    TLS between a master and a node made here, each with its own folder (two cluster instances on one host)."""
    import hashlib
    global ETC, BASE
    kept = (ETC, BASE, dict(efa_cluster.SYNC_DIRS), efa_cluster.SYNC_MANIFEST)
    with tempfile.TemporaryDirectory() as temp:
        served = os.path.join(temp, 'served')
        os.makedirs(served)
        data = b'EFA-TEST-SIGNATURE:0:*:414243\n' * 1000
        with open(os.path.join(served, 'efa-securiteinfo-test.hdb'), 'wb') as f:
            f.write(data)
        with open(os.path.join(temp, 'secret.txt'), 'w') as f:
            f.write('outside')
        os.symlink(os.path.join(temp, 'secret.txt'), os.path.join(served, 'efa-securiteinfo-link.hdb'))
        manifest = {'kinds': {'clamav': {'efa-securiteinfo-test.hdb': {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()},
                                         'efa-securiteinfo-link.hdb': {'size': 7, 'sha256': '0' * 64}, '../secret.txt': {}, '/etc/passwd': {}}}}
        efa_cluster.SYNC_MANIFEST = os.path.join(temp, 'manifest.json')
        efa_cluster.SYNC_DIRS['clamav'] = served
        with open(efa_cluster.SYNC_MANIFEST, 'w') as f:
            json.dump(manifest, f)
        fd, size = sync_file('master', 'mx-2', '/v1/file?kind=clamav&name=efa-securiteinfo-test.hdb')
        os.close(fd)
        assert size == len(data) and sync_file('master', 'mx-2', '/v1/manifest')[1] == {**manifest, 'nodes': []}
        for role, who, path in (('master', None, '/v1/manifest'), ('master', 'master', '/v1/manifest'), ('client', 'master', '/v1/manifest'),
                                ('master', 'mx-2', '/v1/file?kind=clamav&name=../secret.txt'), ('master', 'mx-2', '/v1/file?kind=clamav&name=%2e%2e%2fsecret.txt'),
                                ('master', 'mx-2', '/v1/file?kind=clamav&name=/etc/passwd'), ('master', 'mx-2', '/v1/file?kind=clamav&name=%2Fetc%2Fpasswd'),
                                ('master', 'mx-2', '/v1/file?kind=clamav&name=secret.txt'), ('master', 'mx-2', '/v1/file?kind=clamav&name=efa-securiteinfo-link.hdb'),
                                ('master', 'mx-2', '/v1/file?kind=other&name=efa-securiteinfo-test.hdb'),
                                ('master', 'mx-2', '/v1/file?kind=clamav&name=efa-securiteinfo-test.hdb&name=x')):
            try:
                sync_file(role, who, path)
                raise AssertionError(path)
            except PermissionError:
                pass
        # Two cluster instances: a master with its CA and a node with a certificate from it; a stranger with another CA.
        master_etc, node_etc, other = os.path.join(temp, 'm'), os.path.join(temp, 'n'), os.path.join(temp, 'o')
        for etc in (master_etc, node_etc, other):
            os.makedirs(efa_cluster.folder(etc))
        mbase, nbase, obase = efa_cluster.folder(master_etc), efa_cluster.folder(node_etc), efa_cluster.folder(other)
        efa_cluster.make_ca(mbase, 'm1')
        with open(os.path.join(mbase, 'node.crt'), 'w') as f:
            f.write(efa_cluster.sign(mbase, efa_cluster.make_request(mbase, 'm1'), 'm1'))
        node_cert = efa_cluster.sign(mbase, efa_cluster.make_request(nbase, 'mx-2'), 'mx-2')
        with open(os.path.join(nbase, 'node.crt'), 'w') as f:
            f.write(node_cert)
        shutil.copy(os.path.join(mbase, 'ca.crt'), os.path.join(nbase, 'ca.crt'))
        efa_cluster.make_ca(obase, 'x1')
        with open(os.path.join(obase, 'node.crt'), 'w') as f:
            f.write(efa_cluster.sign(obase, efa_cluster.make_request(obase, 'mx-9'), 'mx-9'))
        shutil.copy(os.path.join(mbase, 'ca.crt'), os.path.join(obase, 'ca.crt'))  # trusts the master, shows a foreign certificate
        # A certificate from the right CA whose node is not (or no longer) listed, such as a removed node.
        gone_etc = os.path.join(temp, 'g')
        os.makedirs(efa_cluster.folder(gone_etc))
        gbase = efa_cluster.folder(gone_etc)
        with open(os.path.join(gbase, 'node.crt'), 'w') as f:
            f.write(efa_cluster.sign(mbase, efa_cluster.make_request(gbase, 'mx-7'), 'mx-7'))
        shutil.copy(os.path.join(mbase, 'ca.crt'), os.path.join(gbase, 'ca.crt'))
        efa_cluster.write_state({'role': 'master', 'name': 'm1', 'nodes': {'mx-2': {'fingerprint': efa_cluster.fingerprint_pem(node_cert)}}}, master_etc)
        ETC, BASE = master_etc, mbase
        server = TLSServer(('127.0.0.1', 0), Handler)
        server.ssl_context = efa_cluster.context(mbase, server=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        with open(os.path.join(mbase, 'node.crt')) as f:
            expected = efa_cluster.fingerprint_pem(f.read())
        port = server.server_address[1]
        try:
            got = os.path.join(temp, 'got.hdb')
            assert efa_cluster.call(nbase, '127.0.0.1', port, '/v1/manifest', expected=expected) == {**manifest, 'nodes': ['mx-2']}
            assert efa_cluster.fetch_file(nbase, '127.0.0.1', port, '/v1/file?kind=clamav&name=efa-securiteinfo-test.hdb', got, len(data),
                                          expected=expected) == (len(data), hashlib.sha256(data).hexdigest())
            for path in ('/v1/file?kind=clamav&name=%2e%2e%2fsecret.txt', '/v1/file?kind=clamav&name=efa-securiteinfo-link.hdb'):
                try:
                    efa_cluster.fetch_file(nbase, '127.0.0.1', port, path, got + '.x', len(data), expected=expected)
                    raise AssertionError(path)
                except OSError as err:
                    assert 'HTTP 404' in str(err), err
            try:
                efa_cluster.fetch_file(nbase, '127.0.0.1', port, '/v1/file?kind=clamav&name=efa-securiteinfo-test.hdb', got + '.x', 100, expected=expected)
                raise AssertionError('more than the limit')
            except OSError:
                pass
            try:
                efa_cluster.call(obase, '127.0.0.1', port, '/v1/manifest', expected=expected)
                raise AssertionError('a foreign certificate')
            except OSError:  # the handshake fails: the certificate is not from the CA of this cluster
                pass
            plain = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            plain.check_hostname, plain.verify_mode = False, ssl.CERT_NONE
            import http.client
            connection = http.client.HTTPSConnection('127.0.0.1', port, timeout=10, context=plain)
            connection.request('GET', '/v1/file?kind=clamav&name=efa-securiteinfo-test.hdb')
            assert connection.getresponse().status == 403, 'no certificate, no file'
            try:
                efa_cluster.call(gbase, '127.0.0.1', port, '/v1/manifest', expected=expected)
                raise AssertionError('a node that is not listed got the manifest')
            except OSError as err:
                assert getattr(err, 'code', None) == 403, err
            try:
                efa_cluster.fetch_file(gbase, '127.0.0.1', port, '/v1/file?kind=clamav&name=efa-securiteinfo-test.hdb', got + '.g', len(data), expected=expected)
                raise AssertionError('a node that is not listed got a file')
            except OSError as err:
                assert 'HTTP 403' in str(err) and not os.path.exists(got + '.g'), err
            # POST /v1/lookalike: a certificate of the CA that is not listed gets 403, so does a list that is no list; a body over
            # MAX_BODY gets 413 before it is read (only its length is sent: the server closes without reading it).
            for who, body, code in ((gbase, {'hits': []}, 403), (nbase, {'hits': 'no list'}, 403)):
                try:
                    efa_cluster.call(who, '127.0.0.1', port, '/v1/lookalike', body=body, expected=expected)
                    raise AssertionError(('lookalike', code))
                except OSError as err:
                    assert getattr(err, 'code', None) == code, (code, err)
            big = http.client.HTTPSConnection('127.0.0.1', port, timeout=10, context=efa_cluster.context(nbase))
            big.putrequest('POST', '/v1/lookalike')
            big.putheader('Content-Type', 'application/json')
            big.putheader('Content-Length', str(MAX_BODY + 1))
            big.endheaders()
            assert big.getresponse().status == 413, 'a body over MAX_BODY'
            big.close()
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            ETC, BASE, dirs, efa_cluster.SYNC_MANIFEST = kept
            efa_cluster.SYNC_DIRS.clear()
            efa_cluster.SYNC_DIRS.update(dirs)


def tls_self_test():
    """A client that connects to 8460 and says nothing must not stop the next one."""
    global CONNECTION_SECONDS
    saved, CONNECTION_SECONDS = CONNECTION_SECONDS, 1
    server = TLSServer(('127.0.0.1', 0), BaseHTTPRequestHandler)
    server.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    silent = socket.create_connection(server.server_address, timeout=5)
    try:
        started = time.time()
        with socket.create_connection(server.server_address, timeout=5) as other:
            other.sendall(b'no TLS\r\n\r\n')
            try:
                other.recv(100)  # closed after the failed handshake
            except OSError:
                pass
        assert time.time() - started < 4, 'the second client waited for the silent one'
    finally:
        silent.close()
        server.shutdown()
        server.server_close()
        CONNECTION_SECONDS = saved


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
    else:
        main(int(sys.argv[sys.argv.index('--port') + 1]) if '--port' in sys.argv else efa_cluster.read_state(ETC).get('port', efa_cluster.PORT))
