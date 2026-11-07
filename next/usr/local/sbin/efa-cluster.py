#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""eFa cluster service (9): HTTPS on the cluster port, only TLS 1.2+ with certificates on both sides from the CA of the master.
Without a certificate only two requests are open: the CA (public anyway) and, on the master, the join with a one-time token.
Every other request needs the certificate of a known member: the master of a client, a node of the master.

    efa-cluster.py [--port N]     EFA_ETC moves the folder of the cluster files (a second node on one test host)
"""
import base64
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import syslog
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

for _folder in ('/usr/lib/eFa/python', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'lib', 'eFa', 'python')):
    if os.path.isdir(_folder) and _folder not in sys.path:
        sys.path.insert(0, _folder)
import efa_cluster  # noqa: E402

ETC = os.environ.get('EFA_ETC', '/etc')
BASE = efa_cluster.folder(ETC)
MAX_BODY = 64 * 1024
JOIN_TRIES = 10  # per address and minute
FETCH_SECONDS = 30
# Handshake and request of one connection: snapshots and journals of the master are larger.
CONNECTION_SECONDS = 120
# What the master may run on a node, for the view over all nodes (9c): mail log, quarantine, queue, and their actions.
MASTER_RUNS = {'maillog-search', 'quarantine-list', 'quarantine-show', 'quarantine-release', 'quarantine-delete',
               'queue-list', 'queue-show', 'queue-action', 'status'}
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
    for address in sorted(set(unbanned) & {address for _jail, address in have}):
        efa_cluster.f2b_unban(address)
    networks, count = protected_networks(state), 0
    for item in bans:
        if (item['jail'], item['address']) not in have and not efa_cluster.protected(item['address'], networks):
            efa_cluster.f2b_ban(item['jail'], item['address'])
            count += 1
    return count


def share_bans(state):
    """Every half minute: the master takes its own bans into the table; a client reports its bans and takes those of the others."""
    own = {(jail, address) for jail, address in efa_cluster.f2b_banned() if not efa_cluster.protected(address, protected_networks(state))}
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


def live_unbans(state):
    return [address for address, until in state.get('unbans', {}).items() if until > time.time()]


def follow():
    """Every half minute: the bans of the cluster; on a client the new entries of the master, applied in order. A failed one is
    noted and skipped."""
    while True:
        time.sleep(FETCH_SECONDS)
        state = efa_cluster.read_state(ETC)
        try:
            share_bans(state)
        except (OSError, ValueError, KeyError) as err:
            syslog.syslog(syslog.LOG_WARNING, f'efa-cluster bans not shared: {err}')
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
    try:
        with open('/etc/eFa-Version') as f:
            version = f.read().strip()
    except OSError:
        version = ''
    state = efa_cluster.read_state(ETC)
    return {'status': status.get('status'), 'down': status.get('down', []), 'version': version, 'time': int(time.time()),
            'applied': state.get('applied', 0), 'failed': state.get('failed', [])[-5:]}


class Handler(BaseHTTPRequestHandler):
    throttle = Throttle()
    lock = threading.Lock()
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
        if self.path.startswith('/v1/journal?after=') and efa_cluster.read_state(ETC).get('role') == 'master':
            after = self.path.split('=', 1)[1]
            return self.answer(200, {'entries': journal_after(int(after) if after.isdigit() else 0),
                                     'mode': efa_cluster.read_state(ETC).get('mode', 'master-client')})
        return self.answer(404, {'error': 'unknown'})

    def do_POST(self):
        value = (self.headers.get('Content-Length') or '0').strip()
        # -1 would read to the end: the join is open without a certificate.
        if not (value.isascii() and value.isdigit()):
            return self.answer(400, {'error': 'bad Content-Length'})
        length = int(value)
        if length > MAX_BODY:
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
    import tempfile
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
        assert count == 1 and banned == [('sshd', '203.0.113.7')], banned
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
    print('self-test ok')


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
