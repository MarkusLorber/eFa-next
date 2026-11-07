#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The only way of the user portal (efa-portal) into eFa (5q): a Unix socket that takes a few fixed efactl commands.

The portal runs without sudo and cannot read the settings. This helper runs as root, knows which login a portal session
belongs to, runs efactl for that login only (--as, so efactl checks the rights of the role user a second time) and refuses
every admin role. A portal taken over can so do what its logged-in users may do, and nothing else.

    efa-portal-helper.py [--socket PATH] [--self-test]
"""
import hashlib
import json
import os
import secrets
import socket
import socketserver
import subprocess
import sys
import syslog
import threading
import time

SOCKET = '/run/efa-portal-helper/helper.sock'
EFACTL = os.environ.get('EFA_EFACTL', '/usr/sbin/efactl')
ETC = os.environ.get('EFA_ETC', '/etc')
CONTENT_FILE = ETC + '/efa-web/content.json'
MAX_REQUEST = 256 * 1024
SESSION_SECONDS = 8 * 3600
# What a logged-in user may run through the portal; efactl checks the role on top.
USER_COMMANDS = {'schema', 'settings', 'whoami', 'my-settings', 'my-settings-set', 'uq-list', 'uq-show', 'uq-release', 'uq-request',
                 'uq-sender', 'uq-delete', 'train-request', 'audit-note'}
# Before a login: the password check, the links of the digests, whether SSO is on.
OPEN_COMMANDS = {'user-verify', 'uq-link-view', 'uq-link-use', 'oidc-status'}
# The portal never sets who acts: these come from the helper only.
OWN_OPTIONS = ('--as', '--session', '--client', '--limit-tenant')
ROLE = 'user'
SESSION_COMMANDS = {'session-open', 'session-check', 'session-end'}


class Sessions:
    """The portal sessions of this helper: random id, the login, and when it ends. Lost on a restart: then users log in again."""

    def __init__(self):
        self.lock, self.items = threading.Lock(), {}

    def start(self, user, now=None):
        now = time.time() if now is None else now
        sid = secrets.token_urlsafe(32)
        with self.lock:
            self.items = {key: item for key, item in self.items.items() if item[1] > now}
            self.items[sid] = (user, now + SESSION_SECONDS)
        return sid

    def user(self, sid, now=None):
        now = time.time() if now is None else now
        with self.lock:
            item = self.items.get(sid or '')
            return item[0] if item and item[1] > now else None

    def end(self, sid):
        with self.lock:
            self.items.pop(sid or '', None)


def sha(sid):
    return hashlib.sha256(sid.encode()).hexdigest()


# efactl loaded once (as efactl-runner does), one fork per call: a new Python per call took 0.2 s, a portal page 0.8 s.
# None in a source tree or a test: then a process per call, as before.
FORKED = None
CALLER = 'efa-portal'
RUNNER = '/usr/local/sbin/efactl-runner.py'


def load_forked():
    import importlib.util
    spec = importlib.util.spec_from_file_location('efactl_runner', RUNNER)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    return runner, runner.load_efactl()


def forked_call(runner, main, argv, secrets_in):
    """One efactl call in a fork of this process, with the environment and limits of efactl-runner."""
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(read)
            reply = runner.run_call({'args': argv, 'secrets': list(secrets_in)}, main, CALLER)
            with os.fdopen(write, 'wb') as out:
                out.write(json.dumps(reply).encode())
        finally:
            os._exit(0)
    os.close(write)
    with os.fdopen(read, 'rb') as f:
        data = f.read()
    os.waitpid(pid, 0)
    try:
        reply = json.loads(data)
        return reply['code'] == 0, json.loads(reply['stdout'])
    except (ValueError, KeyError, TypeError):
        return False, {'error': 'efactl failed, see the log.'}


def efactl(args, secrets_in=(), user=None, sid=None, client=''):
    who = ([f'--as={user}'] if user else []) + ([f'--session={sha(sid)}'] if sid else [])
    if FORKED:
        return forked_call(*FORKED, [f'--client={client}'] + who + list(args), secrets_in)
    done = subprocess.run([EFACTL, f'--client={client}'] + who + list(args), capture_output=True, text=True, timeout=120,
                          input=''.join(line + '\n' for line in secrets_in), env={**os.environ, 'SUDO_USER': 'efa-portal'})
    try:
        return done.returncode == 0, json.loads(done.stdout)
    except ValueError:
        return False, {'error': 'efactl failed, see the log.'}


def link_target(token):
    """The target of a link of a mail, and how to act when it cannot be checked. The link key stays here."""
    sys.path.insert(0, '/usr/lib/eFa/python')
    import efa_links
    try:
        with open(CONTENT_FILE) as f:
            links = json.load(f).get('links', {})
    except (OSError, ValueError):
        links = {}
    target = efa_links.link_target(token, bytes.fromhex(links['key'])) if links.get('key') else None
    return {'target': target, 'unchecked': links.get('unchecked', 'page'), 'continue': links.get('continue', True)}


def handle(request, sessions, run=efactl):
    """One request of the portal: {'args': [...], 'secrets': [...], 'sid': ..., 'client': ...}. Returns (ok, answer)."""
    args, secrets_in = request.get('args'), request.get('secrets', [])
    sid, client = request.get('sid'), str(request.get('client', ''))[:64]
    if not isinstance(args, list) or not args or not all(isinstance(item, str) for item in args) or not isinstance(secrets_in, list):
        return False, {'error': 'Bad request.'}
    if args[0] in SESSION_COMMANDS and sid:
        # The session these name is always the own one.
        args = [args[0]] + [item for item in args[1:] if not item.startswith('--session=')] + [f'--session={sha(sid)}']
    elif any(item.split('=', 1)[0] in OWN_OPTIONS for item in args) or any('\n' in item or '\x00' in item for item in args + secrets_in):
        return False, {'error': 'Bad request.'}
    if not all(isinstance(item, str) for item in secrets_in):
        return False, {'error': 'Bad request.'}
    name = args[0]
    if name == 'link-target':
        return True, link_target(args[1] if len(args) > 1 else '')
    if name in OPEN_COMMANDS:
        ok, answer = run(args, secrets_in, client=client)
        if not ok:
            return ok, answer
        # A login of an admin role is refused here: admins log in at the admin interface, never in the portal.
        login = name == 'user-verify' or (name == 'uq-link-use' and answer.get('purpose') == 'login')
        if login:
            if answer.get('role') != ROLE:
                return False, {'error': 'Use the admin interface for this account.'}
            answer['sid'] = sessions.start(answer['username'])
        return ok, answer
    user = sessions.user(sid)
    if user is None:
        return False, {'error': 'Not logged in.'}
    if name not in USER_COMMANDS | SESSION_COMMANDS:
        return False, {'error': 'Not available in the portal.'}
    ok, answer = run(args, secrets_in, user=user, sid=sid, client=client)
    if name == 'session-end' or (name == 'session-check' and ok and not answer.get('active')):
        sessions.end(sid)
    return ok, answer


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def serve(path):
    global FORKED
    sessions = Sessions()
    if 'EFA_EFACTL' not in os.environ:
        try:
            FORKED = load_forked()
        except (ImportError, OSError) as err:  # no installed efactl module: a process per call
            syslog.syslog(syslog.LOG_WARNING, f'efactl not loaded, one process per call: {err}')

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            data = self.rfile.readline(MAX_REQUEST + 1)
            try:
                if len(data) > MAX_REQUEST:
                    raise ValueError('too large')
                ok, answer = handle(json.loads(data), sessions)
            except (ValueError, TypeError, AttributeError) as err:
                ok, answer = False, {'error': f'Bad request: {str(err)[:80]}'}
            self.wfile.write(json.dumps({'ok': ok, 'answer': answer}).encode() + b'\n')

    if os.path.exists(path):
        os.remove(path)
    server = Server(path, Handler)
    os.chmod(path, 0o660)
    syslog.syslog(syslog.LOG_INFO, f'efa-portal-helper listening on {path}')
    server.serve_forever()


def self_test():
    calls = []

    def run(args, secrets_in=(), user=None, sid=None, client=''):
        calls.append((list(args), user))
        if args[0] == 'user-verify':
            return True, {'username': 'a@x.example' if secrets_in == ['good'] else 'boss', 'role': 'user' if secrets_in == ['good'] else 'super'}
        if args[0] == 'uq-link-use':
            return True, {'purpose': 'login', 'username': 'b@x.example', 'role': 'user'}
        return True, {'active': True, 'ran': args[0]}
    sessions = Sessions()
    ok, answer = handle({'args': ['user-verify', '--username=boss'], 'secrets': ['admin']}, sessions, run)
    assert not ok and 'admin interface' in answer['error'] and not sessions.items, 'no portal session for an admin role'
    ok, answer = handle({'args': ['user-verify', '--username=a@x.example'], 'secrets': ['good']}, sessions, run)
    assert ok and sessions.user(answer['sid']) == 'a@x.example'
    sid = answer['sid']
    assert handle({'args': ['uq-list'], 'sid': sid}, sessions, run)[0] and calls[-1] == (['uq-list'], 'a@x.example')
    assert handle({'args': ['uq-list'], 'sid': 'forged'}, sessions, run) == (False, {'error': 'Not logged in.'})
    for refused in (['transport-set', '--domain=x'], ['backup-now'], ['user-set', '--username=a'], ['token-create']):
        assert handle({'args': refused, 'sid': sid}, sessions, run) == (False, {'error': 'Not available in the portal.'}), refused
    for forged in (['uq-list', '--as=boss'], ['uq-list', '--session=x'], ['uq-list', '--client=1.2.3.4'], ['uq-show', '--id=1\n--as=x']):
        assert not handle({'args': forged, 'sid': sid}, sessions, run)[0], forged
    assert not handle({'args': 'uq-list', 'sid': sid}, sessions, run)[0] and not handle({'args': [], 'sid': sid}, sessions, run)[0]
    ok, answer = handle({'args': ['uq-link-use'], 'secrets': ['tok']}, sessions, run)
    assert ok and sessions.user(answer['sid']) == 'b@x.example', 'a login link of a digest opens a portal session'
    handle({'args': ['session-end'], 'sid': sid}, sessions, run)
    assert sessions.user(sid) is None
    handle({'args': ['session-check', '--session=someone-else'], 'sid': answer['sid']}, sessions, run)
    assert calls[-1][0] == ['session-check', f"--session={sha(answer['sid'])}"], 'only the own session'
    old = Sessions()
    assert old.user(old.start('x', now=0)) is None, 'a session ends'
    # The forked way, with a stand-in for efactl: arguments, stdin and the exit code come back as from a process.
    import pwd
    global CALLER
    CALLER = pwd.getpwuid(os.getuid()).pw_name

    class StandIn:
        @staticmethod
        def run_call(request, main, caller):
            return {'code': 0 if request['args'][-1] != 'fail' else 1, 'stdout': json.dumps({'args': request['args'], 'secrets': request['secrets'],
                                                                                       'caller': caller}), 'stderr': ''}
    ok, answer = forked_call(StandIn, None, ['--client=1', 'uq-list'], ['s'])
    assert ok and answer == {'args': ['--client=1', 'uq-list'], 'secrets': ['s'], 'caller': CALLER}
    assert not forked_call(StandIn, None, ['fail'], [])[0]
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
        sys.exit(0)
    serve(sys.argv[sys.argv.index('--socket') + 1] if '--socket' in sys.argv else SOCKET)
