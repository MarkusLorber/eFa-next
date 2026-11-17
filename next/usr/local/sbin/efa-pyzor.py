#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""eFa-next Pyzor (G7-5): asks a Pyzor server how often the checksum of a mail was reported as spam, on 127.0.0.1:8912.
rspamd posts the raw mail; the answer is {'state': 'hit' | 'clean' | 'error', 'count', 'wl'}. Only the checksum (digest) leaves
the host, never the mail or an address: the program pyzor of EPEL makes it and asks the server. It runs as a program of its own
for each mail (GPL-2.0, kept apart from this AGPL code), at most 4 at a time; answers stay 10 minutes in memory, so a mail to
many recipients asks once. A mail waits at most 3 seconds (pyzor -t 2, rspamd gives up after 3); after 3 failures in a row
the service pauses Pyzor for 5 minutes and says so in state.json, so a slow or dead server never delays every mail (R7-5).
Off by default; this service runs only while Pyzor is on (efactl pyzor-set)."""
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8912
# The settings come as a credential of systemd (LoadCredential): the service user cannot read /etc/eFa.
CONF = os.path.join(os.environ.get('CREDENTIALS_DIRECTORY', '/etc/eFa'), 'pyzor.json')
HOME = os.environ.get('RUNTIME_DIRECTORY', '/run/efa-pyzor')
PYZOR = '/usr/bin/pyzor'
MAX_MAIL = 2 * 1024 * 1024
MIN_COUNT = 5
KEEP, CACHE_MAX = 600, 5000
DEFAULT_SERVER = 'public.pyzor.org:24441'
# R7-5: the answer of the server within 2 s, the program within 3 s; a free slot within 1 s. 3 failures in a row pause 5 minutes.
SERVER_TIMEOUT, RUN_TIMEOUT, SLOT_WAIT = 2, 3, 1
BREAK_AFTER, BREAK_FOR = 3, 300
lock = threading.Lock()
running = threading.BoundedSemaphore(4)
cache = {}
breaker = {'errors': 0, 'paused_until': 0, 'last_error': ''}


class Busy(Exception):
    """All 4 slots taken: this mail goes on without Pyzor; not a failure of the server."""


def server_of(conf):
    """host:port of the Pyzor server from the settings."""
    return str((conf or {}).get('server') or DEFAULT_SERVER)


def parse(output):
    """(count, wl) from the line of pyzor check: server, (code, text), count and whitelist count, tab separated."""
    for line in output.splitlines():
        fields = line.split('\t')
        if len(fields) >= 4 and fields[1].startswith('(200,'):
            return int(fields[2]), int(fields[3])
    raise ValueError('no answer of the Pyzor server')


def pyzor_check(raw, server, run=subprocess.run):
    """Runs pyzor check on the mail, with only this server in its list."""
    servers = os.path.join(HOME, 'servers')
    with lock:
        if not os.path.exists(servers) or open(servers).read() != server + '\n':
            with open(servers + '.tmp', 'w') as f:
                f.write(server + '\n')
            os.replace(servers + '.tmp', servers)
    if not running.acquire(timeout=SLOT_WAIT):
        raise Busy()
    try:
        done = run([PYZOR, '--homedir', HOME, '--servers-file', servers, '-t', str(SERVER_TIMEOUT), 'check'], input=raw,
                   capture_output=True, timeout=RUN_TIMEOUT)
    finally:
        running.release()
    # pyzor check ends with 1 for a mail that is not spam; the line says what the server answered.
    return parse(done.stdout.decode('utf-8', 'replace'))


def verdict(count, wl):
    """hit from MIN_COUNT reports on, unless the checksum was also whitelisted."""
    return {'state': 'hit' if count >= MIN_COUNT and not wl else 'clean', 'count': count, 'wl': wl}


def save_state():
    """state.json in the runtime directory: efactl pyzor-status and the dashboard read the pause from it (root reads it)."""
    try:
        with open(os.path.join(HOME, 'state.json.tmp'), 'w') as f:
            json.dump(breaker, f)
        os.replace(os.path.join(HOME, 'state.json.tmp'), os.path.join(HOME, 'state.json'))
    except OSError:
        pass


def failed(now, err):
    """One more failure in a row; the third pauses Pyzor for BREAK_FOR seconds."""
    with lock:
        breaker['errors'] += 1
        breaker['last_error'] = (type(err).__name__ + ': ' + str(err))[:200]
        if breaker['errors'] >= BREAK_AFTER:
            breaker.update(errors=0, paused_until=now + BREAK_FOR)
            save_state()


def ask(raw, conf, now=None, check=pyzor_check):
    now = time.time() if now is None else now
    if not raw or len(raw) > MAX_MAIL:
        return {'state': 'error', 'count': 0, 'wl': 0}
    key = hashlib.sha256(raw).hexdigest()
    with lock:
        item = cache.get(key)
        if item and now - item[0] < KEEP:
            return item[1]
        if now < breaker['paused_until']:
            return {'state': 'paused', 'count': 0, 'wl': 0}
    try:
        result = verdict(*check(raw, server_of(conf)))
    except Busy:
        return {'state': 'error', 'count': 0, 'wl': 0}
    except Exception as err:  # timeout, no network, no program, a bad answer of the server: never a failure of the mail
        failed(now, err)
        return {'state': 'error', 'count': 0, 'wl': 0}
    with lock:
        if breaker['errors'] or breaker['paused_until']:
            breaker.update(errors=0, paused_until=0, last_error='')
            save_state()
        if len(cache) >= CACHE_MAX:
            for old in [old for old, (at, _) in cache.items() if now - at >= KEEP] or list(cache)[:CACHE_MAX // 2]:
                cache.pop(old, None)
        cache[key] = (now, result)
    return result


def settings():
    try:
        with open(CONF) as f:
            conf = json.load(f)
    except (OSError, ValueError):
        return None
    return conf if conf.get('enabled') else None


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        if self.path != '/check' or not 0 < length <= MAX_MAIL:
            self.send_error(413 if self.path == '/check' else 404)
            return
        raw = self.rfile.read(length)
        conf = settings()
        result = ask(raw, conf) if conf else {'state': 'error', 'count': 0, 'wl': 0}
        body = json.dumps(result).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def self_test():
    import tempfile
    global HOME
    asked = []

    def check(raw, server):
        asked.append((raw, server))
        return {b'one': (12, 0), b'two': (12, 3), b'three': (2, 0)}[raw]
    conf = {'enabled': True, 'server': 'pyzor.example.eu:24441'}
    assert server_of(conf) == 'pyzor.example.eu:24441' and server_of({}) == 'public.pyzor.org:24441'
    assert ask(b'one', conf, 1000, check) == {'state': 'hit', 'count': 12, 'wl': 0}
    assert ask(b'one', conf, 1100, check)['state'] == 'hit' and len(asked) == 1, 'known: asked once'
    assert ask(b'one', conf, 1000 + KEEP + 1, check)['state'] == 'hit' and len(asked) == 2, 'after 10 minutes again'
    assert ask(b'two', conf, 1000, check)['state'] == 'clean', 'whitelisted too: no hit'
    assert ask(b'three', conf, 1000, check) == {'state': 'clean', 'count': 2, 'wl': 0}
    assert asked[0][1] == 'pyzor.example.eu:24441'
    assert ask(b'', conf, 0, check)['state'] == 'error' and ask(b'x' * (MAX_MAIL + 1), conf, 0, check)['state'] == 'error'

    def broken(*_args):
        raise OSError('timeout')
    HOME = tempfile.mkdtemp()
    assert ask(b'four', conf, 0, broken)['state'] == 'error'
    # R7-5: the third failure in a row pauses; during the pause no mail waits for the server, then it is asked again.
    assert ask(b'five', conf, 1, broken)['state'] == 'error' and ask(b'six', conf, 2, broken)['state'] == 'error'
    assert breaker['paused_until'] == 2 + BREAK_FOR and json.load(open(HOME + '/state.json'))['paused_until'] == 2 + BREAK_FOR
    assert ask(b'seven', conf, 100, lambda *_: (_ for _ in ()).throw(AssertionError('asked while paused')))['state'] == 'paused'
    assert ask(b'seven', conf, 3 + BREAK_FOR, check=lambda raw, server: (0, 0))['state'] == 'clean'
    assert breaker == {'errors': 0, 'paused_until': 0, 'last_error': ''} and json.load(open(HOME + '/state.json'))['paused_until'] == 0

    def busy(*_args):
        raise Busy()
    for _ in range(BREAK_AFTER + 1):
        assert ask(b'eight', conf, 4 + BREAK_FOR, busy)['state'] == 'error'
    assert breaker['paused_until'] == 0, 'a full host is no failure of the server'
    # The output of pyzor check, as its client writes it.
    assert parse("public.pyzor.org:24441\t(200, 'OK')\t7\t0\n") == (7, 0)
    for bad in ("public.pyzor.org:24441\t(504, 'Timeout')\n", '', 'junk'):
        try:
            parse(bad)
            raise AssertionError(bad)
        except ValueError:
            pass
    HOME = tempfile.mkdtemp()
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs['input']))
        return subprocess.CompletedProcess(command, 1, b"pyzor.example.eu:24441\t(200, 'OK')\t0\t0\n", b'')
    assert pyzor_check(b'mail', 'pyzor.example.eu:24441', run) == (0, 0)
    assert calls[0][0][-1] == 'check' and calls[0][1] == b'mail' and open(HOME + '/servers').read() == 'pyzor.example.eu:24441\n'
    assert calls[0][0][-3:-1] == ['-t', '2'], 'the server gets 2 seconds'
    cache.clear()
    for number in range(CACHE_MAX + 10):
        ask(f'm{number}'.encode(), conf, 5000, lambda raw, server: (0, 0))
    assert len(cache) <= CACHE_MAX, 'the cache stays small'
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
    else:
        ThreadingHTTPServer(('127.0.0.1', PORT), Handler).serve_forever()
