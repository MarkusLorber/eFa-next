#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""eFa-next SASL (5u): checks the SMTP-AUTH logins of port 587 for Postfix, in place of Dovecot.

Postfix asks on port 587 over the Unix socket /run/efa-sasl/auth with the Dovecot authentication protocol 1.x
(smtpd_sasl_type = dovecot, smtpd_sasl_path of the submission service). This service answers that protocol and nothing else: the mechanisms PLAIN and LOGIN, only on a
TLS connection (Postfix marks it "secured"), against the logins of the submitters (efactl submitter-set). No TCP, no mailboxes,
no system accounts. systemd opens the socket (efa-sasl.socket) and starts this service at the first login; it ends itself
after a while without connections.

    efa-sasl.py [--self-test]
"""
import base64
import hashlib
import hmac
import os
import re
import secrets
import socket
import sys
import syslog
import threading
import time

# The copy next to this program first (a checkout in CI), then the installed one: insert(0) puts the last one in front.
for _folder in ('/usr/lib/eFa/python', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'lib', 'eFa', 'python')):
    if os.path.isdir(_folder) and _folder not in sys.path:
        sys.path.insert(0, _folder)
import efa_shacrypt  # noqa: E402

PASSWD = os.environ.get('EFA_SASL_PASSWD', '/etc/efa-sasl/logins')  # written by efactl (submitter-set), root:efa-sasl 0640
MAX_PENDING = 64
MAX_LINE = 8192
MAX_CONNECTIONS = 32
IDLE_SECONDS = 600
READ_SECONDS = 300
FAIL_DELAY = 2.0
# Per login name and per client address: this many failures in the window, then every try fails at once.
FAIL_LIMIT, FAIL_WINDOW = 5, 600
USER_RE = re.compile(r'^[^\x00-\x20\x7f:]{1,256}$')
CHALLENGES = {'LOGIN': (base64.b64encode(b'Username:').decode(), base64.b64encode(b'Password:').decode())}


def verify(password, stored):
    """A password against a stored hash: {SCRYPT}N$r$p$salt$hash (base64) or {SHA512-CRYPT}$6$... Constant-time compare."""
    if stored.startswith('{SCRYPT}'):
        try:
            n, r, p, salt, digest = stored[8:].split('$')
            want = base64.b64decode(digest)
            got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=len(want),
                                 maxmem=128 * 1024 * 1024)
        except (ValueError, TypeError):
            return False
        return hmac.compare_digest(got, want)
    if stored.startswith('{SHA512-CRYPT}$6$'):
        # PY-1: in plain Python, the crypt module of Python is gone from 3.13 on.
        return efa_shacrypt.verify(password, stored[14:])
    return False


def scrypt_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 15, r=8, p=1, dklen=32, maxmem=128 * 1024 * 1024)
    return '{SCRYPT}%d$%d$%d$%s$%s' % (2 ** 15, 8, 1, base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


DUMMY = scrypt_hash('-', b'0' * 16)


class Logins:
    """The logins of the file, read again when it changes."""

    def __init__(self, path=PASSWD):
        self.path, self.mtime, self.items, self.lock = path, None, {}, threading.Lock()

    def get(self, user):
        with self.lock:
            try:
                mtime = os.stat(self.path).st_mtime
            except OSError:
                self.items, self.mtime = {}, None
                return None
            if mtime != self.mtime:
                items = {}
                with open(self.path) as f:
                    for line in f:
                        name, _, stored = line.rstrip('\n').partition(':')
                        if name and stored:
                            items[name] = stored.split(':')[0]
                self.items, self.mtime = items, mtime
            return self.items.get(user)


class Limiter:
    def __init__(self):
        self.lock, self.failures = threading.Lock(), {}

    def blocked(self, keys, now=None):
        now = time.time() if now is None else now
        with self.lock:
            return any(len([moment for moment in self.failures.get(key, []) if now - moment < FAIL_WINDOW]) >= FAIL_LIMIT for key in keys)

    def failed(self, keys, now=None):
        now = time.time() if now is None else now
        with self.lock:
            for key in keys:
                self.failures[key] = [moment for moment in self.failures.get(key, []) if now - moment < FAIL_WINDOW][-FAIL_LIMIT:] + [now]
            if len(self.failures) > 10000:
                self.failures = {key: times for key, times in self.failures.items() if times and now - times[-1] < FAIL_WINDOW}


def check(user, password, client, logins, limiter, delay=FAIL_DELAY):
    """(ok, reason): the login of a submitter. Unknown names cost the same time as wrong passwords."""
    keys = ('user:' + user, 'ip:' + client)
    if limiter.blocked(keys):
        syslog.syslog(syslog.LOG_WARNING, f'efa-sasl: too many failed logins for {user[:64]} from {client}')
        time.sleep(delay)
        return False, 'Too many failed logins, try again later.'
    stored = logins.get(user) if USER_RE.fullmatch(user) else None
    ok = verify(password, stored or DUMMY) and stored is not None
    if not ok:
        limiter.failed(keys)
        # Fail2Ban reads this line; Postfix logs its own "SASL ... authentication failed" too.
        syslog.syslog(syslog.LOG_WARNING, f'efa-sasl: login failed for {user[:64]} from {client}')
        time.sleep(delay)
        return False, 'Authentication failed.'
    return True, ''


def b64(text):
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, TypeError):
        return None


class Session:
    """One connection of Postfix. Postfix sends AUTH and CONT lines; this answers CONT, OK or FAIL."""

    def __init__(self, logins, limiter, delay=FAIL_DELAY):
        self.logins, self.limiter, self.delay = logins, limiter, delay
        self.pending, self.version_ok = {}, False

    @staticmethod
    def greeting(cuid):
        return (f'VERSION\t1\t2\nMECH\tPLAIN\tplaintext\nMECH\tLOGIN\tplaintext\nSPID\t{os.getpid()}\nCUID\t{cuid}\n'
                f'COOKIE\t{secrets.token_hex(16)}\nDONE\n')

    def line(self, text):
        """One line from Postfix, without its newline. Returns the answer lines; None closes the connection."""
        fields = text.split('\t')
        if fields[0] == 'VERSION':
            if len(fields) < 2 or fields[1] != '1':
                return None
            self.version_ok = True
            return []
        if fields[0] == 'CPID':
            return []
        if not self.version_ok or len(fields) < 2 or not fields[1].isdigit() or len(fields) > 32:
            return None
        rid = fields[1]
        if fields[0] == 'AUTH' and len(fields) >= 3:
            params = dict(item.split('=', 1) if '=' in item else (item, '') for item in fields[3:])
            mech = fields[2].upper()
            if mech not in ('PLAIN', 'LOGIN'):
                return [f'FAIL\t{rid}\treason=Unsupported mechanism.']
            if 'secured' not in params:
                return [f'FAIL\t{rid}\treason=Log in only over TLS.']
            state = {'mech': mech, 'client': params.get('rip', '')[:64], 'step': 0}
            if 'resp' in params and params['resp']:
                return self.step(rid, state, params['resp'])
            if len(self.pending) >= MAX_PENDING:
                # Postfix asks one at a time; many half-finished AUTHs on one connection are not normal.
                return [f'FAIL\t{rid}\treason=Too many pending requests.']
            self.pending[rid] = state
            return [f'CONT\t{rid}\t' + (CHALLENGES['LOGIN'][0] if mech == 'LOGIN' else '')]
        if fields[0] == 'CONT' and len(fields) >= 3 and rid in self.pending:
            return self.step(rid, self.pending.pop(rid), fields[2])
        return [f'FAIL\t{rid}\treason=Bad request.']

    def step(self, rid, state, data):
        raw = b64(data)
        if raw is None or len(raw) > 2048:
            return [f'FAIL\t{rid}\treason=Bad response.']
        if state['mech'] == 'PLAIN':
            parts = raw.split(b'\x00')
            if len(parts) != 3:
                return [f'FAIL\t{rid}\treason=Bad response.']
            authz, user, password = (item.decode('utf-8', 'replace') for item in parts)
            if authz and authz != user:
                return [f'FAIL\t{rid}\treason=No login for another user.']
            return self.finish(rid, user, password, state['client'])
        if state['step'] == 0:
            state.update(step=1, user=raw.decode('utf-8', 'replace'))
            self.pending[rid] = state
            return [f'CONT\t{rid}\t{CHALLENGES["LOGIN"][1]}']
        return self.finish(rid, state['user'], raw.decode('utf-8', 'replace'), state['client'])

    def finish(self, rid, user, password, client):
        ok, reason = check(user, password, client, self.logins, self.limiter, self.delay)
        if not USER_RE.fullmatch(user):
            # Never echoed: a line end in the name would be a reply line of its own to Postfix.
            return [f'FAIL\t{rid}\treason={reason}']
        return [f'OK\t{rid}\tuser={user}'] if ok else [f'FAIL\t{rid}\tuser={user}\treason={reason}']


def handle(conn, cuid, logins, limiter, active):
    conn.settimeout(READ_SECONDS)
    buffer = b''
    try:
        conn.sendall(Session.greeting(cuid).encode())
        session = Session(logins, limiter)
        while True:
            while b'\n' not in buffer:
                data = conn.recv(4096)
                if not data:
                    return
                buffer += data
                if len(buffer) > MAX_LINE:
                    return
            raw, buffer = buffer.split(b'\n', 1)
            answer = session.line(raw.decode('utf-8', 'replace').rstrip('\r'))
            if answer is None:
                return
            if answer:
                conn.sendall(''.join(line + '\n' for line in answer).encode())
    except OSError:
        return
    finally:
        conn.close()
        with active['lock']:
            active['count'] -= 1
            active['last'] = time.time()


def listener():
    """The socket systemd hands over (socket activation), or one of its own for a test."""
    if os.environ.get('LISTEN_PID') == str(os.getpid()) and os.environ.get('LISTEN_FDS') == '1':
        return socket.socket(fileno=3)
    path = os.environ.get('EFA_SASL_SOCKET', '/run/efa-sasl/auth')
    if os.path.exists(path):
        os.remove(path)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(path)
    os.chmod(path, 0o660)
    sock.listen(64)
    return sock


def serve():
    sock, logins, limiter = listener(), Logins(), Limiter()
    active, cuid = {'lock': threading.Lock(), 'count': 0, 'last': time.time()}, 0
    sock.settimeout(30)
    while True:
        try:
            conn, _addr = sock.accept()
        except socket.timeout:
            with active['lock']:
                if active['count'] == 0 and time.time() - active['last'] > IDLE_SECONDS:
                    return  # systemd starts it again at the next login
            continue
        with active['lock']:
            if active['count'] >= MAX_CONNECTIONS:
                conn.close()
                continue
            active['count'] += 1
        cuid += 1
        threading.Thread(target=handle, args=(conn, cuid, logins, limiter, active), daemon=True).start()


def self_test():
    import tempfile
    stored = scrypt_hash('secret pass')
    assert verify('secret pass', stored) and not verify('wrong', stored) and not verify('x', '{PLAIN}x') and not verify('x', '{SCRYPT}bad')
    legacy = '{SHA512-CRYPT}' + efa_shacrypt.make('old pass')
    assert verify('old pass', legacy) and not verify('other', legacy)
    folder = tempfile.mkdtemp()
    path = os.path.join(folder, 'passwd')
    with open(path, 'w') as f:
        f.write(f'mx1@example.org:{stored}\nbroken line\n')
    logins, limiter = Logins(path), Limiter()
    session = Session(logins, limiter, delay=0)
    assert session.line('AUTH\t1\tPLAIN\tservice=smtp') is None, 'nothing before VERSION'
    assert session.line('VERSION\t1\t1') == [] and session.line('CPID\t42') == []
    plain = base64.b64encode(b'\x00mx1@example.org\x00secret pass').decode()
    assert session.line(f'AUTH\t1\tPLAIN\tservice=smtp\tsecured\trip=192.0.2.1\tresp={plain}') == ['OK\t1\tuser=mx1@example.org']
    assert session.line(f'AUTH\t2\tPLAIN\tservice=smtp\trip=192.0.2.1\tresp={plain}')[0].startswith('FAIL\t2\treason=Log in only over TLS')
    wrong = base64.b64encode(b'\x00mx1@example.org\x00nope').decode()
    assert session.line(f'AUTH\t3\tPLAIN\tservice=smtp\tsecured\trip=192.0.2.2\tresp={wrong}')[0].startswith('FAIL\t3\tuser=mx1@example.org')
    other = base64.b64encode(b'boss\x00mx1@example.org\x00secret pass').decode()
    assert 'another user' in session.line(f'AUTH\t4\tPLAIN\tsecured\tresp={other}')[0]
    # PLAIN without initial response, then LOGIN in two steps.
    assert session.line('AUTH\t5\tPLAIN\tsecured\trip=192.0.2.1') == ['CONT\t5\t']
    assert session.line(f'CONT\t5\t{plain}') == ['OK\t5\tuser=mx1@example.org']
    assert session.line('AUTH\t6\tLOGIN\tsecured\trip=192.0.2.1') == ['CONT\t6\tVXNlcm5hbWU6']
    assert session.line('CONT\t6\t' + base64.b64encode(b'mx1@example.org').decode()) == ['CONT\t6\tUGFzc3dvcmQ6']
    assert session.line('CONT\t6\t' + base64.b64encode(b'secret pass').decode()) == ['OK\t6\tuser=mx1@example.org']
    # A line end in the name never reaches the reply: it would be a reply line of its own to Postfix (an OK for the next id).
    for forged in (b'\x00x\nOK\t41\tuser=mx1@example.org\x00p', b'\x00mx1@example.org\n\x00secret pass', b'\x00a\tb\x00p'):
        answer = session.line(f'AUTH\t40\tPLAIN\tsecured\trip=192.0.2.7\tresp={base64.b64encode(forged).decode()}')
        assert answer == ['FAIL\t40\treason=Authentication failed.'], answer
    assert session.line('AUTH\t42\tLOGIN\tsecured\trip=192.0.2.8') == ['CONT\t42\tVXNlcm5hbWU6']
    session.line('CONT\t42\t' + base64.b64encode(b'x\r\nOK\t43\tuser=mx1@example.org').decode())
    assert session.line('CONT\t42\t' + base64.b64encode(b'p').decode()) == ['FAIL\t42\treason=Authentication failed.']
    # Many half-finished AUTHs on one connection are refused, so self.pending cannot grow without bound.
    flood = Session(logins, limiter, delay=0)
    flood.line('VERSION\t1\t1')
    for i in range(MAX_PENDING):
        flood.line(f'AUTH\t{1000 + i}\tLOGIN\tsecured\trip=192.0.2.1')
    assert flood.line(f'AUTH\t{2000}\tLOGIN\tsecured\trip=192.0.2.1')[0].endswith('Too many pending requests.')
    assert len(flood.pending) == MAX_PENDING
    assert session.line('AUTH\t7\tCRAM-MD5\tsecured')[0] == 'FAIL\t7\treason=Unsupported mechanism.'
    assert session.line('AUTH\t8\tPLAIN\tsecured\tresp=!!!')[0] == 'FAIL\t8\treason=Bad response.'
    assert session.line('CONT\t99\tabc')[0] == 'FAIL\t99\treason=Bad request.' and session.line('AUTH\tx\tPLAIN') is None
    unknown = base64.b64encode(b'\x00nobody@example.org\x00secret pass').decode()
    assert session.line(f'AUTH\t9\tPLAIN\tsecured\trip=192.0.2.3\tresp={unknown}')[0].startswith('FAIL'), 'unknown login'
    # Five failures for one address: then even the right password fails for a while.
    for number in range(5):
        session.line(f'AUTH\t{20 + number}\tPLAIN\tsecured\trip=198.51.100.9\tresp={wrong}')
    assert session.line(f'AUTH\t30\tPLAIN\tsecured\trip=198.51.100.9\tresp={plain}')[0].startswith('FAIL\t30\tuser=mx1@example.org\treason=Too many')
    assert not limiter.blocked(('ip:198.51.100.9',), now=time.time() + FAIL_WINDOW + 1), 'the limit ends'
    assert Session(logins, limiter).line('VERSION\t2\t0') is None, 'another major version closes'
    assert 'MECH\tPLAIN\tplaintext\nMECH\tLOGIN\tplaintext' in Session.greeting(1) and Session.greeting(1).endswith('DONE\n')
    # Over a real socket: greeting, then a login.
    os.environ['EFA_SASL_SOCKET'] = os.path.join(folder, 'auth')
    sock = listener()
    active = {'lock': threading.Lock(), 'count': 1, 'last': 0}
    threading.Thread(target=lambda: handle(sock.accept()[0], 1, logins, Limiter(), active), daemon=True).start()
    client = socket.socket(socket.AF_UNIX)
    client.connect(os.environ['EFA_SASL_SOCKET'])
    reader = client.makefile('rb')
    greeting = [reader.readline() for _ in range(7)]
    assert greeting[0] == b'VERSION\t1\t2\n' and greeting[-1] == b'DONE\n'
    client.sendall(f'VERSION\t1\t1\nCPID\t7\nAUTH\t1\tPLAIN\tservice=smtp\tsecured\tresp={plain}\n'.encode())
    assert reader.readline() == b'OK\t1\tuser=mx1@example.org\n'
    client.sendall(b'A' * (MAX_LINE + 10))
    assert reader.readline() == b'', 'an overlong line closes the connection'
    client.close()
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
        sys.exit(0)
    syslog.openlog('efa-sasl', syslog.LOG_PID, syslog.LOG_MAIL)
    serve()
