#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""efactl for the web interface without a new Python per request: the code is loaded once, every call runs in its own fork.

The same rights as the sudo rule of efa-web (efa-web may run /usr/sbin/efactl with any arguments as root), nothing more:
only the user efa-web may connect, checked by the kernel (SO_PEERCRED), and every call starts from the freshly loaded
code with the environment sudo would give. efa-web falls back to sudo when this socket is not there.

    efactl-runner.py [--socket PATH] [--self-test]
    efactl-runner.py --probe   what the calling user gets: denied (no access to the socket), refused (not efa-web) or ok
"""
import json
import os
import pwd
import signal
import socket
import socketserver
import struct
import sys
import syslog
import tempfile

SOCKET = '/run/efactl-runner/runner.sock'
EFACTL = '/usr/sbin/efactl'
LIBRARY = '/usr/lib/eFa/python'
CALLER = 'efa-web'
# A mail of 10 MB to check (9n) comes in base64.
MAX_REQUEST = 16 * 1024 * 1024
# What sudo with env_reset and the secure_path of EL9 gives efactl.
SECURE_PATH = '/sbin:/bin:/usr/sbin:/usr/bin'
# As the sudo way of efa-web: subprocess.run(..., timeout=120) there, the kernel ends the fork here.
CALL_SECONDS = 120
READ_SECONDS = 10


def request_problem(request):
    """None for a request of the right form: a list of plain strings as arguments, the secrets as lines."""
    if not isinstance(request, dict) or not isinstance(request.get('args'), list) or not isinstance(request.get('secrets', []), list):
        return 'bad request'
    for item in request['args'] + request.get('secrets', []):
        if not isinstance(item, str) or '\0' in item or '\n' in item:
            return 'bad request'
    return None


def sudo_env(caller, args):
    user = pwd.getpwnam(caller)
    return {'PATH': SECURE_PATH, 'HOME': '/root', 'USER': 'root', 'LOGNAME': 'root', 'SHELL': '/bin/bash',
            'LANG': os.environ.get('LANG', 'C.UTF-8'), 'SUDO_USER': caller, 'SUDO_UID': str(user.pw_uid), 'SUDO_GID': str(user.pw_gid),
            'SUDO_COMMAND': ' '.join([EFACTL] + args)[:4096]}


def run_call(request, main, caller):
    """One efactl call in this (forked) process: stdin, stdout and stderr are files, as under sudo. Returns the reply."""
    secrets_in = ''.join(line + '\n' for line in request.get('secrets', []))
    with tempfile.TemporaryFile() as stdin, tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        stdin.write(secrets_in.encode())
        stdin.seek(0)
        for fd, f in ((0, stdin), (1, stdout), (2, stderr)):
            os.dup2(f.fileno(), fd)
        os.environ.clear()
        os.environ.update(sudo_env(caller, request['args']))
        # The umask of sudo; SIGALRM ends this fork without a reply, efa-web then reports the call as failed.
        os.umask(0o022)
        signal.alarm(CALL_SECONDS)
        sys.argv = [EFACTL] + request['args']
        try:
            code = main() or 0
        except SystemExit as done:
            code = done.code if isinstance(done.code, int) else 1
        except Exception as err:  # what would end efactl with a traceback under sudo
            print(f'efactl: {err!r}', file=sys.stderr)
            code = 1
        sys.stdout.flush()
        sys.stderr.flush()
        stdout.seek(0)
        stderr.seek(0)
        return {'code': code, 'stdout': stdout.read().decode(errors='replace'), 'stderr': stderr.read().decode(errors='replace')[-8000:]}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        uid = struct.unpack('3i', self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))[1]
        if uid != self.server.caller_uid:
            syslog.syslog(syslog.LOG_WARNING, f'refused a caller with uid {uid}')
            return
        # A caller that never ends its line must not keep a fork: 64 of them would stop every call.
        self.request.settimeout(READ_SECONDS)
        try:
            request = json.loads(self.rfile.readline(MAX_REQUEST))
        except (ValueError, OSError):
            request = None
        problem = request_problem(request)
        if problem:
            self.wfile.write(json.dumps({'code': 1, 'stdout': json.dumps({'error': problem}), 'stderr': problem}).encode() + b'\n')
            return
        # Like the line sudo writes, without the arguments: they can hold addresses.
        command = next((item for item in request['args'] if not item.startswith('-')), '')
        syslog.syslog(syslog.LOG_INFO, f'{self.server.caller}: efactl {command[:64]}')
        reply = run_call(request, self.server.main, self.server.caller)
        self.wfile.write(json.dumps(reply).encode() + b'\n')


class Server(socketserver.ForkingMixIn, socketserver.UnixStreamServer):
    # Every call is a fork of the loaded code; the forks clean up after themselves.
    block_on_close = False
    max_children = 64


def serve(path, main, caller=CALLER):
    if os.path.exists(path):
        os.unlink(path)
    old = os.umask(0o117)
    server = Server(path, Handler)
    os.umask(old)
    server.main, server.caller, server.caller_uid = main, caller, pwd.getpwnam(caller).pw_uid
    os.chown(path, 0, pwd.getpwnam(caller).pw_gid)
    return server


def load_efactl():
    sys.path.insert(0, LIBRARY)
    import efactl_main
    return efactl_main.main


def call(path, args, secrets_in=()):
    """What efa-web does: one request, one reply."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(130)
        sock.connect(path)
        sock.sendall(json.dumps({'args': list(args), 'secrets': list(secrets_in)}).encode() + b'\n')
        return json.loads(sock.makefile('rb').readline())


def self_test():
    # One second for every call of this test, set before the server is forked.
    global CALL_SECONDS, READ_SECONDS
    CALL_SECONDS = READ_SECONDS = 1
    assert request_problem({'args': ['status']}) is None and request_problem({'args': ['a\nb']}) and request_problem({'args': 'status'})
    assert request_problem({'args': ['x'], 'secrets': [1]}) and request_problem([]) and request_problem({'args': ['a\0']})

    def fake_main():
        if sys.argv[1] == 'slow':
            signal.pause()
        print(json.dumps({'argv': sys.argv, 'user': os.environ.get('SUDO_USER'), 'path': os.environ['PATH'], 'secret': sys.stdin.readline().strip(),
                          'etc': os.environ.get('EFA_ETC'), 'umask': os.umask(0o022)}))
        return 3 if sys.argv[1] == 'fail' else 0

    me = pwd.getpwuid(os.getuid()).pw_name
    folder = tempfile.mkdtemp()
    path = folder + '/t.sock'
    os.environ['EFA_ETC'] = '/must/not/reach/efactl'
    server = serve(path, fake_main, me) if os.getuid() == 0 else None
    if server is None:
        # Not root: chown to root fails; the same server without it.
        old = os.umask(0o117)
        server = Server(path, Handler)
        os.umask(old)
        server.main, server.caller, server.caller_uid = fake_main, me, os.getuid()
    assert oct(os.stat(path).st_mode & 0o777) == '0o660'
    pid = os.fork()
    if pid == 0:
        for _ in range(5):
            server.handle_request()
        os._exit(0)
    reply = call(path, ['status', '--as=x'], ['s3cret'])
    out = json.loads(reply['stdout'])
    assert reply['code'] == 0 and out['argv'] == [EFACTL, 'status', '--as=x'] and out['user'] == me and out['secret'] == 's3cret', reply
    assert out['path'] == SECURE_PATH and out['etc'] is None, 'the environment of the runner never reaches efactl'
    assert out['umask'] == 0o022, 'the umask of sudo, not the one of the runner'
    assert call(path, ['fail'])['code'] == 3
    try:
        call(path, ['slow'])
        raise AssertionError('a call over the time limit must end without a reply')
    except ValueError:
        pass
    assert json.loads(call(path, ['a\nb'])['stdout'])['error'] == 'bad request'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(path)
        sock.sendall(b'{"args": ')
        # A request without its line end: the fork gives up after READ_SECONDS, it does not wait for ever.
        assert b'bad request' in sock.makefile('rb').readline()
    os.waitpid(pid, 0)
    server.caller_uid = os.getuid() + 1
    pid = os.fork()
    if pid == 0:
        server.handle_request()
        os._exit(0)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(path)
        sock.sendall(b'{"args": ["status"]}\n')
        # Closed with the request unread: an empty answer or a reset, never a reply.
        try:
            assert sock.makefile('rb').readline() == b'', 'another user gets nothing'
        except ConnectionResetError:
            pass
    os.waitpid(pid, 0)
    server.server_close()
    os.unlink(path)
    os.rmdir(folder)
    print('self-test ok')


def probe(path=SOCKET):
    """For the CI: run as each service user after an install."""
    try:
        reply = call(path, ['status'])
    except PermissionError:
        return 'denied'
    except (ValueError, ConnectionResetError):
        return 'refused'
    return 'ok' if reply['code'] == 0 else 'failed'


def main():
    if '--self-test' in sys.argv:
        self_test()
        return 0
    if '--probe' in sys.argv:
        print(probe())
        return 0
    path = sys.argv[sys.argv.index('--socket') + 1] if '--socket' in sys.argv else SOCKET
    syslog.openlog('efactl-runner')
    server = serve(path, load_efactl())
    server.serve_forever()
    return 0


if __name__ == '__main__':
    sys.exit(main())
