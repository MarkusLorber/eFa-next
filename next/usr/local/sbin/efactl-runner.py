#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""efactl for the web interface without a new Python per request: the code is loaded once, every call runs in its own fork.

The only way of efa-web to efactl (efa-web has no sudo rule): only the user efa-web may connect, checked by the kernel
(SO_PEERCRED), and every call starts from the freshly loaded code with the environment sudo would give. A download or an
upload (backup, logo) passes a pipe of efa-web as stdin or stdout of the call (SCM_RIGHTS), so nothing large goes through JSON.

Protocol: one byte first, b'N' or b'F' (then with the pipe ends as ancillary data, stdin before stdout), then one JSON line
{"args": [...], "secrets": [...], "stdin_fd": bool, "stdout_fd": bool}; the reply is one JSON line.

    efactl-runner.py [--socket PATH] [--self-test]
    efactl-runner.py --probe   what the calling user gets: denied (no access to the socket), refused (not efa-web) or ok
"""
import json
import os
import pwd
import re
import signal
import socket
import socketserver
import stat
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
# The time limit of one call; the kernel ends the fork (SIGALRM).
CALL_SECONDS = 120
# A backup download to a slow browser: the call writes into the pipe as fast as the browser reads.
STREAM_SECONDS = 1800
# The only calls that may bring a pipe (and with it the long time limit): what efa-web streams.
STREAM_COMMANDS = {'backup-read', 'backup-import', 'tenant-brand-set'}
READ_SECONDS = 10


def request_problem(request, fds=()):
    """None for a request of the right form: a list of plain strings as arguments, the secrets as lines, and exactly the pipes
    it names (stdin_fd, stdout_fd), each a pipe."""
    if not isinstance(request, dict) or not isinstance(request.get('args'), list) or not isinstance(request.get('secrets', []), list):
        return 'bad request'
    # An argument may span lines, as under sudo: a PEM certificate, a disclaimer, an HTML part (they failed with "bad request"
    # since efa-web reaches efactl only through this runner). A secret is one line on stdin, so it may not.
    for item in request['args']:
        if not isinstance(item, str) or '\0' in item:
            return 'bad request'
    for item in request.get('secrets', []):
        if not isinstance(item, str) or '\0' in item or '\n' in item or '\r' in item:
            return 'bad request'
    wanted = [request.get(name) is True for name in ('stdin_fd', 'stdout_fd')].count(True)
    if wanted != len(fds) or any(not stat.S_ISFIFO(os.fstat(fd).st_mode) for fd in fds):
        return 'bad request'
    if fds and request.get('secrets'):
        return 'bad request'
    if fds and command_of(request['args']) not in STREAM_COMMANDS:
        return 'bad request'
    return None


def command_of(args):
    """The efactl command of a call: the first argument that is no option (efa-web sends its options as --name=value)."""
    return next((item for item in args if not item.startswith('-')), '')


def receive(sock):
    """The first byte and the pipe ends sent with it. None for anything else than b'N' or b'F'."""
    message, fds, _flags, _address = socket.recv_fds(sock, 1, 2)
    if message == b'N' and not fds or message == b'F' and fds:
        return fds
    for fd in fds:
        os.close(fd)
    return None


def sudo_env(caller, args):
    user = pwd.getpwnam(caller)
    return {'PATH': SECURE_PATH, 'HOME': '/root', 'USER': 'root', 'LOGNAME': 'root', 'SHELL': '/bin/bash',
            'LANG': os.environ.get('LANG', 'C.UTF-8'), 'SUDO_USER': caller, 'SUDO_UID': str(user.pw_uid), 'SUDO_GID': str(user.pw_gid),
            'SUDO_COMMAND': ' '.join([EFACTL] + args)[:4096]}


def run_call(request, main, caller, fds=()):
    """One efactl call in this (forked) process: stdin, stdout and stderr are files, as under sudo, or the pipes of the
    caller (fds: stdin before stdout, as the request names them). Returns the reply."""
    fds = list(fds)
    secrets_in = ''.join(line + '\n' for line in request.get('secrets', []))
    with tempfile.TemporaryFile() as stdin, tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        stdin.write(secrets_in.encode())
        stdin.seek(0)
        for fd, f in ((0, stdin), (1, stdout), (2, stderr)):
            os.dup2(f.fileno(), fd)
        if request.get('stdin_fd') is True:
            os.dup2(fds[0], 0)
        piped_out = request.get('stdout_fd') is True
        if piped_out:
            os.dup2(fds[-1], 1)
        # Only 0 and 1 hold the pipes now: the caller sees the end of the download when this call closes 1.
        for fd in fds:
            os.close(fd)
        os.environ.clear()
        os.environ.update(sudo_env(caller, request['args']))
        # The umask of sudo; SIGALRM ends this fork without a reply, efa-web then reports the call as failed.
        os.umask(0o022)
        signal.alarm(STREAM_SECONDS if piped_out or request.get('stdin_fd') is True else CALL_SECONDS)
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
        if piped_out:
            # The end of the download: the caller reads the pipe to its end, then this reply.
            os.close(1)
        stdout.seek(0)
        stderr.seek(0)
        return {'code': code, 'stdout': '' if piped_out else stdout.read().decode(errors='replace'),
                'stderr': stderr.read().decode(errors='replace')[-8000:]}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        uid = struct.unpack('3i', self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))[1]
        if uid != self.server.caller_uid:
            syslog.syslog(syslog.LOG_WARNING, f'refused a caller with uid {uid}')
            return
        # A caller that never ends its line must not keep a fork: 64 of them would stop every call.
        self.request.settimeout(READ_SECONDS)
        fds = []
        try:
            fds = receive(self.request)
            request = json.loads(self.rfile.readline(MAX_REQUEST)) if fds is not None else None
        except (ValueError, OSError):
            request = None
        problem = request_problem(request, fds or [])
        if problem:
            for fd in fds or []:
                os.close(fd)
            self.wfile.write(json.dumps({'code': 1, 'stdout': json.dumps({'error': problem}), 'stderr': problem}).encode() + b'\n')
            return
        # Like the line sudo writes, without the arguments: they can hold addresses.
        command = command_of(request['args'])
        # Only the characters of a command name: a value of a form never forges a line of the log.
        syslog.syslog(syslog.LOG_INFO, f"{self.server.caller}: efactl {re.sub(r'[^a-z0-9-]', '?', command[:64])}")
        reply = run_call(request, self.server.main, self.server.caller, fds)
        self.wfile.write(json.dumps(reply).encode() + b'\n')


class Server(socketserver.ForkingMixIn, socketserver.UnixStreamServer):
    # Every call is a fork of the loaded code; the forks clean up after themselves.
    block_on_close = False
    max_children = 64
    # A page loads its reads in parallel: with the default backlog of 5 a connect got EAGAIN and a tile showed Unknown.
    request_queue_size = 128


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
    # efactl imports pymysql only when a command needs the database: loaded here once, not in every fork (about 40 ms each on
    # the users page). Only the module: no connection exists before the fork.
    try:
        import pymysql.cursors  # noqa: F401
    except ImportError:
        pass
    return efactl_main.main


def send(sock, args, secrets_in=(), stdin=None, stdout=None):
    """A request as efa-web sends it; stdin and stdout are pipe ends of the caller or None."""
    fds = [fd for fd in (stdin, stdout) if fd is not None]
    if fds:
        socket.send_fds(sock, [b'F'], fds)
    else:
        sock.sendall(b'N')
    sock.sendall(json.dumps({'args': list(args), 'secrets': list(secrets_in), 'stdin_fd': stdin is not None,
                             'stdout_fd': stdout is not None}).encode() + b'\n')


def call(path, args, secrets_in=()):
    """What efa-web does: one request, one reply."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(130)
        sock.connect(path)
        send(sock, args, secrets_in)
        return json.loads(sock.makefile('rb').readline())


def self_test():
    assert Server.request_queue_size >= 64, 'the backlog takes the parallel reads of a page'
    # One second for every call of this test, set before the server is forked.
    global CALL_SECONDS, READ_SECONDS
    CALL_SECONDS = READ_SECONDS = 1
    assert request_problem({'args': ['status']}) is None and request_problem({'args': 'status'})
    # Lines in an argument (a certificate, a disclaimer) pass; a secret is one line of stdin and stays one.
    assert request_problem({'args': ['crypto-import', '--data=-----BEGIN\r\nAA\n-----END']}) is None
    assert request_problem({'args': ['x'], 'secrets': ['a\nb']}) and request_problem({'args': ['x'], 'secrets': ['a\rb']})
    assert request_problem({'args': ['x'], 'secrets': [1]}) and request_problem([]) and request_problem({'args': ['a\0']})
    # S24: a pipe, and with it 1800 s, only for the streaming calls of efa-web; any other call with a pipe is refused.
    read_end, write_end = os.pipe()
    assert request_problem({'args': ['--client=192.0.2.1', '--as=anna', 'status'], 'stdin_fd': True}, [read_end]) == 'bad request'
    assert request_problem({'args': ['--client=192.0.2.1', 'backup-import'], 'stdin_fd': True}, [read_end]) is None
    assert command_of(['--client=192.0.2.1', '--as=anna', 'backup-read', '--name=x']) == 'backup-read' and command_of([]) == ''
    os.close(read_end)
    os.close(write_end)
    # The fake calls of this test that stream.
    STREAM_COMMANDS.update({'dump', 'count'})

    def fake_main():
        if sys.argv[1] == 'slow':
            signal.pause()
        if sys.argv[1] == 'dump':
            sys.stdout.buffer.write(b'x' * 200000)
            return 0
        if sys.argv[1] == 'count':
            print(json.dumps({'count': len(sys.stdin.buffer.read())}))
            return 0
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
        for _ in range(10):
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
    assert json.loads(call(path, ['a'], ['b\nc'])['stdout'])['error'] == 'bad request'
    assert json.loads(call(path, ['status', '--text=one\ntwo'])['stdout'])['argv'] == [EFACTL, 'status', '--text=one\ntwo']
    # A download: the call writes into the pipe of the caller, the reply comes after the end of the data.
    read_end, write_end = os.pipe()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(path)
        send(sock, ['dump'], stdout=write_end)
        os.close(write_end)
        with os.fdopen(read_end, 'rb') as pipe:
            assert pipe.read() == b'x' * 200000, 'the whole download, then the end of the pipe'
        reply = json.loads(sock.makefile('rb').readline())
        assert reply['code'] == 0 and reply['stdout'] == '', reply
    # An upload: the pipe is stdin of the call.
    read_end, write_end = os.pipe()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(path)
        send(sock, ['count'], stdin=read_end)
        os.close(read_end)
        with os.fdopen(write_end, 'wb') as pipe:
            pipe.write(b'y' * 300000)
        assert json.loads(json.loads(sock.makefile('rb').readline())['stdout'])['count'] == 300000
    # A file instead of a pipe (efa-web could hand over any file it opened), or a pipe the request does not name: refused.
    with tempfile.TemporaryFile() as f, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(path)
        socket.send_fds(sock, [b'F'], [f.fileno()])
        sock.sendall(json.dumps({'args': ['count'], 'stdin_fd': True}).encode() + b'\n')
        assert b'bad request' in sock.makefile('rb').readline()
    read_end, write_end = os.pipe()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(path)
        socket.send_fds(sock, [b'F'], [read_end])
        sock.sendall(json.dumps({'args': ['status']}).encode() + b'\n')
        assert b'bad request' in sock.makefile('rb').readline()
    os.close(read_end)
    os.close(write_end)
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
