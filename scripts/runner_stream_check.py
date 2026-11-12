# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""For the CI, run as efa-web on an installed host: the two pipe ways of the web interface reach the real efactl through
efactl-runner, without changing anything. An upload that is no backup is refused, a download of an unknown backup ends with
its error in the pipe.
    sudo -u efa-web python3 -I - < scripts/runner_stream_check.py
"""
import importlib.util
import json
import os
import socket
import sys

spec = importlib.util.spec_from_file_location('runner', '/usr/local/sbin/efactl-runner.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def stream(args, data=None):
    read_end, write_end = os.pipe()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(60)
        sock.connect(runner.SOCKET)
        if data is None:
            runner.send(sock, args, stdout=write_end)
            os.close(write_end)
            with os.fdopen(read_end, 'rb') as pipe:
                piped = pipe.read()
        else:
            runner.send(sock, args, stdin=read_end)
            os.close(read_end)
            with os.fdopen(write_end, 'wb') as pipe:
                pipe.write(data)
            piped = b''
        return json.loads(sock.makefile('rb').readline()), piped


reply, _ = stream(['backup-import'], b'no backup' * 1000)
assert reply['code'] == 1 and 'no eFa-next backup' in json.loads(reply['stdout'])['error'], reply
reply, piped = stream(['backup-read', '--name=efa-backup-none.tar.gz.gpg'])
assert reply['code'] == 1 and reply['stdout'] == '' and b'Unknown backup' in piped, (reply, piped)
print('runner streams: ok')
sys.exit(0)
