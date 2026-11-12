# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""clamd through its socket (INSTREAM), in memory: for efa-unlock (files of an archive) and efa-cdr (parts of a mail)."""
import socket
import struct

CLAMD = '/run/clamd.scan/clamd.sock'


def clamd_scan(data, path=CLAMD):
    """The name of what clamd found in data, '' when clean; OSError when clamd does not answer."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(30)
        conn.connect(path)
        conn.sendall(b'zINSTREAM\0')
        for start in range(0, len(data), 65536):
            chunk = data[start:start + 65536]
            conn.sendall(struct.pack('>I', len(chunk)) + chunk)
        conn.sendall(struct.pack('>I', 0))
        answer = b''
        while not answer.endswith(b'\0'):
            more = conn.recv(4096)
            if not more:
                break
            answer += more
    text = answer.rstrip(b'\0').decode('utf-8', 'replace')
    if text.endswith('FOUND'):
        return text.split(':', 1)[-1].strip()[:-6].strip() or 'unknown'
    if not text.endswith('OK'):
        raise OSError(f'clamd: {text[:100]}')
    return ''
