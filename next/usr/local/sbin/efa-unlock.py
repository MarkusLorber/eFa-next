#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""eFa-next unlock (10): opens encrypted ZIP archives for the virus scan, on 127.0.0.1:8910. rspamd posts the archive and the subject
and text of the mail as JSON; the password is looked for there (a few candidates, a time limit). Each file goes to clamd by its
socket, in memory; nothing is written or kept. ZIP with ZipCrypto only (Python); AES-ZIP, 7z and RAR stay marked as before.
The answer: {'state': 'unlocked' | 'locked' | 'unsupported' | 'error', 'virus': name or '', 'files': n}."""
import base64
import io
import json
import re
import socket
import struct
import sys
import time
import zipfile
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8910
CLAMD = '/run/clamd.scan/clamd.sock'
MAX_ARCHIVE = 10 * 1024 * 1024
MAX_FILES, MAX_TOTAL, MAX_RATIO = 50, 50 * 1024 * 1024, 100
MAX_CANDIDATES, SECONDS = 10, 5
# "Passwort: x", "password is x", "Kennwort lautet x", "PW x": the word after these first, then short tokens of short lines.
HINT_RE = re.compile(r'(?:passwor[dt]|kennwort|pass(?:wd)?|pw|code|schl(?:ü|ue)ssel|key)\s*(?:lautet|is|ist|=|:)?\s*[:=]?\s*["\'„“]?([^\s"\'“”]{3,64})', re.I)
TOKEN_RE = re.compile(r'^[^\s]{4,32}$')


def candidates(text):
    """Up to 10 passwords to try, the ones after a hint word first."""
    found = []
    for item in HINT_RE.findall(text or ''):
        item = item.strip('.,;:!?)')
        if item and item not in found:
            found.append(item)
    for line in (text or '').splitlines():
        line = line.strip()
        if TOKEN_RE.match(line) and line not in found and not line.lower().startswith(('http', 'www.')):
            found.append(line)
    return found[:MAX_CANDIDATES]


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


def unlock(data, text, scan=clamd_scan, deadline=None):
    deadline = deadline or time.monotonic() + SECONDS
    if len(data) > MAX_ARCHIVE:
        return {'state': 'error', 'virus': '', 'files': 0}
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        members = [info for info in archive.infolist() if not info.is_dir()][:MAX_FILES + 1]
    except (zipfile.BadZipFile, ValueError, OSError, EOFError, NotImplementedError):
        return {'state': 'unsupported', 'virus': '', 'files': 0}
    if not members or len(members) > MAX_FILES or not any(info.flag_bits & 0x1 for info in members):
        return {'state': 'unsupported', 'virus': '', 'files': 0}
    if any(info.compress_type == 99 for info in members):
        return {'state': 'unsupported', 'virus': '', 'files': 0}  # WinZip AES: not in the standard library
    if sum(info.file_size for info in members) > MAX_TOTAL or any(info.compress_size and info.file_size / info.compress_size > MAX_RATIO
                                                                   for info in members):
        return {'state': 'error', 'virus': '', 'files': 0}
    first = min(members, key=lambda info: info.file_size)
    password = None
    for candidate in candidates(text):
        if time.monotonic() > deadline:
            break
        try:
            archive.read(first, pwd=candidate.encode())
            password = candidate.encode()
            break
        except (RuntimeError, zipfile.BadZipFile, zlib.error, ValueError, NotImplementedError, OSError, EOFError):
            continue
    if password is None:
        return {'state': 'locked', 'virus': '', 'files': 0}
    try:
        for info in members:
            if time.monotonic() > deadline + SECONDS:
                return {'state': 'error', 'virus': '', 'files': 0}
            found = scan(archive.read(info, pwd=password))
            if found:
                return {'state': 'unlocked', 'virus': found, 'files': len(members)}
    except (RuntimeError, zipfile.BadZipFile, zlib.error, ValueError, NotImplementedError, OSError, EOFError):
        return {'state': 'error', 'virus': '', 'files': 0}
    return {'state': 'unlocked', 'virus': '', 'files': len(members)}


def ole_verdict(results):
    """5v (b): the findings of olevba as {'autoexec': [...], 'suspicious': [...], 'iocs': n}; results: (kind, keyword, description)."""
    found = {'autoexec': [], 'suspicious': [], 'iocs': 0}
    for kind, keyword, _description in results or []:
        if kind == 'AutoExec' and keyword not in found['autoexec']:
            found['autoexec'].append(str(keyword)[:40])
        elif kind == 'Suspicious' and keyword not in found['suspicious']:
            found['suspicious'].append(str(keyword)[:40])
        elif kind == 'IOC':
            found['iocs'] += 1
    found['autoexec'], found['suspicious'] = found['autoexec'][:10], found['suspicious'][:10]
    return found


def ole_report(data):
    """The macros of an Office file, read by olevba of oletools (EPEL); {'macros': False} without any, 'error' when it cannot read it."""
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        return {'error': 'oletools missing'}
    try:
        parser = VBA_Parser('attachment', data=data)
        try:
            if not parser.detect_vba_macros():
                return {'macros': False}
            return {'macros': True, **ole_verdict(parser.analyze_macros())}
        finally:
            parser.close()
    except Exception:  # olevba raises many kinds on broken files: the file then counts as unreadable, never as clean
        return {'error': 'unreadable'}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        if not 0 < length <= MAX_ARCHIVE * 2:
            self.send_error(413)
            return
        if self.path == '/ole':
            # 5v (b): the Office file itself is the body.
            body = json.dumps(ole_report(self.rfile.read(length))).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        try:
            request = json.loads(self.rfile.read(length))
            result = unlock(base64.b64decode(request.get('archive', '')), str(request.get('text', ''))[:20000])
        except (ValueError, TypeError, AttributeError):
            result = {'state': 'error', 'virus': '', 'files': 0}
        body = json.dumps(result).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _zipcrypto(files, password):
    """A ZIP with ZipCrypto (stored) for the self-test; Python cannot write one, so the cipher is done here."""
    keys = [0x12345678, 0x23456789, 0x34567890]

    def update(char):
        keys[0] = zlib.crc32(bytes([char]), keys[0] ^ 0xffffffff) ^ 0xffffffff
        keys[1] = (keys[1] + (keys[0] & 0xff)) & 0xffffffff
        keys[1] = (keys[1] * 134775813 + 1) & 0xffffffff
        keys[2] = zlib.crc32(bytes([keys[1] >> 24]), keys[2] ^ 0xffffffff) ^ 0xffffffff

    def encrypt(data):
        out = bytearray()
        for char in data:
            temp = (keys[2] | 2) & 0xffff
            out.append(char ^ (((temp * (temp ^ 1)) >> 8) & 0xff))
            update(char)
        return bytes(out)
    out, central = io.BytesIO(), b''
    for name, data in files.items():
        keys[:] = [0x12345678, 0x23456789, 0x34567890]
        for char in password:
            update(char)
        crc = zlib.crc32(data)
        body = encrypt(bytes(11) + bytes([crc >> 24])) + encrypt(data)
        offset = out.tell()
        header = struct.pack('<4sHHHHHIIIHH', b'PK\x03\x04', 20, 1, 0, 0, 0, crc, len(body), len(data), len(name), 0)
        out.write(header + name.encode() + body)
        central += struct.pack('<4sHHHHHHIIIHHHHHII', b'PK\x01\x02', 20, 20, 1, 0, 0, 0, crc, len(body), len(data), len(name), 0, 0, 0, 0, 0,
                               offset) + name.encode()
    start = out.tell()
    out.write(central + struct.pack('<4sHHHHIIH', b'PK\x05\x06', 0, 0, len(files), len(files), len(central), start, 0))
    return out.getvalue()


def self_test():
    assert candidates('Hallo,\nanbei die Rechnung. Das Passwort lautet: Sommer2026!\nGruß') [:1] == ['Sommer2026']
    assert candidates('password is "x9Kq-77"') == ['x9Kq-77'] and candidates('PW: 4711abc\n1234') == ['4711abc', '1234']
    eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    archive = _zipcrypto({'invoice.txt': b'hello', 'payload.com': eicar}, b'Sommer2026')
    fake_scan = lambda data: 'Eicar-Signature' if b'EICAR' in data else ''
    assert unlock(archive, 'Das Passwort lautet: Sommer2026', fake_scan) == {'state': 'unlocked', 'virus': 'Eicar-Signature', 'files': 2}
    clean = _zipcrypto({'a.txt': b'hello world'}, b'secret1')
    assert unlock(clean, 'Kennwort: secret1', fake_scan) == {'state': 'unlocked', 'virus': '', 'files': 1}
    assert unlock(clean, 'Kennwort: wrong', fake_scan)['state'] == 'locked'
    plain = io.BytesIO()
    with zipfile.ZipFile(plain, 'w') as f:
        f.writestr('a.txt', 'x')
    assert unlock(plain.getvalue(), 'pw: x', fake_scan)['state'] == 'unsupported' and unlock(b'junk', '', fake_scan)['state'] == 'unsupported'
    assert unlock(clean, 'Kennwort: secret1', lambda data: (_ for _ in ()).throw(OSError('down')))['state'] == 'error'
    # 5v (b): the macro findings by kind; an unreadable file is an error, never clean.
    assert ole_verdict([('AutoExec', 'AutoOpen', 'x'), ('Suspicious', 'Shell', 'x'), ('Suspicious', 'Shell', 'y'), ('IOC', 'http://x', 'URL')]) == \
        {'autoexec': ['AutoOpen'], 'suspicious': ['Shell'], 'iocs': 1}
    assert ole_report(b'not an office file') in ({'error': 'oletools missing'}, {'macros': False}, {'error': 'unreadable'})
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
    else:
        ThreadingHTTPServer(('127.0.0.1', PORT), Handler).serve_forever()
