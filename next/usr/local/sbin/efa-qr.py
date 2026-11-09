#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""eFa-next QR (5x): reads QR codes in pictures and PDF files for rspamd, on 127.0.0.1:8909. One POST per part, the body is the file;
the answer is JSON with the URLs found. zbarimg reads the pictures, pdftoppm turns the first pages of a PDF into pictures. Every
call has a time limit and runs in a folder of its own that goes afterwards; nothing is kept. No network but the local socket."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8909
MAX_FILE = 10 * 1024 * 1024
MAX_PAGES = 3
SECONDS = 10
URL_RE = re.compile(r'(?:https?://|www\.)[^\s"<>]{3,2000}', re.I)
KINDS = {b'\x89PNG': 'png', b'\xff\xd8\xff': 'jpg', b'GIF8': 'gif', b'%PDF': 'pdf', b'BM': 'bmp'}


def kind_of(data):
    return next((kind for magic, kind in KINDS.items() if data.startswith(magic)), None)


def urls_in(text):
    found = []
    for item in URL_RE.findall(text):
        url = item if item.lower().startswith('http') else 'http://' + item
        if url not in found:
            found.append(url)
    return found[:20]


def decode(data, run=subprocess.run):
    """The URLs of the QR codes in a picture or the first pages of a PDF; [] for anything else."""
    kind = kind_of(data)
    if not kind or len(data) > MAX_FILE:
        return []
    work = tempfile.mkdtemp(prefix='efa-qr-')
    try:
        source = os.path.join(work, 'in.' + kind)
        with open(source, 'wb') as f:
            f.write(data)
        pictures = [source]
        if kind == 'pdf':
            run(['pdftoppm', '-r', '110', '-f', '1', '-l', str(MAX_PAGES), '-png', source, os.path.join(work, 'page')],
                capture_output=True, timeout=SECONDS, check=False)
            pictures = sorted(os.path.join(work, name) for name in os.listdir(work) if name.startswith('page'))
        text = ''
        for picture in pictures[:MAX_PAGES]:
            done = run(['zbarimg', '--quiet', '--raw', '--nodbus', '-Sdisable', '-Sqrcode.enable', picture],
                       capture_output=True, text=True, timeout=SECONDS, check=False)
            text += (done.stdout or '') + '\n'
        return urls_in(text)
    except (OSError, subprocess.SubprocessError):
        return []
    finally:
        shutil.rmtree(work, ignore_errors=True)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        if not 0 < length <= MAX_FILE:
            self.send_error(413)
            return
        body = json.dumps({'urls': decode(self.rfile.read(length))}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def self_test():
    assert kind_of(b'\x89PNG\r\n') == 'png' and kind_of(b'%PDF-1.4') == 'pdf' and kind_of(b'MZ') is None
    assert urls_in('https://evil.example/a\nwww.phish.example/x\nhttps://evil.example/a\nWIFI:S:x;;') == ['https://evil.example/a', 'http://www.phish.example/x']

    class Done:
        def __init__(self, out):
            self.stdout = out
    calls = []

    def run(argv, **kwargs):
        calls.append(argv[0])
        if argv[0] == 'pdftoppm':
            open(argv[-1] + '-1.png', 'wb').close()
        return Done('https://qr.example/pay\n')
    assert decode(b'\x89PNG' + b'x' * 10, run) == ['https://qr.example/pay'] and calls == ['zbarimg']
    calls.clear()
    assert decode(b'%PDF-1.4 x', run) == ['https://qr.example/pay'] and calls == ['pdftoppm', 'zbarimg']
    assert decode(b'MZ' + b'x' * 10, run) == [] and decode(b'\x89PNG' + b'x' * MAX_FILE, run) == []
    if shutil.which('zbarimg'):
        assert decode(b'\x89PNG\r\n\x1a\n' + b'\x00' * 20) == [], 'a broken picture gives nothing, never an error'
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
    else:
        ThreadingHTTPServer(('127.0.0.1', PORT), Handler).serve_forever()
