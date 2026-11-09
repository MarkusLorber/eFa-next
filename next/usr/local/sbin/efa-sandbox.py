#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""eFa-next sandbox (14): hands suspicious attachments to a self-hosted CAPEv2 sandbox and keeps its verdicts, on 127.0.0.1:8911.
rspamd posts {'sha256', 'name', 'file' (base64)}; the answer is {'state': 'malicious' | 'clean' | 'pending' | 'timeout' | 'error',
'score'}. An unknown file goes to the sandbox and is pending; rspamd defers the mail, and the retry finds the verdict. The
verdicts by hash only, 7 days, in the state folder; no file is kept here. No sandbox runs on this host. HTTPS only."""
import base64
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8911
# The settings with the token come as a credential of systemd (LoadCredential): the service user cannot read /etc/eFa.
CONF = os.path.join(os.environ.get('CREDENTIALS_DIRECTORY', '/etc/eFa'), 'sandbox-service.json')
STATE = os.path.join(os.environ.get('STATE_DIRECTORY', '/var/lib/efa-sandbox'), 'verdicts.json')
MAX_FILE = 20 * 1024 * 1024
KEEP, WAIT, POLL = 7 * 86400, 30 * 60, 30
lock = threading.Lock()


def load(path=STATE):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save(verdicts, path=STATE):
    now = time.time()
    kept = {key: item for key, item in verdicts.items() if now - item.get('at', now) < KEEP}
    with open(path + '.tmp', 'w') as f:
        json.dump(kept, f)
    os.replace(path + '.tmp', path)


def multipart(name, data):
    boundary = uuid.uuid4().hex
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', name)[:100] or 'file'
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{safe}"\r\nContent-Type: application/octet-stream\r\n\r\n'
            ).encode() + data + f'\r\n--{boundary}--\r\n'.encode()
    return body, f'multipart/form-data; boundary={boundary}'


def cape(conf, path, body=None, content_type=None, opener=urllib.request.urlopen):
    headers = {'Authorization': f"Token {conf['token']}", 'User-Agent': 'eFa-next'}
    if content_type:
        headers['Content-Type'] = content_type
    request = urllib.request.Request(conf['url'].rstrip('/') + path, data=body, headers=headers, method='POST' if body is not None else 'GET')
    with opener(request, timeout=30, context=ssl.create_default_context()) as reply:
        return json.loads(reply.read(4 * 1024 * 1024))


def verdict_of(report, threshold):
    """malicious or clean from a CAPE report: its malscore against the threshold of the operator."""
    score = (report.get('malscore') if isinstance(report, dict) else None)
    if score is None and isinstance(report, dict):
        score = (report.get('info') or {}).get('score')
    try:
        score = float(score)
    except (TypeError, ValueError):
        return 'error', None
    return ('malicious' if score >= threshold else 'clean'), score


def ask(request, conf, verdicts, now=None, call=cape):
    """The answer for one file; submits it when it is new."""
    now = time.time() if now is None else now
    sha = str(request.get('sha256', '')).lower()
    if not re.fullmatch(r'[0-9a-f]{64}', sha):
        return {'state': 'error', 'score': None}
    item = verdicts.get(sha)
    if item:
        if item['state'] == 'pending' and now - item['since'] > WAIT:
            item.update(state='timeout', at=now)
        return {'state': item['state'], 'score': item.get('score')}
    data = base64.b64decode(request.get('file', '') or '')
    if not data or len(data) > MAX_FILE:
        return {'state': 'error', 'score': None}
    body, kind = multipart(str(request.get('name', 'file')), data)
    try:
        answer = call(conf, '/apiv2/tasks/create/file/', body, kind)
        task = (answer.get('data') or {}).get('task_ids', [None])[0]
    except (OSError, ValueError, AttributeError, IndexError):
        return {'state': 'error', 'score': None}
    if task is None:
        return {'state': 'error', 'score': None}
    verdicts[sha] = {'state': 'pending', 'task': task, 'since': now, 'at': now}
    return {'state': 'pending', 'score': None}


def poll(conf, verdicts, now=None, call=cape):
    """The pending tasks: the verdict of each one CAPE has reported."""
    now = time.time() if now is None else now
    for item in verdicts.values():
        if item['state'] != 'pending':
            continue
        if now - item['since'] > WAIT:
            item.update(state='timeout', at=now)
            continue
        try:
            status = (call(conf, f"/apiv2/tasks/status/{int(item['task'])}/").get('data') or '')
            if status != 'reported':
                continue
            report = call(conf, f"/apiv2/tasks/get/report/{int(item['task'])}/")
        except (OSError, ValueError, AttributeError, TypeError):
            continue
        state, score = verdict_of(report, conf.get('threshold', 5.0))
        item.update(state=state, score=score, at=now)


def settings():
    try:
        with open(CONF) as f:
            conf = json.load(f)
    except (OSError, ValueError):
        return None
    return conf if str(conf.get('url', '')).startswith('https://') and conf.get('token') else None


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        if not 0 < length <= MAX_FILE * 2:
            self.send_error(413)
            return
        conf = settings()
        try:
            request = json.loads(self.rfile.read(length))
            with lock:
                verdicts = load()
                result = ask(request, conf, verdicts) if conf else {'state': 'error', 'score': None}
                save(verdicts)
        except (ValueError, TypeError, AttributeError, OSError):
            result = {'state': 'error', 'score': None}
        body = json.dumps(result).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def poller():
    while True:
        time.sleep(POLL)
        conf = settings()
        if conf:
            with lock:
                verdicts = load()
                poll(conf, verdicts)
                save(verdicts)


def self_test():
    import tempfile
    calls = []

    def call(conf, path, body=None, kind=None):
        calls.append(path)
        if path.startswith('/apiv2/tasks/create/'):
            assert b'filename="invoice.docm"' in body and kind.startswith('multipart/form-data; boundary=')
            return {'data': {'task_ids': [42]}}
        if path.startswith('/apiv2/tasks/status/'):
            return {'data': 'reported'}
        return {'malscore': 7.5}
    conf, verdicts, sha = {'url': 'https://cape.example', 'token': 't', 'threshold': 5.0}, {}, 'a' * 64
    request = {'sha256': sha, 'name': 'invoice.docm', 'file': base64.b64encode(b'PK...').decode()}
    assert ask(request, conf, verdicts, 1000, call) == {'state': 'pending', 'score': None} and verdicts[sha]['task'] == 42
    assert ask(request, conf, verdicts, 1001, call)['state'] == 'pending' and len(calls) == 1, 'known: not sent again'
    poll(conf, verdicts, 1100, call)
    assert ask(request, conf, verdicts, 1101, call) == {'state': 'malicious', 'score': 7.5}
    assert verdict_of({'info': {'score': 1}}, 5.0) == ('clean', 1.0) and verdict_of({}, 5.0) == ('error', None)
    verdicts = {}
    ask({**request, 'sha256': 'b' * 64}, conf, verdicts, 0, call)
    poll(conf, verdicts, WAIT + 1, lambda *args: {'data': 'running'})
    assert verdicts['b' * 64]['state'] == 'timeout'
    assert ask({'sha256': 'nothex'}, conf, {}, 0, call)['state'] == 'error'
    folder = tempfile.mkdtemp()
    save({'x': {'state': 'clean', 'at': 0}, 'y': {'state': 'clean', 'at': time.time()}}, folder + '/v.json')
    assert list(load(folder + '/v.json')) == ['y'], 'older than 7 days goes'
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
    else:
        threading.Thread(target=poller, daemon=True).start()
        ThreadingHTTPServer(('127.0.0.1', PORT), Handler).serve_forever()
