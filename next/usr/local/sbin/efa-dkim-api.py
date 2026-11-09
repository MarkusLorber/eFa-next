#!/usr/bin/python3 -I
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Provisioning API on port 8463: DKIM keys (5o, docs/api-dkim-provisioning.md) and disclaimers as ZIP (8k,
docs/api-disclaimer.md). Runs as efa-dkim-api: TLS 1.2+, the client certificate of a registered source, its token, its right
for the kind of call, its addresses and its calls per minute. Each call goes to the fixed command of its kind in efactl, which
checks the content and stores it."""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import syslog
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ETC = os.environ.get('EFA_ETC', '/etc')
STATE = ETC + '/eFa/dkim-provision.json'
FOLDER = ETC + '/eFa/dkim-api'
PORT = 8463
PATH = re.compile(r'^/api/v1/dkim/provision/?([A-Za-z0-9.-]{0,253})$')
DISCLAIMER_PATH = re.compile(r'^/api/v1/disclaimer/?([a-z0-9][a-z0-9-]{0,39})?$')
MAX_PUT, MAX_POST = 1024 * 1024, 2 * 1024 * 1024
MAX_ZIP = 5 * 1024 * 1024
FAILED_PER_MINUTE = 30
# Handshake and request of one connection; a large body at a slow line still fits.
CONNECTION_SECONDS = 60
EFACTL = ['sudo', '-n', '/usr/sbin/efactl', '--client', 'dkim-api', 'dkim-provision-apply', '--source']
EFACTL_DISCLAIMER = ['sudo', '-n', '/usr/sbin/efactl', '--client', 'dkim-api', 'disclaimer-provision-apply', '--source']


class Window:
    """Calls per key in the last 60 seconds; wait() says how many seconds until the oldest one leaves."""

    def __init__(self):
        self.calls, self.lock = {}, threading.Lock()

    def take(self, key, limit, now=None):
        now = now or time.time()
        with self.lock:
            # Forget keys whose calls have all aged out, so a flood of changing IPs cannot grow the dict without bound.
            if len(self.calls) > 10000:
                self.calls = {k: times for k, times in self.calls.items() if times and times[-1] > now - 60}
            recent = [t for t in self.calls.get(key, []) if t > now - 60]
            if len(recent) >= limit:
                self.calls[key] = recent
                return max(1, int(recent[0] + 60 - now) + 1)
            recent.append(now)
            self.calls[key] = recent
            return 0


def load_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def fingerprint(der):
    digest = hashlib.sha256(der).hexdigest().upper()
    return ':'.join(digest[i:i + 2] for i in range(0, len(digest), 2))


def source_of(state, der):
    if not der:
        return None
    wanted = fingerprint(der)
    return next((name for name, item in state.get('sources', {}).items() if item.get('fingerprint', '').upper() == wanted), None)


def token_ok(source, header):
    if not header.startswith('Bearer '):
        return False
    return hmac.compare_digest(hashlib.sha256(header[7:].strip().encode()).hexdigest(), source.get('token_hash', ''))


def plain_ip(address):
    """IPv4 clients arrive as ::ffff:a.b.c.d on the IPv6 socket."""
    ip = ipaddress.ip_address(address.split('%', 1)[0])
    return getattr(ip, 'ipv4_mapped', None) or ip


def address_ok(source, address):
    allowed = source.get('addresses') or []
    if not allowed:
        return True
    ip = plain_ip(address)
    return any(ip in ipaddress.ip_network(item, strict=False) for item in allowed)


def body_length(headers):
    """The Content-Length of a request, None if it is no number of 0 or more: -1 would read to the end, past every limit."""
    value = (headers.get('Content-Length') or '0').strip()
    return int(value) if value.isascii() and value.isdigit() else None


class Handler(BaseHTTPRequestHandler):
    server_version = 'efa-dkim-api'
    sys_version = ''
    sources_window, failed_window = Window(), Window()

    def log_message(self, fmt, *args):
        syslog.syslog(syslog.LOG_INFO, 'efa-dkim-api ' + (fmt % args)[:300])

    def answer(self, code, data, retry=0):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        if retry:
            self.send_header('Retry-After', str(retry))
        self.end_headers()
        self.wfile.write(body)

    def failed(self, text):
        address = str(plain_ip(self.client_address[0]))
        # The line Fail2Ban reads; the 30 in a minute here hold until it bans.
        syslog.syslog(syslog.LOG_WARNING, f'efa-dkim-api login failed from {address}: {text}')
        wait = self.failed_window.take(address, FAILED_PER_MINUTE)
        return self.answer(429, {'error': 'too many failed logins'}, wait) if wait else self.answer(401, {'error': text})

    def handle_call(self, method):
        path = self.path.split('?', 1)[0]
        match, kind = PATH.match(path), 'dkim'
        if not match:
            match, kind = DISCLAIMER_PATH.match(path), 'disclaimer'
        if not match:
            return self.answer(404, {'error': 'unknown address'})
        state = load_state()
        name = source_of(state, self.connection.getpeercert(binary_form=True))
        if name is None:
            return self.failed('no or unknown client certificate')
        source = state['sources'][name]
        if not token_ok(source, self.headers.get('Authorization', '')):
            return self.failed('no or wrong token')
        if not address_ok(source, self.client_address[0]):
            return self.answer(403, {'error': 'this address is not allowed for this source'})
        if kind not in (source.get('rights') or ['dkim']):
            return self.answer(403, {'error': f'this source has no right for {kind}'})
        wait = self.sources_window.take(name, int(source.get('rate') or 600))
        if wait:
            return self.answer(429, {'error': 'too many calls'}, wait)
        if kind == 'disclaimer':
            return self.disclaimer_call(method, name, match.group(1) or '')
        domain = match.group(1).lower()
        body = None
        if method in ('PUT', 'POST'):
            if (method == 'PUT') != bool(domain):
                return self.answer(404, {'error': 'PUT to /<domain>, POST to /'})
            length = body_length(self.headers)
            if length is None:
                return self.answer(400, {'error': 'bad Content-Length'})
            if length > (MAX_PUT if method == 'PUT' else MAX_POST):
                return self.answer(413, {'error': 'body too large'})
            try:
                body = json.loads(self.rfile.read(length) or b'null')
            except ValueError:
                return self.answer(400, {'error': 'no valid JSON'})
        elif method == 'DELETE' and not domain:
            return self.answer(404, {'error': 'DELETE /<domain>'})
        done = subprocess.run(EFACTL + [name], input=json.dumps({'method': method, 'domain': domain, 'body': body}),
                              capture_output=True, text=True, timeout=120)
        try:
            result = json.loads(done.stdout)
            return self.answer(int(result['code']), result['body'])
        except (ValueError, KeyError, TypeError):
            syslog.syslog(syslog.LOG_ERR, f'efa-dkim-api: efactl failed: {(done.stderr or done.stdout)[-300:]}')
            return self.answer(500, {'error': 'internal error, see the log of eFa-next'})

    def disclaimer_call(self, method, name, template_id):
        body = ''
        if method in ('PUT', 'DELETE') and not template_id:
            return self.answer(404, {'error': f'{method} /api/v1/disclaimer/<id>'})
        if method == 'POST':
            return self.answer(405, {'error': 'PUT a ZIP to /api/v1/disclaimer/<id>'})
        if method == 'PUT':
            length = body_length(self.headers)
            if length is None:
                return self.answer(400, {'error': 'bad Content-Length'})
            if length > MAX_ZIP:
                return self.answer(413, {'error': 'ZIP too large'})
            body = base64.b64encode(self.rfile.read(length)).decode()
        done = subprocess.run(EFACTL_DISCLAIMER + [name], input=json.dumps({'method': method, 'id': template_id, 'zip': body}),
                              capture_output=True, text=True, timeout=120)
        try:
            result = json.loads(done.stdout)
            return self.answer(int(result['code']), result['body'])
        except (ValueError, KeyError, TypeError):
            syslog.syslog(syslog.LOG_ERR, f'efa-dkim-api: efactl failed: {(done.stderr or done.stdout)[-300:]}')
            return self.answer(500, {'error': 'internal error, see the log of eFa-next'})

    def do_GET(self):
        self.handle_call('GET')

    def do_PUT(self):
        self.handle_call('PUT')

    def do_POST(self):
        self.handle_call('POST')

    def do_DELETE(self):
        self.handle_call('DELETE')


def context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20')
    ctx.load_cert_chain(FOLDER + '/server.crt', FOLDER + '/server.key')
    # Only the certificates of the sources: a self-signed one is its own trust anchor. No certificate: answered with 401.
    ctx.verify_mode = ssl.CERT_OPTIONAL
    if os.path.getsize(FOLDER + '/clients.pem') > 10:
        ctx.load_verify_locations(FOLDER + '/clients.pem')
    return ctx


class TLSServer(ThreadingHTTPServer):
    """The TLS handshake of each connection in its own thread and with a time limit, which stays for the request: a client
    that connects and says nothing cannot stop the accept loop, nor keep a thread."""
    ssl_context = None

    def finish_request(self, request, client_address):
        request.settimeout(CONNECTION_SECONDS)
        try:
            connection = self.ssl_context.wrap_socket(request, server_side=True)
        except OSError:  # no TLS, a failed handshake or the time limit
            return
        try:
            self.RequestHandlerClass(connection, client_address, self)
        finally:
            connection.close()


class Server(TLSServer):
    """IPv6 and IPv4 on one socket."""
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


def main():
    syslog.openlog('efa-dkim-api')
    try:
        server = Server(('::', PORT), Handler)
    except OSError:  # a host with IPv6 switched off
        server = TLSServer(('0.0.0.0', PORT), Handler)
    server.ssl_context = context()
    server.serve_forever()


def self_test():
    window = Window()
    assert [window.take('a', 2, 100), window.take('a', 2, 101), window.take('a', 2, 102) > 0] == [0, 0, True]
    assert window.take('a', 2, 161) == 0, 'after a minute it is free again'
    # Old keys are forgotten, so a flood of changing addresses does not grow the dict without bound.
    for i in range(10100):
        window.take(f'ip{i}', 600, now=200 + i)
    assert len(window.calls) <= 10001, len(window.calls)
    der = b'certificate'
    state = {'sources': {'s1': {'fingerprint': fingerprint(der), 'token_hash': hashlib.sha256(b'tok').hexdigest(), 'addresses': ['192.0.2.0/24']}}}
    assert source_of(state, der) == 's1' and source_of(state, b'other') is None and source_of(state, None) is None
    assert token_ok(state['sources']['s1'], 'Bearer tok') and not token_ok(state['sources']['s1'], 'Bearer nope') and not token_ok(state['sources']['s1'], 'tok')
    assert address_ok(state['sources']['s1'], '::ffff:192.0.2.9') and str(plain_ip('::ffff:192.0.2.9')) == '192.0.2.9'
    assert address_ok(state['sources']['s1'], '192.0.2.9') and not address_ok(state['sources']['s1'], '198.51.100.1') and address_ok({}, '198.51.100.1')
    assert PATH.match('/api/v1/dkim/provision/example.org').group(1) == 'example.org' and PATH.match('/api/v1/dkim/provision/').group(1) == ''
    assert not PATH.match('/api/v1/dkim/provision/../x') and not PATH.match('/other')
    assert DISCLAIMER_PATH.match('/api/v1/disclaimer/sales-de').group(1) == 'sales-de' and DISCLAIMER_PATH.match('/api/v1/disclaimer').group(1) is None
    assert not DISCLAIMER_PATH.match('/api/v1/disclaimer/../x') and not DISCLAIMER_PATH.match('/api/v1/disclaimer/A')
    assert [body_length({'Content-Length': value}) for value in ('12', None, '-1', 'x', '²', ' 3 ')] == [12, 0, None, None, None, 3]
    tls_self_test(TLSServer)
    print('self-test ok')


def tls_self_test(server_class):
    """A client that connects and says nothing must not stop the next one: each handshake has its own thread and time limit."""
    global CONNECTION_SECONDS
    saved, CONNECTION_SECONDS = CONNECTION_SECONDS, 1
    server = server_class(('127.0.0.1', 0), BaseHTTPRequestHandler)
    server.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    silent = socket.create_connection(server.server_address, timeout=5)
    try:
        started = time.time()
        with socket.create_connection(server.server_address, timeout=5) as other:
            other.sendall(b'no TLS\r\n\r\n')
            try:
                other.recv(100)  # closed after the failed handshake, with or without an alert
            except OSError:
                pass
        assert time.time() - started < 4, 'the second client waited for the silent one'
    finally:
        silent.close()
        server.shutdown()
        server.server_close()
        CONNECTION_SECONDS = saved


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
    else:
        main()
