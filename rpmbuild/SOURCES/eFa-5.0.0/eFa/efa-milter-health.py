#!/usr/bin/python3
# eFa milter health service: probes the milters in smtpd_milters and key services,
# logs state changes to mail.log, serves GET /health on 127.0.0.1:8905 (200 ok, 503 down)
# and, as a milter on 127.0.0.1:8999, adds X-Milter-Failed to mail while something is down.
# Needed because milter_default_action = accept lets mail pass silently when a milter fails.
import json
import re
import socket
import struct
import subprocess
import sys
import syslog
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MILTER_PORT = 8999
HTTP_PORT = 8905
INTERVAL = 10
HEADER = 'X-Milter-Failed'
SERVICES = ('postfix', 'rspamd', 'redis', 'clamd@scan')
# MSMilter refuses connections after a probe session and reloads its lists on each one, so never connect to it.
LISTEN_ONLY = (33333,)
# Optional site-specific systemd units, one per line. Logged and shown in /health, but not marked in mail.
EXTRA_FILE = '/etc/sysconfig/efa-milter-health'

state = {}
checked_at = 0


def probe(port):
    """True if a milter answers option negotiation, so a hung daemon with an open port counts as down."""
    if port in LISTEN_ONLY:
        out = subprocess.run(['ss', '-ltnH', f'sport = :{port}'], capture_output=True, text=True).stdout
        return bool(out.strip())
    try:
        with socket.create_connection(('127.0.0.1', port), 3) as s:
            s.settimeout(3)
            s.sendall(struct.pack('!IcIII', 13, b'O', 6, 0x1ff, 0x1fffff))
            ok = s.recv(5)[4:5] == b'O'
            s.sendall(struct.pack('!Ic', 1, b'Q'))
            return ok
    except OSError:
        return False


def milter_ports():
    out = subprocess.run(['postconf', '-h', 'smtpd_milters'], capture_output=True, text=True).stdout
    return [int(p) for p in re.findall(r'inet:127\.0\.0\.1:(\d+)', out) if int(p) != MILTER_PORT]


def service_active(name):
    return subprocess.run(['systemctl', 'is-active', '--quiet', '--', name]).returncode == 0


def extra_services():
    try:
        with open(EXTRA_FILE) as f:
            lines = [line.split('#')[0].strip() for line in f]
    except FileNotFoundError:
        return []
    return [line for line in lines if line]


def check_once():
    global state, checked_at
    new = {f'milter:{p}': probe(p) for p in milter_ports()}
    new.update({f'service:{s}': service_active(s) for s in SERVICES})
    new.update({f'extra:{s}': service_active(s) for s in extra_services()})
    for name, ok in new.items():
        if state.get(name, True) != ok:
            syslog.syslog(syslog.LOG_INFO if ok else syslog.LOG_CRIT, f'{name} {"recovered" if ok else "DOWN"}')
    state, checked_at = new, time.time()


def monitor():
    while True:
        try:
            check_once()
        except Exception as e:
            syslog.syslog(syslog.LOG_ERR, f'check failed: {e}')
        time.sleep(INTERVAL)


def down():
    return sorted(name for name, ok in state.items() if not ok)


class Health(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/health':
            self.send_error(404)
            return
        failed = down()
        body = json.dumps({'status': 'down' if failed else 'ok', 'down': failed,
                           'checks': state, 'checked_at': int(checked_at)}).encode()
        self.send_response(503 if failed else 200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def run_milter():
    import Milter

    class Marker(Milter.Base):
        def __init__(self):
            self.forged = 0

        def envfrom(self, *args):
            self.forged = 0
            return Milter.CONTINUE

        def header(self, name, value):
            if name.lower() == HEADER.lower():
                self.forged += 1
            return Milter.CONTINUE

        def eom(self):
            # A sender must not be able to fake or hide the marker.
            for i in range(self.forged, 0, -1):
                self.chgheader(HEADER, i, '')
            # shortcut: state is up to INTERVAL seconds old, per-mail probing would slow every message.
            failed = [name for name in down() if not name.startswith('extra:')]
            if failed:
                self.addheader(HEADER, ', '.join(failed))
            return Milter.ACCEPT

    Milter.factory = Marker
    Milter.set_flags(Milter.ADDHDRS | Milter.CHGHDRS)
    Milter.runmilter('efa-milter-health', f'inet:{MILTER_PORT}@127.0.0.1', timeout=60)


def self_test():
    srv = socket.create_server(('127.0.0.1', 0))
    port = srv.getsockname()[1]

    def fake_milter():
        conn, _ = srv.accept()
        with conn:
            assert conn.recv(17)[4:5] == b'O'
            conn.sendall(struct.pack('!IcIII', 13, b'O', 6, 0, 0))

    threading.Thread(target=fake_milter, daemon=True).start()
    assert probe(port) is True
    srv.close()
    assert probe(port) is False
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
        sys.exit(0)
    syslog.openlog('efa-milter-health', syslog.LOG_PID, syslog.LOG_MAIL)
    threading.Thread(target=monitor, daemon=True).start()
    threading.Thread(target=ThreadingHTTPServer(('127.0.0.1', HTTP_PORT), Health).serve_forever, daemon=True).start()
    run_milter()
