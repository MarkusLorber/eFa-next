#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
# eFa-next milter health service: probes the milters in smtpd_milters and key services,
# logs state changes to mail.log, serves GET /health on 127.0.0.1:8905 (200 ok, 503 down)
# and, as a milter on 127.0.0.1:8999, adds X-Milter-Failed to mail while something is down.
# Needed because milter_default_action = accept lets mail pass silently when a milter fails.
import json
import os
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
# Redis on EL9, Valkey on EL10 (same port, same data). Also the services a mail filter needs besides the scanners (PKG-3).
REDIS_UNIT = 'valkey' if os.path.exists('/usr/lib/systemd/system/valkey.service') else 'redis'
SERVICES = ('postfix', 'rspamd', REDIS_UNIT, 'clamd@scan', 'nginx', 'mariadb', 'unbound', 'fail2ban', 'firewalld')
# MSMilter refuses connections after a probe session and reloads its lists on each one, so never connect to it.
LISTEN_ONLY = (33333,)
# Optional site-specific systemd units, one per line. Logged and shown in /health, but not marked in mail.
EXTRA_FILE = '/etc/sysconfig/efa-milter-health'

MAIN_CF = '/etc/postfix/main.cf'
# A5: which milters, when down, make this service tempfail the mail instead of letting it pass. Written by efactl
# milter-health-set (root:efa-mail 0640). Empty or absent = accept, the behaviour milter_default_action=accept gives.
TEMPFAIL_FILE = os.environ.get('EFA_MILTER_TEMPFAIL', '/etc/eFa/milter-health.json')
state = {}
checked_at = 0
ports_cache = (None, [])
tempfail_cache = {'mtime': None, 'ports': frozenset()}


def tempfail_ports():
    """The milter ports the admin set to tempfail on, read again only when the file changed."""
    try:
        mtime = os.stat(TEMPFAIL_FILE).st_mtime_ns
    except OSError:
        tempfail_cache.update(mtime=None, ports=frozenset())
        return tempfail_cache['ports']
    if mtime != tempfail_cache['mtime']:
        try:
            with open(TEMPFAIL_FILE) as f:
                ports = frozenset(str(p) for p in json.load(f).get('tempfail', []))
        except (OSError, ValueError, AttributeError, TypeError):
            ports = frozenset()  # a broken file never turns mail away
        tempfail_cache.update(mtime=mtime, ports=ports)
    return tempfail_cache['ports']


def tempfail_due(failed, tempfail):
    """The down milters that the admin chose to tempfail on. failed: the names from down(); tempfail: the chosen ports."""
    return [name for name in failed if name.startswith('milter:') and name.split(':', 1)[1] in tempfail]


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
    # This runs every 10 seconds: ask postconf only after main.cf changed.
    global ports_cache
    try:
        stamp = os.stat(MAIN_CF).st_mtime_ns
    except OSError:
        stamp = None
    if stamp is None or ports_cache[0] != stamp:
        out = subprocess.run(['postconf', '-h', 'smtpd_milters'], capture_output=True, text=True).stdout
        ports_cache = (stamp, [int(p) for p in re.findall(r'inet:127\.0\.0\.1:(\d+)', out) if int(p) != MILTER_PORT])
    return ports_cache[1]


def services_active(names):
    """One systemctl call for all units, it prints one line per unit in the given order."""
    if not names:
        return {}
    out = subprocess.run(['systemctl', 'is-active', '--', *names], capture_output=True, text=True).stdout.split()
    return {name: index < len(out) and out[index] == 'active' for index, name in enumerate(names)}


def extra_services():
    try:
        with open(EXTRA_FILE) as f:
            lines = [line.split('#')[0].strip() for line in f]
    except FileNotFoundError:
        return []
    return [line for line in lines if line]


WIZARD_RUN_DIR = '/run/efa-init'


def broken_units(listing=None, wizard_dir=None):
    """eFa-next services that failed or start again and again (a missing credential file, a crash at the start): the
    dashboard names them instead of a quiet restart loop. Also efa-web skipped by its condition (the folder of the wizard)
    while no wizard runs: it would stay off until a reboot."""
    if listing is None:
        listing = subprocess.run(['systemctl', 'list-units', '--all', '--no-legend', '--plain', 'efa-*.service'],
                                 capture_output=True, text=True, timeout=10).stdout
    if wizard_dir is None:
        wizard_dir = os.path.isdir(WIZARD_RUN_DIR)
    fields = [line.split() for line in listing.splitlines()]
    found = sorted(f[0] for f in fields if len(f) >= 4 and (f[2] == 'failed' or f[3] == 'auto-restart'))
    states = {f[0]: f[2] for f in fields if len(f) >= 3}
    if wizard_dir and states.get('efa-init.service') not in ('active', 'activating', 'reloading') and \
            states.get('efa-web.service', 'inactive') != 'active':
        found.append(f'efa-web.service (skipped: {WIZARD_RUN_DIR} left without the wizard)')
    return found


def check_once():
    global state, checked_at
    new = {f'milter:{p}': probe(p) for p in milter_ports()}
    extras = extra_services()
    active = services_active(list(SERVICES) + extras)
    new.update({f'service:{s}': active[s] for s in SERVICES})
    new.update({f'extra:{s}': active[s] for s in extras})
    new.update({f'unit:{u}': False for u in broken_units()})
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
            # A5: milter_default_action stays accept; only the milters the admin marked turn a mail away, with a retryable 4xx.
            due = tempfail_due(failed, tempfail_ports())
            if due:
                self.setreply('451', '4.7.1', 'A mail filter is temporarily unavailable, please try again later.')
                syslog.syslog(syslog.LOG_WARNING, f'tempfail: {", ".join(due)} down')
                return Milter.TEMPFAIL
            return Milter.ACCEPT

    Milter.factory = Marker
    Milter.set_flags(Milter.ADDHDRS | Milter.CHGHDRS)
    Milter.runmilter('efa-milter-health', f'inet:{MILTER_PORT}@127.0.0.1', timeout=60)
    # A connection that comes in while Python shuts down crashes pymilter: end without the shutdown.
    os._exit(0)


def self_test():
    listing = ('efa-web.service loaded active running eFa-next web interface\n'
               'efa-outbound.service loaded activating auto-restart eFa-next outbound milter\n'
               'efa-cdr.service loaded failed failed eFa-next content milter\n'
               'efa-firstboot.service loaded inactive dead eFa-next first boot\n')
    assert broken_units(listing, False) == ['efa-cdr.service', 'efa-outbound.service'], 'a restart loop and a failed unit, not a oneshot'
    # WEB-RESTART: efa-web skipped while the folder of the wizard is left without the wizard: named; with the wizard: not.
    skipped = 'efa-web.service loaded inactive dead eFa-next web interface\nefa-init.service loaded failed failed eFa-next first-run wizard\n'
    assert broken_units(skipped, True)[-1].startswith('efa-web.service (skipped') and 'efa-web.service (skipped' not in ' '.join(broken_units(skipped, False))
    with_wizard = 'efa-web.service loaded inactive dead eFa-next web interface\nefa-init.service loaded active running eFa-next first-run wizard\n'
    assert not [item for item in broken_units(with_wizard, True) if 'skipped' in item], 'the wizard runs: efa-web waits for it on purpose'
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
    # A5: only a down milter the admin chose turns mail away; services and unchosen milters still pass (accept).
    failed = ['milter:11332', 'milter:8907', 'service:rspamd']
    assert tempfail_due(failed, frozenset({'11332'})) == ['milter:11332']
    assert tempfail_due(failed, frozenset()) == [] and tempfail_due(failed, frozenset({'25'})) == []
    assert tempfail_due(['service:clamd@scan'], frozenset({'clamd@scan'})) == [], 'only milters tempfail, not services'
    import tempfile
    with tempfile.TemporaryDirectory() as folder:
        global TEMPFAIL_FILE
        TEMPFAIL_FILE = os.path.join(folder, 'milter-health.json')
        assert tempfail_ports() == frozenset(), 'no file means accept'
        with open(TEMPFAIL_FILE, 'w') as f:
            f.write('{"tempfail": [11332, "8907"]}')
        assert tempfail_ports() == frozenset({'11332', '8907'})
        with open(TEMPFAIL_FILE, 'w') as f:
            f.write('broken')
        tempfail_cache['mtime'] = None
        assert tempfail_ports() == frozenset(), 'a broken file never turns mail away'
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
        sys.exit(0)
    syslog.openlog('efa-milter-health', syslog.LOG_PID, syslog.LOG_MAIL)
    threading.Thread(target=monitor, daemon=True).start()
    threading.Thread(target=ThreadingHTTPServer(('127.0.0.1', HTTP_PORT), Health).serve_forever, daemon=True).start()
    run_milter()
