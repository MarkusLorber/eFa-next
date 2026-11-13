#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""SEC-STD on the installed host (ci.sh --install): the preview changes nothing; applying Mozilla modern makes the web
interface TLS 1.3 only while port 587 keeps TLS 1.2 (checked with openssl s_client); the check reads the settings in effect
(sshd -T); the rollback brings TLS 1.2 on the web back. Whatever happens, the rollback point is used at the end."""
import json
import os
import subprocess
import sys
import time

ROLLBACK = '/var/lib/eFa/standards-rollback.json'


def run(*cmd, check=True):
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if check and done.returncode != 0:
        raise SystemExit(f'{" ".join(cmd)}: {(done.stdout + done.stderr)[-400:]}')
    return done.stdout.strip()


def efactl(*args):
    return json.loads(run('/usr/sbin/efactl', *args))


def handshake(port, version, starttls=False):
    """True when a TLS handshake with exactly this version works."""
    cmd = ['openssl', 's_client', '-connect', f'127.0.0.1:{port}', f'-{version}', '-brief']
    if starttls:
        cmd += ['-starttls', 'smtp']
    done = subprocess.run(cmd, input='', capture_output=True, text=True, timeout=30)
    return done.returncode == 0 and 'Protocol version' in done.stderr + done.stdout


def settles(check, seconds=20):
    """True once check() holds: nginx takes a reload a moment after the command returns."""
    for _ in range(seconds):
        if check():
            return True
        time.sleep(1)
    return check()


def main():
    if os.path.exists(ROLLBACK):
        print('standards-live: skipped, a rollback point of the admin is there and stays')
        return 0
    web12_before = handshake(443, 'tls1_2')
    preview = efactl('standards-set', '--select=moz-modern')
    assert not preview.get('applied') and not os.path.exists(ROLLBACK), ('a preview changes nothing', preview)
    try:
        applied = efactl('standards-set', '--select=moz-modern', '--apply=yes', '--confirm=yes')
        print('applied:', applied['changes'])
        assert applied.get('applied') and os.path.exists(ROLLBACK), applied
        assert settles(lambda: not handshake(443, 'tls1_2')), 'web: TLS 1.2 refused after Mozilla modern'
        assert handshake(443, 'tls1_3'), 'web: TLS 1.3 works'
        assert handshake(587, 'tls1_2', starttls=True), '587 keeps TLS 1.2 (intermediate)'
        found = efactl('standards-check')['standards']
        assert {'bsi-02102-2', 'rfc9325', 'moz-modern', 'cis-el'} <= set(found), found.keys()
        assert all(row['status'] in ('fulfilled', 'over', 'alternative', 'not', 'needs') for item in found.values() for row in item['rows'])
        kex = next((line.split(None, 1)[1] for line in run('sshd', '-T').splitlines() if line.startswith('kexalgorithms ')), '')
        rows = {row['setting']: row for row in found['bsi-02102-4']['rows']}
        assert kex and kex.split(',')[0] in str(rows['sshd kexalgorithms']['now']), ('the check reads sshd -T', kex, rows['sshd kexalgorithms'])
        efactl('standards-rollback', '--confirm=yes')
        assert not os.path.exists(ROLLBACK)
        assert settles(lambda: handshake(443, 'tls1_2') == web12_before), 'the rollback brings the web TLS versions back'
        print('standards-live: ok')
        return 0
    finally:
        if os.path.exists(ROLLBACK):
            run('/usr/sbin/efactl', 'standards-rollback', '--confirm=yes', check=False)


if __name__ == '__main__':
    sys.exit(main())
